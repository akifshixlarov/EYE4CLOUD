"""
tests/test_automation.py

Scheduled scans and Telegram notifications:
1. next-run calculation for daily / interval schedules
2. the scheduler runs only when due, books the next slot, and records the status
3. Telegram is sent from dashboard settings and a failure never leaks the token
4. Telegram input validation
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests

import core.scheduler as scheduler
import core.settings as settings
from core.notifications import build_summary, notify_scan_complete
from core.security import validate_telegram_config

TOKEN = "123456789:" + "A" * 35
NOW = datetime(2026, 10, 28, 10, 0, tzinfo=timezone.utc)


@pytest.fixture
def tmp_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "SETTINGS_FILE", tmp_path / "settings.json")
    for var in ("TEAMS_WEBHOOK_URL", "SLACK_WEBHOOK_URL", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path


def test_compute_next_run():
    daily = {"mode": "daily", "time": "09:00", "interval_hours": 24}
    assert scheduler.compute_next_run(daily, NOW) == datetime(2026, 10, 29, 9, 0, tzinfo=timezone.utc)
    daily["time"] = "11:30"
    assert scheduler.compute_next_run(daily, NOW) == datetime(2026, 10, 28, 11, 30, tzinfo=timezone.utc)

    interval = {"mode": "interval", "time": "09:00", "interval_hours": 6}
    assert scheduler.compute_next_run(interval, NOW) == datetime(2026, 10, 28, 16, 0, tzinfo=timezone.utc)


def test_run_due_scan(tmp_settings):
    fake_scan = MagicMock(return_value={"total_findings": 4})
    settings.update_settings(
        "schedule", enabled=True, mode="interval", interval_hours=6,
        subscription_ids=["33333333-3333-3333-3333-333333333333"], next_run=NOW.isoformat(),
    )

    with patch.object(scheduler, "run_scan", fake_scan):
        # Not due yet
        assert scheduler.run_due_scan(datetime(2026, 10, 28, 9, 0, tzinfo=timezone.utc)) is False
        # Due
        assert scheduler.run_due_scan(NOW) is True
        # Next slot already booked - no second run
        assert scheduler.run_due_scan(NOW) is False

    fake_scan.assert_called_once()
    assert fake_scan.call_args.kwargs["credentials"] == {"subscription_ids": ["33333333-3333-3333-3333-333333333333"]}
    assert fake_scan.call_args.kwargs["trigger"] == "Scheduled"

    saved = settings.load_settings()["schedule"]
    assert saved["next_run"] == "2026-10-28T16:00:00+00:00"
    assert saved["last_status"] == "OK - 4 findings"

    # A failing scan is recorded, not raised
    settings.update_settings("schedule", next_run=NOW.isoformat())
    with patch.object(scheduler, "run_scan", side_effect=EnvironmentError("no creds")):
        assert scheduler.run_due_scan(NOW) is True
    assert settings.load_settings()["schedule"]["last_status"] == "Failed: OSError"


def test_disabled_schedule_never_runs(tmp_settings):
    settings.update_settings("schedule", enabled=False, next_run=NOW.isoformat())
    with patch.object(scheduler, "run_scan") as fake_scan:
        assert scheduler.run_due_scan(NOW) is False
    fake_scan.assert_not_called()


def test_telegram_notification_from_settings(tmp_settings, caplog):
    result = {"findings": [], "total_findings": 0, "subscription_ids": ["sub-1"]}
    summary = build_summary(result, previous=None, trigger="Scheduled")

    # Not configured -> nothing sent
    with patch("core.notifications.requests.post") as post:
        assert notify_scan_complete(summary) is False
    post.assert_not_called()

    settings.update_settings("telegram", enabled=True, bot_token=TOKEN, chat_id="42")
    with patch("core.notifications.requests.post") as post:
        assert notify_scan_complete(summary) is True
    url = post.call_args.args[0]
    body = post.call_args.kwargs["json"]
    assert url == f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    assert body["chat_id"] == "42"
    assert "Posture Score: 100/100" in body["text"] and "Trigger: Scheduled" in body["text"]

    # Network failure: swallowed, and the token never reaches the log
    error = requests.HTTPError(f"401 for url: https://api.telegram.org/bot{TOKEN}/sendMessage")
    with patch("core.notifications.requests.post", side_effect=error):
        assert notify_scan_complete(summary) is False
    assert TOKEN not in caplog.text


def test_settings_file_is_private(tmp_settings):
    settings.update_settings("telegram", bot_token=TOKEN)
    assert (settings.SETTINGS_FILE.stat().st_mode & 0o777) == 0o600


def test_validate_telegram_config():
    assert validate_telegram_config(TOKEN, "123456789") == (True, "")
    assert validate_telegram_config(TOKEN, "-1001234567890")[0] is True
    assert validate_telegram_config(TOKEN, "@my_channel")[0] is True
    assert validate_telegram_config("not-a-token", "42")[0] is False
    assert validate_telegram_config(TOKEN + "/../x", "42")[0] is False
    assert validate_telegram_config(TOKEN, "42; rm -rf")[0] is False


def test_scheduled_scans_show_in_local_history(tmp_path, monkeypatch):
    import json
    import ui.scanner_runner as sr

    monkeypatch.delenv("PUBLIC_MODE", raising=False)
    monkeypatch.setattr(sr, "RESULTS_DIR", tmp_path)
    (tmp_path / "scan_scheduled_2026-10-28_09-00-00.json").write_text(
        json.dumps({"scan_time": "2026-10-28T09:00:00+00:00", "findings": []})
    )
    session_scan = {"scan_time": "2026-10-28T10:00:00+00:00", "findings": []}

    names = [name for name, _ in sr.list_session_scans("abc", session_scans_store=[session_scan])]
    assert names == ["scan_scheduled_2026-10-28_09-00-00.json", "scan_1_2026-10-28 10:00"]

    # Public mode never reads shared files
    monkeypatch.setenv("PUBLIC_MODE", "true")
    assert len(sr.list_session_scans("abc", session_scans_store=[session_scan])) == 1
    assert sr.list_session_scans("abc", session_scans_store=[]) == []
