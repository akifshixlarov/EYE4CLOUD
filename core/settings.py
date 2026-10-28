"""
core/settings.py

Settings saved from the dashboard: the scan schedule and Telegram notifications.

They live in results/settings.json (git-ignored, chmod 600) because the
background scheduler must read them even when no browser session is open.
Local (non-public) mode only - nothing here is used with PUBLIC_MODE=true.
"""

import json
import os
import threading

from core.history import RESULTS_DIR

SETTINGS_FILE = RESULTS_DIR / "settings.json"

DEFAULTS = {
    "schedule": {
        "enabled": False,
        "mode": "daily",          # "daily" (at a fixed UTC time) or "interval" (every N hours)
        "time": "09:00",          # HH:MM, UTC
        "interval_hours": 24,
        "subscription_ids": [],   # empty -> AZURE_SUBSCRIPTION_ID(S) from .env
        "next_run": None,         # ISO timestamp, UTC
        "last_run": None,
        "last_status": None,
    },
    "telegram": {
        "enabled": False,
        "bot_token": "",
        "chat_id": "",
    },
}

# The scheduler thread and the UI both write - one writer at a time
_LOCK = threading.Lock()


def load_settings() -> dict:
    """Returns the saved settings merged over DEFAULTS (a missing/broken file means defaults)."""
    saved = {}
    if SETTINGS_FILE.exists():
        try:
            saved = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            saved = {}
    return {section: {**values, **saved.get(section, {})} for section, values in DEFAULTS.items()}


def update_settings(section: str, **values) -> dict:
    """Merges `values` into one section and saves atomically (the file holds the bot token)."""
    with _LOCK:
        settings = load_settings()
        settings[section].update(values)

        SETTINGS_FILE.parent.mkdir(exist_ok=True)
        tmp_file = SETTINGS_FILE.with_suffix(".tmp")
        tmp_file.write_text(json.dumps(settings, indent=2), encoding="utf-8")
        os.chmod(tmp_file, 0o600)
        os.replace(tmp_file, SETTINGS_FILE)
    return settings
