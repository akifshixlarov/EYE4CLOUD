"""
core/scheduler.py

Runs the scan schedule configured in the dashboard (local mode only).

One daemon thread per server process wakes every POLL_SECONDS; when the saved
next_run time has passed it runs core.scanner.run_scan with the SERVER
credentials (.env Service Principal or `az login`). Dashboard sign-ins are
session-only and are deliberately never kept for background use.
Results are saved as results/scan_scheduled_<timestamp>.json.
"""

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from core.scanner import run_scan
from core.security import GLOBAL_SCAN_SEMAPHORE, is_public_mode, redact
from core.settings import load_settings, update_settings

POLL_SECONDS = 30
SCHEDULED_SESSION_ID = "scheduled"


def compute_next_run(schedule: dict, now: datetime) -> datetime:
    """Next run strictly after `now` (UTC) for a "daily" or "interval" schedule."""
    if schedule["mode"] == "interval":
        return now + timedelta(hours=int(schedule["interval_hours"]))

    hour, minute = map(int, schedule["time"].split(":"))
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return candidate if candidate > now else candidate + timedelta(days=1)


def run_due_scan(now: datetime | None = None) -> bool:
    """Runs the scheduled scan if it is due. Returns True if a scan was attempted."""
    now = now or datetime.now(timezone.utc)
    schedule = load_settings()["schedule"]
    if not schedule["enabled"] or not schedule["next_run"]:
        return False
    if datetime.fromisoformat(schedule["next_run"]) > now:
        return False

    # Book the next slot first, so a failing scan is not retried every POLL_SECONDS
    update_settings("schedule", next_run=compute_next_run(schedule, now).isoformat())

    credentials = {"subscription_ids": schedule["subscription_ids"]} if schedule["subscription_ids"] else None
    with GLOBAL_SCAN_SEMAPHORE:
        try:
            result = run_scan(session_id=SCHEDULED_SESSION_ID, credentials=credentials, trigger="Scheduled")
            status = f"OK - {result['total_findings']} findings"
        except Exception as e:
            logging.error("Scheduled scan failed: %s", redact(str(e)))
            status = f"Failed: {type(e).__name__}"

    update_settings("schedule", last_run=now.isoformat(), last_status=status)
    return True


def _loop() -> None:
    while True:
        try:
            run_due_scan()
        except Exception as e:
            logging.error("Scheduler tick failed: %s", redact(str(e)))
        time.sleep(POLL_SECONDS)


def start_scheduler() -> threading.Thread | None:
    """Starts the background thread. Call once per process (app.py wraps it in st.cache_resource)."""
    if is_public_mode():
        return None
    thread = threading.Thread(target=_loop, name="eye4cloud-scheduler", daemon=True)
    thread.start()
    return thread
