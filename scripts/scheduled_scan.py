"""
scripts/scheduled_scan.py

Headless (UI-less) scan - for Windows Task Scheduler, cron or GitHub Actions.
All the logic lives in core/scanner.py; this script only calls it,
writes the result to logs/scheduled_scan.log and prints a short summary.

Usage:
    python scripts/scheduled_scan.py

Exit code: 0 on a successful scan, 1 on error - so the scheduler/CI can
tell that the scan failed.
"""

import logging
import sys
from pathlib import Path

# When run directly as `python scripts/scheduled_scan.py`, the project root
# is not on sys.path - we add it so the `core` package can be found
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.scanner import run_scan  # noqa: E402
from core.scoring import calculate_scores  # noqa: E402

LOG_FILE = PROJECT_ROOT / "logs" / "scheduled_scan.log"


def _setup_logging() -> None:
    """Writes both to a file (for history) and to the screen (for the CI log)."""
    LOG_FILE.parent.mkdir(exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )

    # At INFO level the Azure SDK dumps every HTTP request/response in full -
    # that bloats the log file of scheduled scans, so we lower it to WARNING
    logging.getLogger("azure").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def main() -> int:
    _setup_logging()

    try:
        result = run_scan(trigger="Scheduled")
    except Exception:
        logging.exception("Scan failed")
        return 1

    scores = calculate_scores(result["findings"])
    severity = scores["findings_by_severity"]

    logging.info(
        "Scan completed: score=%s/100, findings=%s (High=%s, Medium=%s, Low=%s)",
        scores["overall"],
        result["total_findings"],
        severity["High"],
        severity["Medium"],
        severity["Low"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
