"""
scripts/scheduled_scan.py

UI-siz (headless) skan - Windows Task Scheduler, cron ve ya GitHub Actions
ucun. Butun mentiq core/scanner.py-dadir; bu skript yalnizca onu cagirir,
neticeni logs/scheduled_scan.log-a yazir ve ekrana qisa xulase verir.

Istifade:
    python scripts/scheduled_scan.py

Exit kodu: ugurlu skanda 0, xetada 1 - beleliklə scheduler/CI skanin
ugursuz oldugunu goreri bilir.
"""

import logging
import sys
from pathlib import Path

# `python scripts/scheduled_scan.py` kimi birbasa cagirilanda layihe koku
# sys.path-da olmur - elave edirik ki, `core` paketi tapilsin
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.scanner import run_scan  # noqa: E402
from core.scoring import calculate_scores  # noqa: E402

LOG_FILE = PROJECT_ROOT / "logs" / "scheduled_scan.log"


def _setup_logging() -> None:
    """Hem fayla (tarixce ucun), hem ekrana (CI log-u ucun) yazir."""
    LOG_FILE.parent.mkdir(exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )

    # Azure SDK INFO seviyyesinde her HTTP sorgu/cavabini tam dump edir -
    # zamanlanmis skanda log faylini sisirdiyi ucun WARNING-e endiririk
    logging.getLogger("azure").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def main() -> int:
    _setup_logging()

    try:
        result = run_scan()
    except Exception:
        logging.exception("Skan ugursuz oldu")
        return 1

    scores = calculate_scores(result["findings"])
    severity = scores["findings_by_severity"]

    logging.info(
        "Skan tamamlandi: score=%s/100, tapinti=%s (High=%s, Medium=%s, Low=%s)",
        scores["overall"],
        result["total_findings"],
        severity["High"],
        severity["Medium"],
        severity["Low"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
