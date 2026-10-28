"""
core/history.py

Manages scan history: the scan_*.json files in the results/ folder -
listing, loading one, deleting one, clearing all.

core/diff.py uses this module for analysis (comparison/trend) - this is
the only place that touches the file system directly.
"""

import json
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def list_scan_files() -> list[Path]:
    """Returns all scan files in the results/ folder in chronological order."""
    if not RESULTS_DIR.exists():
        return []
    return sorted(RESULTS_DIR.glob("scan_*.json"))


def load_scan(file_path: Path) -> dict:
    """Reads a scan_*.json file and returns it as a dict."""
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def delete_scan(file_path: Path) -> None:
    """Deletes a single scan file. Silently passes if the file no longer exists."""
    Path(file_path).unlink(missing_ok=True)


def clear_history() -> None:
    """Deletes all scan files in the results/ folder."""
    for file_path in list_scan_files():
        file_path.unlink()
