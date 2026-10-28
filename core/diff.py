"""
core/diff.py

Takes the last two scan_*.json files in the results/ folder and compares them:
  - new findings (absent in previous, present in latest)
  - resolved findings (present in previous, absent in latest)
  - score change

This is the part unique to this project, missing from static tools like
ScoutSuite/Prowler - not a one-off "snapshot", but a trend over time.
"""

from core.history import list_scan_files, load_scan as _load_scan
from core.scoring import calculate_scores


def _finding_key(finding: dict) -> tuple:
    """
    Unique key to recognise the same finding across two different scans.
    The (category, resource, check) triple is enough - the same check on the
    same resource yields the same key in every scan.
    """
    return (finding["category"], finding["resource"], finding["check"])


def compare_last_two_scans() -> dict | None:
    """
    Compares the last two scans. Returns None if there are fewer than 2 scans -
    at least 2 scans are needed for a comparison.

    Returned format:
    {
        "previous_time": "...",
        "latest_time": "...",
        "previous_score": 55,
        "latest_score": 70,
        "score_change": +15,
        "new_findings": [...],
        "resolved_findings": [...]
    }
    """
    scan_files = list_scan_files()
    if len(scan_files) < 2:
        return None

    return diff_scans(_load_scan(scan_files[-2]), _load_scan(scan_files[-1]))


def diff_scans(previous: dict, latest: dict) -> dict:
    """Compares two scan dicts (same format as compare_last_two_scans returns)."""
    previous_keys = {_finding_key(f): f for f in previous.get("findings", [])}
    latest_keys = {_finding_key(f): f for f in latest.get("findings", [])}

    new_findings = [
        f for key, f in latest_keys.items() if key not in previous_keys
    ]
    resolved_findings = [
        f for key, f in previous_keys.items() if key not in latest_keys
    ]

    previous_score = calculate_scores(previous.get("findings", []))["overall"]
    latest_score = calculate_scores(latest.get("findings", []))["overall"]

    return {
        "previous_time": previous.get("scan_time", ""),
        "latest_time": latest.get("scan_time", ""),
        "previous_score": previous_score,
        "latest_score": latest_score,
        "score_change": latest_score - previous_score,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
    }


def score_history() -> list[dict]:
    """
    Returns the score trend across all scans - used for the line chart
    in Streamlit: [{"time": "...", "score": 62}, ...]
    """
    history = []
    for file_path in list_scan_files():
        scan = _load_scan(file_path)
        score = calculate_scores(scan["findings"])["overall"]
        history.append({"time": scan["scan_time"], "score": score})
    return history
