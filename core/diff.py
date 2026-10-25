"""
core/diff.py

results/ qovlugundaki son iki scan_*.json faylini goturub muqayise edir:
  - yeni yaranan tapintilar (previous-da yox, latest-de var)
  - hell olunan tapintilar (previous-da var, latest-de yox)
  - score deyisimi

Bu, ScoutSuite/Prowler kimi statik alətlərdə olmayan, layihenin ozune
mexsus hissesidir - tek defelik "snapshot" deyil, zaman icinde trend gosterir.
"""

from core.history import list_scan_files, load_scan as _load_scan
from core.scoring import calculate_scores


def _finding_key(finding: dict) -> tuple:
    """
    Iki fərqli scan-da eyni tapintini tanimaq ucun unikal acar.
    (category, resource, check) uckuluyu kifayetdir - eyni resursda eyni
    check her scan-da eyni acari verecek.
    """
    return (finding["category"], finding["resource"], finding["check"])


def compare_last_two_scans() -> dict | None:
    """
    Son iki skani muqayise edir. Eger 2-den az skan varsa None qaytarir -
    muqayise etmek ucun en azi 2 scan lazimdir.

    Qaytarilan format:
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

    previous = _load_scan(scan_files[-2])
    latest = _load_scan(scan_files[-1])

    previous_keys = {_finding_key(f): f for f in previous["findings"]}
    latest_keys = {_finding_key(f): f for f in latest["findings"]}

    new_findings = [
        f for key, f in latest_keys.items() if key not in previous_keys
    ]
    resolved_findings = [
        f for key, f in previous_keys.items() if key not in latest_keys
    ]

    previous_score = calculate_scores(previous["findings"])["overall"]
    latest_score = calculate_scores(latest["findings"])["overall"]

    return {
        "previous_time": previous["scan_time"],
        "latest_time": latest["scan_time"],
        "previous_score": previous_score,
        "latest_score": latest_score,
        "score_change": latest_score - previous_score,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
    }


def score_history() -> list[dict]:
    """
    Butun skanlar boyu score trendini qaytarir - Streamlit-de line chart
    ucun istifade olunur: [{"time": "...", "score": 62}, ...]
    """
    history = []
    for file_path in list_scan_files():
        scan = _load_scan(file_path)
        score = calculate_scores(scan["findings"])["overall"]
        history.append({"time": scan["scan_time"], "score": score})
    return history
