"""
ui/session_manager.py

Sessiya məlumatlarını, Demo rejimi və skan tarixçəsini koordinasiya edən köməkçi modul.
"""

from pathlib import Path
import streamlit as st

from core.diff import _finding_key
from core.scoring import calculate_scores
from core.history import load_scan
from ui.demo_data import get_demo_scans
from ui.scanner_runner import list_session_scans


def get_available_scans(
    session_id: str,
    is_demo: bool,
    session_scans_store: list[dict] | None = None,
) -> list[tuple[str, dict]]:
    """
    (ekran_adi, scan_dict) cütlərinin xronoloji siyahısını qaytarır.
    Demo rejimində saxta skanları, normal rejimdə isə sessiya yaddaşındakı skanları yükləyir.
    """
    if is_demo:
        demo_list = get_demo_scans()
        result = []
        for i, s in enumerate(demo_list, 1):
            time_short = s["scan_time"][:16].replace("T", " ")
            name = f"demo_scan_{i}_{time_short}"
            result.append((name, s))
        return result

    # Sessiyaya aid olan skanlar
    return list_session_scans(session_id, session_scans_store=session_scans_store)


def compute_scan_diff(scans: list[dict]) -> dict | None:
    """
    Siyahıdakı son iki skan arasında müqayisə aparır:
    - new_findings
    - resolved_findings
    - score_change
    """
    if len(scans) < 2:
        return None

    previous = scans[-2]
    latest = scans[-1]

    previous_keys = {_finding_key(f): f for f in previous.get("findings", [])}
    latest_keys = {_finding_key(f): f for f in latest.get("findings", [])}

    new_findings = [f for key, f in latest_keys.items() if key not in previous_keys]
    resolved_findings = [f for key, f in previous_keys.items() if key not in latest_keys]

    prev_score = calculate_scores(previous.get("findings", []))["overall"]
    curr_score = calculate_scores(latest.get("findings", []))["overall"]

    return {
        "previous_time": previous.get("scan_time", ""),
        "latest_time": latest.get("scan_time", ""),
        "previous_score": prev_score,
        "latest_score": curr_score,
        "score_change": curr_score - prev_score,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
    }


def compute_score_history(scans: list[dict]) -> list[dict]:
    """Skanlar üzrə posture score tarixçəsi."""
    history = []
    for s in scans:
        score = calculate_scores(s.get("findings", []))["overall"]
        history.append({
            "time": s.get("scan_time", ""),
            "score": score,
        })
    return history
