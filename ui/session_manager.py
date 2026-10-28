"""
ui/session_manager.py

Helper module that coordinates session data, Demo mode and scan history.
"""

from pathlib import Path
import streamlit as st

from core.diff import diff_scans
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
    Returns a chronological list of (display_name, scan_dict) pairs.
    Loads fake scans in Demo mode, otherwise the scans in session memory.
    """
    if is_demo:
        demo_list = get_demo_scans()
        result = []
        for i, s in enumerate(demo_list, 1):
            time_short = s["scan_time"][:16].replace("T", " ")
            name = f"demo_scan_{i}_{time_short}"
            result.append((name, s))
        return result

    # Scans belonging to the session
    return list_session_scans(session_id, session_scans_store=session_scans_store)


def compute_scan_diff(scans: list[dict]) -> dict | None:
    """
    Compares the last two scans in the list:
    - new_findings
    - resolved_findings
    - score_change
    """
    if len(scans) < 2:
        return None
    return diff_scans(scans[-2], scans[-1])


def compute_score_history(scans: list[dict]) -> list[dict]:
    """Posture score history across scans."""
    history = []
    for s in scans:
        score = calculate_scores(s.get("findings", []))["overall"]
        history.append({
            "time": s.get("scan_time", ""),
            "score": score,
        })
    return history
