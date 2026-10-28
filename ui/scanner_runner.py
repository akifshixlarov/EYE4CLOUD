"""
ui/scanner_runner.py

Scan execution and result management (Hardened v2):
- Explicit credentials parameter (no global state is kept)
- Global concurrency semaphore (at most 2 parallel scans at once)
- Per-session rate limiting (max 3 scans per 10 minutes)
- Public Mode: results are kept ONLY in st.session_state memory, never written to disk
- Automatic cleanup after the scan (when keep_connected=False)
"""

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

from core.auth import get_clients, list_subscription_ids
from core.security import (
    is_public_mode,
    check_rate_limit,
    wipe_session_credentials,
    GLOBAL_SCAN_SEMAPHORE,
    MAX_SCANS_PER_WINDOW,
)
from checks.storage_checks import run_all_storage_checks
from checks.nsg_checks import run_all_nsg_checks
from checks.keyvault_checks import run_all_keyvault_checks
from checks.vm_checks import run_all_vm_checks
from core.notifications import build_summary, notify_scan_complete
from core.history import RESULTS_DIR, load_scan

CHECK_DEFINITIONS = [
    ("Storage Accounts", run_all_storage_checks),
    ("Network Security Groups", run_all_nsg_checks),
    ("Key Vaults", run_all_keyvault_checks),
    ("Virtual Machines", run_all_vm_checks),
]


def execute_parallel_scan(
    session_id: str,
    credentials: dict | None = None,
    keep_connected: bool = False,
    session_scans_store: list[dict] | None = None,
) -> dict:
    """
    Runs the scan in parallel inside an st.status container.
    Enforces global concurrency and per-session rate limits.
    """
    # 1. Rate limiting
    rate_limits = st.session_state.get("rate_limits", {})
    allowed, rate_msg = check_rate_limit(rate_limits, "scan", MAX_SCANS_PER_WINDOW)
    if not allowed:
        st.error(f"🛑 {rate_msg}")
        raise PermissionError(rate_msg)

    # 2. Global concurrency cap
    acquired = GLOBAL_SCAN_SEMAPHORE.acquire(blocking=False)
    if not acquired:
        err_msg = "The server is currently at capacity (maximum parallel scans). Please try again in 1-2 minutes."
        st.error(f"⏳ {err_msg}")
        raise RuntimeError(err_msg)

    try:
        subscription_ids = list_subscription_ids(credentials)

        with st.status("🔍 Scanning the Azure environment for security issues...", expanded=True) as status_box:
            all_findings = []
            total_steps = len(subscription_ids) * len(CHECK_DEFINITIONS)
            progress_bar = st.progress(0, text="Starting scan...")
            completed_steps = 0

            for sub_id in subscription_ids:
                sub_label = sub_id[:8] + "..." if len(sub_id) > 8 else sub_id
                st.write(f"🌐 **Subscription:** preparing SDK clients for `{sub_label}`...")
                clients = get_clients(sub_id, credentials=credentials)

                with ThreadPoolExecutor(max_workers=min(4, len(CHECK_DEFINITIONS))) as executor:
                    future_to_check = {
                        executor.submit(check_fn, clients): check_name
                        for check_name, check_fn in CHECK_DEFINITIONS
                    }

                    for future in as_completed(future_to_check):
                        check_name = future_to_check[future]
                        completed_steps += 1
                        percent = int((completed_steps / total_steps) * 100)
                        progress_bar.progress(percent, text=f"Checking: {check_name} ({percent}%)")

                        try:
                            results = future.result()
                            for f in results:
                                f["subscription_id"] = sub_id
                            all_findings.extend(results)
                            detail = f"{len(results)} findings detected" if results else "Clean ✓"
                            st.write(f"&nbsp;&nbsp;✔️ **{check_name}**: {detail}")
                        except Exception as e:
                            logging.exception("Error during check '%s'", check_name)
                            st.write(f"&nbsp;&nbsp;⚠️ **{check_name}**: Skipped due to an error ({type(e).__name__})")

            progress_bar.progress(100, text="Scan complete!")
            status_box.update(label="✅ Scan completed successfully!", state="complete", expanded=False)

        result = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "subscription_ids": subscription_ids,
            "total_findings": len(all_findings),
            "findings": all_findings,
        }

        # 3. Store in memory or on disk
        if is_public_mode():
            # PUBLIC MODE: kept ONLY in session memory, NEVER WRITTEN TO DISK
            if session_scans_store is not None:
                session_scans_store.append(result)
            elif "session_scans" in st.session_state:
                st.session_state["session_scans"].append(result)
        else:
            # Non-public (local) mode
            previous = session_scans_store[-1] if session_scans_store else None
            save_session_scan(result, session_id)
            if session_scans_store is not None:
                session_scans_store.append(result)
            try:
                notify_scan_complete(build_summary(result, previous))
            except Exception:
                logging.exception("Notification was not sent")

        # 4. Automatic cleanup after the scan (when keep_connected=False)
        if not keep_connected:
            wipe_session_credentials(st.session_state)
            st.info("🔒 Security: credentials were wiped from memory because the scan finished.")

        return result

    finally:
        GLOBAL_SCAN_SEMAPHORE.release()


def save_session_scan(result: dict, session_id: str) -> Path:
    """Saves the result in the results/ folder (only called in non-public mode)."""
    if is_public_mode():
        # Never written to disk in public mode
        return Path("")

    RESULTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    file_path = RESULTS_DIR / f"scan_{session_id}_{timestamp}.json"

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    return file_path


def list_session_scans(session_id: str, session_scans_store: list[dict] | None = None) -> list[tuple[str, dict]]:
    """
    Returns the list of scans belonging to the session.
    In public mode, or when a session store exists, never falls back to legacy shared files.
    In local mode the background scheduler's scans (scan_scheduled_*.json) are
    added too, named by file name so the sidebar delete button works on them.
    """
    if session_scans_store:
        # 1. Scans in session memory
        res = []
        for idx, s in enumerate(session_scans_store, 1):
            time_str = s["scan_time"][:16].replace("T", " ")
            name = f"scan_{idx}_{time_str}"
            res.append((name, s))
    elif is_public_mode():
        # No shared on-disk files in public mode
        return []
    else:
        # 2. Read from disk in non-public (local) mode
        res = _load_scan_files(f"scan_{session_id}_*.json")

    if is_public_mode():
        return res

    res += _load_scan_files("scan_scheduled_*.json")
    res.sort(key=lambda item: item[1].get("scan_time", ""))
    return res


def _load_scan_files(pattern: str) -> list[tuple[str, dict]]:
    res = []
    for p in sorted(RESULTS_DIR.glob(pattern)):
        try:
            res.append((p.name, load_scan(p)))
        except Exception:
            continue
    return res
