"""
ui/scanner_runner.py

Skan icrası və nəticələrin idarə edilməsi (Hardened v2):
- Eksplisit credentials parametri (heç bir qlobal state saxlanılmır)
- Qlobal Concurrency Semaphore (eyni anda ən çox 2 paralel skan)
- Per-session Rate Limiting (10 dəqiqədə maks 3 skan)
- Public Mode: nəticələr YALNIZ st.session_state yaddaşında saxlanılır, diskə yazılmır
- Skan bitdikdə avtomatik təmizlənmə (keep_connected=False olduqda)
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
from checks.dependency_checks import run_all_dependency_checks
from core.notifications import notify_scan_complete
from core.history import RESULTS_DIR

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
    st.status konteyneri daxilində paralel skan icra edir.
    Qlobal concurrency və sessiya dərəcəsi hədlərini tətbiq edir.
    """
    # 1. Rate limiting
    rate_limits = st.session_state.get("rate_limits", {})
    allowed, rate_msg = check_rate_limit(rate_limits, "scan", MAX_SCANS_PER_WINDOW)
    if not allowed:
        st.error(f"🛑 {rate_msg}")
        raise PermissionError(rate_msg)

    # 2. Qlobal Concurrency Cap
    acquired = GLOBAL_SCAN_SEMAPHORE.acquire(blocking=False)
    if not acquired:
        err_msg = "Server hal-hazırda tam yüklənib (maksimum paralel skan həddi). Zəhmət olmasa 1-2 dəqiqə sonra cəhd edin."
        st.error(f"⏳ {err_msg}")
        raise RuntimeError(err_msg)

    try:
        subscription_ids = list_subscription_ids(credentials)

        with st.status("🔍 Azure mühiti təhlükəsizlik üzrə skan edilir...", expanded=True) as status_box:
            all_findings = []
            total_steps = len(subscription_ids) * len(CHECK_DEFINITIONS) + 1
            progress_bar = st.progress(0, text="Skan başladılır...")
            completed_steps = 0

            for sub_id in subscription_ids:
                sub_label = sub_id[:8] + "..." if len(sub_id) > 8 else sub_id
                st.write(f"🌐 **Subscription:** `{sub_label}` üçün SDK müştəriləri hazırlanır...")
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
                        progress_bar.progress(percent, text=f"Yoxlanılır: {check_name} ({percent}%)")

                        try:
                            results = future.result()
                            for f in results:
                                f["subscription_id"] = sub_id
                            all_findings.extend(results)
                            detail = f"{len(results)} tapıntı aşkarlandı" if results else "Təmiz ✓"
                            st.write(f"&nbsp;&nbsp;✔️ **{check_name}**: {detail}")
                        except Exception as e:
                            logging.exception("Check '%s' zamanı xəta", check_name)
                            st.write(f"&nbsp;&nbsp;⚠️ **{check_name}**: Xəta səbəbilə atlandı ({type(e).__name__})")

            # Dependency check (CVE)
            st.write("📦 **Dependencies (PyPI / OSV.dev)** zəiflikləri yoxlanılır...")
            try:
                dep_findings = run_all_dependency_checks()
                for f in dep_findings:
                    f["subscription_id"] = "N/A"
                all_findings.extend(dep_findings)
                st.write(f"&nbsp;&nbsp;✔️ **Dependencies**: {len(dep_findings)} tapıntı")
            except Exception:
                logging.exception("Dependency check xətası")
                st.write("&nbsp;&nbsp;⚠️ **Dependencies**: Yoxlama zamanı xəta baş verdi")

            completed_steps += 1
            progress_bar.progress(100, text="Skan tamamlandı!")
            status_box.update(label="✅ Skan uğurla tamamlandı!", state="complete", expanded=False)

        result = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "subscription_ids": subscription_ids,
            "total_findings": len(all_findings),
            "findings": all_findings,
        }

        # 3. Yaddaşda və ya diskdə saxlama
        if is_public_mode():
            # PUBLIC MODE: YALNIZ sessiya yaddaşında saxlanılır, DİSKƏ YAZILMIR
            if session_scans_store is not None:
                session_scans_store.append(result)
            elif "session_scans" in st.session_state:
                st.session_state["session_scans"].append(result)
        else:
            # Qeyri-ictimai (local) rejim
            save_session_scan(result, session_id)
            if session_scans_store is not None:
                session_scans_store.append(result)
            try:
                notify_scan_complete(result)
            except Exception:
                pass

        # 4. Skan bitdikdə avtomatik təmizlənmə (keep_connected=False olduqda)
        if not keep_connected:
            wipe_session_credentials(st.session_state)
            st.info("🔒 Təhlükəsizlik: Skan başa çatdığı üçün credential-lar dərhal yaddaşdan təmizləndi.")

        return result

    finally:
        GLOBAL_SCAN_SEMAPHORE.release()


def save_session_scan(result: dict, session_id: str) -> Path:
    """Nəticəni results/ qovluğunda saxlayır (yalnız non-public rejimdə çağırılır)."""
    if is_public_mode():
        # Public rejimdə heç vaxt diskə yazılmır
        return Path("")

    RESULTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    file_path = RESULTS_DIR / f"scan_{session_id}_{timestamp}.json"

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    return file_path


def list_session_scans(session_id: str, session_scans_store: list[dict] | None = None) -> list[tuple[str, dict]]:
    """
    Sessiyaya aid skanların siyahısını qaytarır.
    İctimai rejimdə və ya sessiya mağazası olduqda köhnə ortaq fayllara heç vaxt fallback etmir.
    """
    # 1. Sessiya yaddaşındakı skanlar
    if session_scans_store:
        res = []
        for idx, s in enumerate(session_scans_store, 1):
            time_str = s["scan_time"][:16].replace("T", " ")
            name = f"scan_{idx}_{time_str}"
            res.append((name, s))
        return res

    if is_public_mode():
        # Public rejimdə diskdəki ortaq fayllar YOXDUR
        return []

    # 2. Qeyri-ictimai (local) rejimdə diskdən oxumaq
    if not RESULTS_DIR.exists():
        return []

    from core.history import load_scan
    session_files = sorted(RESULTS_DIR.glob(f"scan_{session_id}_*.json"))
    res = []
    for p in session_files:
        try:
            res.append((p.name, load_scan(p)))
        except Exception:
            continue
    return res
