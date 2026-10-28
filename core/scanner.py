"""
core/scanner.py

Calls all checks/*.py modules and merges the results.

Public Mode support:
- With PUBLIC_MODE=true, results are NOT written to disk (results/) and no webhook is sent.
- Credentials are accepted as an explicit parameter and passed to get_clients.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from core.auth import get_clients, list_subscription_ids
from core.diff import compare_last_two_scans
from core.scoring import calculate_scores
from core.notifications import notify_scan_complete
from core.security import is_public_mode
from checks.storage_checks import run_all_storage_checks
from checks.nsg_checks import run_all_nsg_checks
from checks.keyvault_checks import run_all_keyvault_checks
from checks.vm_checks import run_all_vm_checks
from checks.dependency_checks import run_all_dependency_checks

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"

_CHECK_MODULES = [
    ("Storage Account", run_all_storage_checks),
    ("Network Security Group", run_all_nsg_checks),
    ("Key Vault", run_all_keyvault_checks),
    ("Virtual Machine", run_all_vm_checks),
]


def run_scan(
    progress_callback=None,
    session_id: str | None = None,
    credentials: dict | None = None,
) -> dict:
    """
    Runs one full scan and returns the result dict.
    credentials are passed safely from the session as a parameter.
    """
    subscription_ids = list_subscription_ids(credentials)

    findings = []
    for subscription_id in subscription_ids:
        findings += _scan_subscription(
            subscription_id,
            progress_callback=progress_callback,
            credentials=credentials,
        )

    # Dependency check (CVE)
    if progress_callback:
        progress_callback("Dependencies (CVE)", "running", "Querying OSV.dev...")
    for finding in run_all_dependency_checks():
        finding["subscription_id"] = "N/A"
        findings.append(finding)
    if progress_callback:
        progress_callback("Dependencies (CVE)", "complete", "")

    result = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "subscription_ids": subscription_ids,
        "total_findings": len(findings),
        "findings": findings,
    }

    # In public mode nothing is written to disk and no webhook is sent
    if not is_public_mode():
        _save_result(result, session_id=session_id)
        _notify(result)

    return result


def _scan_subscription(
    subscription_id: str,
    progress_callback=None,
    credentials: dict | None = None,
) -> list[dict]:
    """Runs all Azure checks against a single subscription."""
    clients = get_clients(subscription_id, credentials=credentials)

    findings = []
    for check_name, check_fn in _CHECK_MODULES:
        if progress_callback:
            progress_callback(check_name, "running", f"Subscription: {subscription_id[:8]}...")
        try:
            results = check_fn(clients)
            findings += results
            if progress_callback:
                detail = f"{len(results)} findings" if results else "Clean ✓"
                progress_callback(check_name, "complete", detail)
        except Exception:
            logging.exception("Check '%s' failed (sub: %s)", check_name, subscription_id[:8])
            if progress_callback:
                progress_callback(check_name, "error", "An error occurred - skipped")

    for finding in findings:
        finding["subscription_id"] = subscription_id

    return findings


def _notify(result: dict) -> None:
    """Sends the scan summary to the webhook (non-public mode only)."""
    if is_public_mode():
        return

    try:
        diff = compare_last_two_scans()
        summary = {
            "score": calculate_scores(result["findings"])["overall"],
            "total_findings": result["total_findings"],
            "subscription_id": ", ".join(result["subscription_ids"]),
            "new_findings": len(diff["new_findings"]) if diff else None,
            "resolved_findings": len(diff["resolved_findings"]) if diff else None,
            "score_change": diff["score_change"] if diff else None,
        }
        notify_scan_complete(summary)
    except Exception:
        logging.exception("Notification was not sent")


def _save_result(result: dict, session_id: str | None = None) -> Path:
    """Saves the result in the results/ folder (non-public mode only)."""
    RESULTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    if session_id:
        file_path = RESULTS_DIR / f"scan_{session_id}_{timestamp}.json"
    else:
        file_path = RESULTS_DIR / f"scan_{timestamp}.json"

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    return file_path
