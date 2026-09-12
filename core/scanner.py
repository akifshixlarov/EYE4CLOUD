"""
core/scanner.py

Butun checks/*.py modullarini cagirir, neticeleri birlesdirir ve
results/scan_<timestamp>.json faylina yazir.

Bu fayl hem terminaldan birbasa (`python -m core.scanner`) test etmek,
hem de Streamlit app-in "Skan et" duymesinden cagirmaq ucun istifade olunur.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from core.auth import get_clients, list_subscription_ids
from core.diff import compare_last_two_scans
from core.notifications import notify_scan_complete
from core.scoring import calculate_scores
from checks.storage_checks import run_all_storage_checks
from checks.nsg_checks import run_all_nsg_checks
from checks.keyvault_checks import run_all_keyvault_checks
from checks.vm_checks import run_all_vm_checks
from checks.dependency_checks import run_all_dependency_checks

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def run_scan() -> dict:
    """
    Bir tam skan icra edir ve netice + metadata-ni bir dict kimi qaytarir.
    Bu dict eyni zamanda JSON-a yazilan formatdir.

    .env-de bir nece subscription verilibse (AZURE_SUBSCRIPTION_IDS), her biri
    ayrica skan olunur ve neticeler birlesdirilir - her finding-de hansi
    subscription-dan geldiyi gorunur.
    """
    subscription_ids = list_subscription_ids()

    findings = []
    for subscription_id in subscription_ids:
        findings += _scan_subscription(subscription_id)

    # Dependency check subscription-dan asili deyil (layihenin oz
    # kitabxanalarina baxir), ona gore dovreden kenarda bir defe calisir
    for finding in run_all_dependency_checks():
        finding["subscription_id"] = "N/A"
        findings.append(finding)

    result = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "subscription_ids": subscription_ids,
        "total_findings": len(findings),
        "findings": findings,
    }

    _save_result(result)
    _notify(result)
    return result


def _scan_subscription(subscription_id: str) -> list[dict]:
    """Tek bir subscription uzerinde butun Azure check-lerini isledir."""
    clients = get_clients(subscription_id)

    findings = []
    findings += run_all_storage_checks(clients)
    findings += run_all_nsg_checks(clients)
    findings += run_all_keyvault_checks(clients)
    findings += run_all_vm_checks(clients)

    for finding in findings:
        finding["subscription_id"] = subscription_id

    return findings


def _notify(result: dict) -> None:
    """
    Skan xulasesini webhook-a gonderir (eger .env-de konfiqurasiya edilibse).
    Diff yalniz netice diske yazildiqdan sonra hesablanir - beleliklə bu skan
    "latest", ondan evvelki ise "previous" olur.
    """
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


def _save_result(result: dict) -> Path:
    """Neticeni results/ qovlugunda vaxt-damgali JSON kimi saxlayir."""
    RESULTS_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    file_path = RESULTS_DIR / f"scan_{timestamp}.json"

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    return file_path


if __name__ == "__main__":
    # Terminaldan `python -m core.scanner` ile birbasa test etmek ucun
    scan_result = run_scan()
    print(f"Skan tamamlandi: {scan_result['total_findings']} tapinti")
    print(json.dumps(scan_result, indent=2, ensure_ascii=False))
