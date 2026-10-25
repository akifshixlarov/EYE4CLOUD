"""
checks/storage_checks.py

Storage Account-lar uzerinde 3 check:
  1) Public Blob Access aktivdirmi?
  2) Secure Transfer (HTTPS-only) mecburidirmi?
  3) Minimum TLS versiyasi 1.2-den asagidirmi?

Her funksiya AzureClients obyekti qebul edir ve tapinti dict-lerinin
siyahisini qaytarir. Butun tapintilar eyni "shape"-de olur ki, sonradan
scoring.py ve app.py bunlari asanliqla emal ede bilsin.
"""

from core.auth import AzureClients

# TLS 1.2-den asagi versiyalar - Azure SDK bunlari bu setirlerle qaytarir
WEAK_TLS_VERSIONS = {"TLS1_0", "TLS1_1"}


def _finding(resource_name: str, resource_group: str, check: str,
             issue: str, severity: str, compliance: str) -> dict:
    """Butun check modullarinda eyni formati saxlamaq ucun kicik helper."""
    return {
        "category": "Storage Account",
        "resource": resource_name,
        "resource_group": resource_group,
        "check": check,
        "issue": issue,
        "severity": severity,
        "compliance": compliance,
    }


def check_public_blob_access(clients: AzureClients) -> list[dict]:
    """
    Her Storage Account ucun allow_blob_public_access sahesini yoxlayir.
    True (veya None -> Azure defaultu True qebul edir) olarsa, bu High
    severity problemdir - hec kimin bilmeden public blob container
    yaratmasi mumkundur.
    """
    findings = []

    for account in clients.storage.storage_accounts.list():
        resource_group = account.id.split("/")[4]  # ARM id-den RG-ni cixarmaq
        allow_public = account.allow_blob_public_access

        # Azure-da bu deyer None gele bilir - o zaman servis defaultu tetbiq olunur (True)
        if allow_public is None or allow_public is True:
            findings.append(_finding(
                resource_name=account.name,
                resource_group=resource_group,
                check="public_blob_access",
                issue="Public Blob Access is enabled (or left at default) - "
                      "containers can be made publicly accessible by mistake",
                severity="High",
                # CIS Microsoft Azure Foundations Benchmark v2.1.0
                compliance="CIS Azure 3.7",
            ))

    return findings


def check_secure_transfer(clients: AzureClients) -> list[dict]:
    """
    Her Storage Account ucun enable_https_traffic_only sahesini yoxlayir.
    False olarsa, HTTP ile de elaqe qura bilerler - trafik acilmamis
    kanalla getmis olur (Medium severity, cunki exploit ucun elave serait lazimdir).
    """
    findings = []

    for account in clients.storage.storage_accounts.list():
        resource_group = account.id.split("/")[4]
        https_only = account.enable_https_traffic_only

        if https_only is False:
            findings.append(_finding(
                resource_name=account.name,
                resource_group=resource_group,
                check="secure_transfer",
                issue="Secure Transfer (HTTPS-only) is not enforced - "
                      "unencrypted HTTP connections are allowed",
                severity="Medium",
                # CIS Microsoft Azure Foundations Benchmark v2.1.0
                compliance="CIS Azure 3.1",
            ))

    return findings


def check_minimum_tls_version(clients: AzureClients) -> list[dict]:
    """
    Her Storage Account ucun minimum_tls_version sahesini yoxlayir.
    TLS 1.2-den asagi (TLS1_0 / TLS1_1) olarsa flag edilir - bu versiyalarin
    bilinen zeiflikleri var. Deyer None gelerse, hesab kohne default
    (TLS1_0) ile qalib demekdir, o da flag edilir.
    """
    findings = []

    for account in clients.storage.storage_accounts.list():
        resource_group = account.id.split("/")[4]

        # SDK bu sahe ucun enum qaytarir (MinimumTlsVersion.TLS1_0). O, str-den
        # toreyib, deye muqayise isleyir, amma f-string-de "MinimumTlsVersion.TLS1_0"
        # kimi cixir - ona gore acig deyeri gotururuk
        min_tls = getattr(account.minimum_tls_version, "value", account.minimum_tls_version)

        if min_tls in WEAK_TLS_VERSIONS or min_tls is None:
            findings.append(_finding(
                resource_name=account.name,
                resource_group=resource_group,
                check="minimum_tls_version",
                issue=f"Minimum TLS version is '{min_tls or 'not set (defaults to TLS1_0)'}' - "
                      "TLS below 1.2 has known weaknesses",
                severity="Medium",
                # CIS Microsoft Azure Foundations Benchmark v2.1.0
                compliance="CIS Azure 3.15",
            ))

    return findings


def run_all_storage_checks(clients: AzureClients) -> list[dict]:
    """storage_checks modulundaki butun check-leri bir siyahida birlesdirir."""
    return (
        check_public_blob_access(clients)
        + check_secure_transfer(clients)
        + check_minimum_tls_version(clients)
    )
