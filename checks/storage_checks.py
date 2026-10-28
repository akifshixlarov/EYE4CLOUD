"""
checks/storage_checks.py

3 checks on Storage Accounts:
  1) Is Public Blob Access enabled?
  2) Is Secure Transfer (HTTPS-only) enforced?
  3) Is the minimum TLS version below 1.2?

Each function takes an AzureClients object and returns a list of finding
dicts. All findings share the same "shape" so that later on
scoring.py and app.py can process them easily.
"""

from core.auth import AzureClients

# TLS versions below 1.2 - the Azure SDK returns them as these strings
WEAK_TLS_VERSIONS = {"TLS1_0", "TLS1_1"}


def _finding(resource_name: str, resource_group: str, check: str,
             issue: str, severity: str, compliance: str) -> dict:
    """Small helper to keep the same format across all check modules."""
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
    Checks the allow_blob_public_access field of each Storage Account.
    If True (or None -> Azure treats the default as True), this is a High
    severity problem - anyone could create a public blob container
    without noticing.
    """
    findings = []

    for account in clients.storage.storage_accounts.list():
        resource_group = account.id.split("/")[4]  # extract the RG from the ARM id
        allow_public = account.allow_blob_public_access

        # Azure may return None here - in that case the service default applies (True)
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
    Checks the enable_https_traffic_only field of each Storage Account.
    If False, clients can also connect over HTTP - traffic travels over an
    unencrypted channel (Medium severity, since exploiting it needs extra conditions).
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
    Checks the minimum_tls_version field of each Storage Account.
    Flagged if below TLS 1.2 (TLS1_0 / TLS1_1) - these versions have
    known weaknesses. If the value is None, the account still uses the old default
    (TLS1_0), which is flagged as well.
    """
    findings = []

    for account in clients.storage.storage_accounts.list():
        resource_group = account.id.split("/")[4]

        # The SDK returns an enum for this field (MinimumTlsVersion.TLS1_0). It derives
        # from str, so comparison works, but in an f-string it renders as "MinimumTlsVersion.TLS1_0"
        # - so we take the plain value
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
    """Combines all checks in the storage_checks module into one list."""
    return (
        check_public_blob_access(clients)
        + check_secure_transfer(clients)
        + check_minimum_tls_version(clients)
    )
