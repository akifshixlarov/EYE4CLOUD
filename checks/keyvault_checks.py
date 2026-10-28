"""
checks/keyvault_checks.py

2 checks on Key Vaults:
  1) Is Soft Delete enabled?
  2) Is Purge Protection enabled?

Note: vaults.list_by_subscription() returns only partial data (id, name, location)
- the full properties (enable_soft_delete, enable_purge_protection) require
a separate vaults.get() call per vault. This SDK behaviour differs from
Storage/NSG, hence this note.
"""

from core.auth import AzureClients


def _finding(vault_name: str, resource_group: str, check: str,
             issue: str, severity: str, compliance: str) -> dict:
    return {
        "category": "Key Vault",
        "resource": vault_name,
        "resource_group": resource_group,
        "check": check,
        "issue": issue,
        "severity": severity,
        "compliance": compliance,
    }


def check_key_vaults(clients: AzureClients) -> list[dict]:
    findings = []

    for vault_summary in clients.keyvault.vaults.list_by_subscription():
        resource_group = vault_summary.id.split("/")[4]
        vault_name = vault_summary.name

        # list_by_subscription returns partial data, so when full properties
        # are needed we call get() separately
        vault = clients.keyvault.vaults.get(resource_group, vault_name)
        props = vault.properties

        if not props.enable_soft_delete:
            findings.append(_finding(
                vault_name=vault_name,
                resource_group=resource_group,
                check="soft_delete",
                issue="Soft Delete is disabled - deleted secrets, keys, and "
                      "certificates cannot be recovered",
                severity="High",
                # CIS Microsoft Azure Foundations Benchmark v2.1.0 - "8.5 Ensure
                # the Key Vault is Recoverable" treats soft delete + purge protection
                # as one control, so both carry the same ID
                compliance="CIS Azure 8.5",
            ))

        if not props.enable_purge_protection:
            findings.append(_finding(
                vault_name=vault_name,
                resource_group=resource_group,
                check="purge_protection",
                issue="Purge Protection is disabled - the vault can be "
                      "permanently deleted ahead of schedule, even by mistake",
                severity="High",
                compliance="CIS Azure 8.5",
            ))

    return findings


def run_all_keyvault_checks(clients: AzureClients) -> list[dict]:
    return check_key_vaults(clients)
