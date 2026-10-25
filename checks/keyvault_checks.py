"""
checks/keyvault_checks.py

Key Vault-larda 2 check:
  1) Soft Delete aktivdirmi?
  2) Purge Protection aktivdirmi?

Qeyd: vaults.list_by_subscription() yalniz qismi melumat (id, name, location)
qaytarir - tam properties (enable_soft_delete, enable_purge_protection) ucun
her vault ucun ayrica vaults.get() cagirmaq lazimdir. Bu, Storage/NSG-den
ferqli bir SDK davranisidir, deye buraya qeyd yazdim.
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

        # list_by_subscription qismi melumat qaytardigi ucun tam properties
        # lazimdirsa ayrica get() cagiririq
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
                # the Key Vault is Recoverable" soft delete + purge protection-i
                # bir control kimi qiymetlendirir, ona gore ikisi de eyni ID-ni daşıyır
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
