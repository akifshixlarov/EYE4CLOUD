"""
checks/sql_checks.py

7 checks on Azure SQL logical servers and their databases:
  1) Firewall rule open to the whole internet (0.0.0.0 - 255.255.255.255)
  2) "Allow Azure services" rule (0.0.0.0 - 0.0.0.0)
  3) Public network access enabled
  4) Minimum TLS version below 1.2
  5) No Microsoft Entra administrator
  6) Server-level auditing disabled
  7) Transparent Data Encryption disabled (per user database, "master" skipped)

All calls are read-only (Reader role). Firewall rules, Entra admin, auditing
and each database's TDE are separate API calls - each one is wrapped on its
own, so one forbidden/failed call only skips that sub-check instead of the
whole server (or module).
"""

import logging

from azure.core.exceptions import HttpResponseError

from core.auth import AzureClients

CATEGORY = "Azure SQL"
OPEN_RANGE = ("0.0.0.0", "255.255.255.255")
AZURE_SERVICES_RANGE = ("0.0.0.0", "0.0.0.0")
# "None" = no minimum enforced (the SDK returns it as a string); None = field not set
WEAK_TLS_VERSIONS = {None, "None", "1.0", "1.1"}


def _finding(resource: str, resource_group: str, check: str,
             issue: str, severity: str) -> dict:
    return {
        "category": CATEGORY,
        "resource": resource,
        "resource_group": resource_group,
        "check": check,
        "issue": issue,
        "severity": severity,
        # CIS IDs for these controls are not verified yet - see CLAUDE.md
        "compliance": "N/A",
    }


def _value(field):
    """SDK enums derive from str but render as 'Enum.MEMBER' in f-strings - take the plain value."""
    return getattr(field, "value", field)


def _safe_call(description: str, call):
    """Runs one read call; on an Azure error logs it and returns None (= skip this sub-check)."""
    try:
        return call()
    except HttpResponseError as e:
        logging.warning("SQL check skipped (%s): %s", description, type(e).__name__)
        return None


def _check_firewall(clients: AzureClients, server_name: str, resource_group: str) -> list[dict]:
    rules = _safe_call(f"firewall rules of {server_name}",
                       lambda: list(clients.sql.firewall_rules.list_by_server(resource_group, server_name)))
    findings = []
    for rule in rules or []:
        ip_range = (rule.start_ip_address, rule.end_ip_address)
        if ip_range == OPEN_RANGE:
            findings.append(_finding(
                server_name, resource_group, "sql_firewall_open_to_internet",
                f"Firewall rule '{rule.name}' allows connections from any IP address "
                "(0.0.0.0 - 255.255.255.255)",
                "High",
            ))
        elif ip_range == AZURE_SERVICES_RANGE:
            findings.append(_finding(
                server_name, resource_group, "sql_allow_azure_services",
                f"Firewall rule '{rule.name}' allows access from all Azure services, "
                "including other customers' resources",
                "Medium",
            ))
    return findings


def _check_server_settings(server, resource_group: str) -> list[dict]:
    findings = []

    if _value(server.public_network_access) == "Enabled":
        findings.append(_finding(
            server.name, resource_group, "sql_public_network_access",
            "Public network access is enabled - the server endpoint is reachable "
            "from the internet (subject to firewall rules)",
            "Medium",
        ))

    min_tls = _value(server.minimal_tls_version)
    if min_tls in WEAK_TLS_VERSIONS:
        findings.append(_finding(
            server.name, resource_group, "sql_min_tls",
            f"Minimum TLS version is '{min_tls or 'not set'}' - TLS below 1.2 is allowed",
            "Medium",
        ))

    return findings


def _check_entra_admin(clients: AzureClients, server_name: str, resource_group: str) -> list[dict]:
    admins = _safe_call(f"Entra admin of {server_name}",
                        lambda: list(clients.sql.server_azure_ad_administrators.list_by_server(resource_group, server_name)))
    if admins is None or admins:
        return []
    return [_finding(
        server_name, resource_group, "sql_no_entra_admin",
        "No Microsoft Entra administrator is configured - only SQL authentication "
        "can be used, without central identity management or MFA",
        "Medium",
    )]


def _check_auditing(clients: AzureClients, server_name: str, resource_group: str) -> list[dict]:
    policy = _safe_call(f"auditing of {server_name}",
                        lambda: clients.sql.server_blob_auditing_policies.get(resource_group, server_name))
    if policy is None or _value(policy.state) == "Enabled":
        return []
    return [_finding(
        server_name, resource_group, "sql_auditing_disabled",
        "Server-level auditing is disabled - database activity is not recorded",
        "Medium",
    )]


def _check_databases_tde(clients: AzureClients, server_name: str, resource_group: str) -> list[dict]:
    databases = _safe_call(f"databases of {server_name}",
                           lambda: list(clients.sql.databases.list_by_server(resource_group, server_name)))
    findings = []
    for db in databases or []:
        if db.name == "master":
            continue
        tde = _safe_call(f"TDE of {server_name}/{db.name}",
                         lambda: clients.sql.transparent_data_encryptions.get(
                             resource_group, server_name, db.name, "current"))
        if tde is not None and _value(tde.state) != "Enabled":
            findings.append(_finding(
                f"{server_name}/{db.name}", resource_group, "sql_tde_disabled",
                "Transparent Data Encryption is disabled - database files and "
                "backups are not encrypted at rest",
                "High",
            ))
    return findings


def check_sql_servers(clients: AzureClients) -> list[dict]:
    findings = []

    # If this list call fails (provider not registered / no access) the error goes
    # up to the scanner, which records it in result["errors"]
    for server in clients.sql.servers.list():
        resource_group = server.id.split("/")[4]

        findings += _check_firewall(clients, server.name, resource_group)
        findings += _check_server_settings(server, resource_group)
        findings += _check_entra_admin(clients, server.name, resource_group)
        findings += _check_auditing(clients, server.name, resource_group)
        findings += _check_databases_tde(clients, server.name, resource_group)

    return findings


def run_all_sql_checks(clients: AzureClients) -> list[dict]:
    return check_sql_servers(clients)
