"""
tests/test_sql_checks.py

checks/sql_checks.py with fake SDK objects (no real Azure calls):
a vulnerable server, a safe server, "master" skipped, a server without
databases, and one forbidden call that must not hide the other findings.
Also: core/scanner.py records a failing module in result["errors"].
"""

from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch

from azure.core.exceptions import HttpResponseError

from checks.sql_checks import run_all_sql_checks
from core.remediation import get_remediation

RG = "rg-test"


def _server(name, public="Enabled", tls="1.0"):
    return NS(
        id=f"/subscriptions/sub/resourceGroups/{RG}/providers/Microsoft.Sql/servers/{name}",
        name=name,
        public_network_access=public,
        minimal_tls_version=tls,
    )


def _sql_client(server, firewall=(), admins=(), auditing="Disabled", databases=(), tde=None):
    """tde: {db_name: state}"""
    sql = MagicMock()
    sql.servers.list.return_value = [server]
    sql.firewall_rules.list_by_server.return_value = [
        NS(name=n, start_ip_address=s, end_ip_address=e) for n, s, e in firewall
    ]
    sql.server_azure_ad_administrators.list_by_server.return_value = list(admins)
    sql.server_blob_auditing_policies.get.return_value = NS(state=auditing)
    sql.databases.list_by_server.return_value = [NS(name=d) for d in databases]
    sql.transparent_data_encryptions.get.side_effect = (
        lambda rg, srv, db, name: NS(state=(tde or {}).get(db, "Enabled"))
    )
    return NS(sql=sql)


def _checks(findings):
    return sorted((f["check"], f["resource"]) for f in findings)


def test_vulnerable_server_flags_every_check():
    clients = _sql_client(
        _server("sql-bad"),
        firewall=[("AllowAll", "0.0.0.0", "255.255.255.255"),
                  ("AllowAllWindowsAzureIps", "0.0.0.0", "0.0.0.0")],
        admins=[],
        auditing="Disabled",
        databases=["master", "appdb"],
        tde={"appdb": "Disabled", "master": "Disabled"},
    )
    findings = run_all_sql_checks(clients)

    assert _checks(findings) == [
        ("sql_allow_azure_services", "sql-bad"),
        ("sql_auditing_disabled", "sql-bad"),
        ("sql_firewall_open_to_internet", "sql-bad"),
        ("sql_min_tls", "sql-bad"),
        ("sql_no_entra_admin", "sql-bad"),
        ("sql_public_network_access", "sql-bad"),
        ("sql_tde_disabled", "sql-bad/appdb"),  # master skipped
    ]
    severities = {f["check"]: f["severity"] for f in findings}
    assert severities["sql_firewall_open_to_internet"] == "High"
    assert severities["sql_tde_disabled"] == "High"
    assert severities["sql_allow_azure_services"] == "Medium"

    for f in findings:
        assert set(f) == {"category", "resource", "resource_group", "check", "issue", "severity", "compliance"}
        assert f["category"] == "Azure SQL" and f["resource_group"] == RG
        # Every check has its own remediation entry
        assert get_remediation(f)["command"]


def test_safe_server_has_no_findings():
    clients = _sql_client(
        _server("sql-good", public="Disabled", tls="1.2"),
        firewall=[("Office", "203.0.113.10", "203.0.113.10")],
        admins=[NS(login="sql-admins")],
        auditing="Enabled",
        databases=["master", "appdb"],
    )
    assert run_all_sql_checks(clients) == []


def test_tls_not_set_and_server_without_databases():
    clients = _sql_client(_server("sql-empty", public="Disabled", tls=None),
                          admins=[NS()], auditing="Enabled", databases=[])
    assert _checks(run_all_sql_checks(clients)) == [("sql_min_tls", "sql-empty")]


def test_forbidden_call_skips_only_that_subcheck():
    clients = _sql_client(_server("sql-partial"), databases=["appdb"], tde={"appdb": "Disabled"})
    clients.sql.server_blob_auditing_policies.get.side_effect = HttpResponseError("403 Forbidden")
    clients.sql.firewall_rules.list_by_server.side_effect = HttpResponseError("403 Forbidden")

    checks = {f["check"] for f in run_all_sql_checks(clients)}
    assert "sql_auditing_disabled" not in checks
    assert {"sql_public_network_access", "sql_min_tls", "sql_no_entra_admin", "sql_tde_disabled"} <= checks


def test_tde_remediation_splits_server_and_database():
    finding = {"check": "sql_tde_disabled", "resource": "sql-bad/appdb", "resource_group": RG}
    assert get_remediation(finding)["command"] == (
        "az sql db tde set --server sql-bad --database appdb --resource-group rg-test --status Enabled"
    )


def test_scanner_records_failing_module_in_errors(monkeypatch):
    import core.scanner as scanner

    monkeypatch.setenv("PUBLIC_MODE", "true")  # no disk writes / notifications
    ok_module = MagicMock(return_value=[{"category": "Key Vault", "resource": "kv", "check": "soft_delete"}])
    broken_module = MagicMock(side_effect=HttpResponseError("AuthorizationFailed"))
    monkeypatch.setattr(scanner, "CHECK_MODULES", [("Key Vault", ok_module), ("Azure SQL", broken_module)])

    with patch.object(scanner, "get_clients"):
        result = scanner.run_scan(credentials={"credential": object(), "subscription_ids": ["12345678-aaaa"]})

    assert len(result["findings"]) == 1
    assert result["errors"] == ["Azure SQL (sub 12345678...): HttpResponseError - check skipped"]
