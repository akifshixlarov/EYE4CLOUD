"""
tests/test_checks.py

Unit tests for all five check modules using mocked Azure SDK objects.
No real Azure connection is required — every SDK call is intercepted
by unittest.mock.MagicMock or unittest.mock.patch.

Coverage:
  checks/storage_checks.py  — 3 functions, 8 tests
  checks/nsg_checks.py      — helpers + main check, 9 tests
  checks/keyvault_checks.py — 2 checks in one function, 6 tests
  checks/vm_checks.py       — 2 checks + HttpResponseError guard, 9 tests
  checks/dependency_checks.py — parser + severity mapper, 5 tests
"""

from unittest.mock import MagicMock, patch, PropertyMock
import pytest

from azure.core.exceptions import HttpResponseError


# ---------------------------------------------------------------------------
# Shared helper: build a fake ARM resource id
# ---------------------------------------------------------------------------
def _arm_id(resource_group: str, provider: str, type_: str, name: str) -> str:
    return (
        f"/subscriptions/sub-1111/resourceGroups/{resource_group}"
        f"/providers/{provider}/{type_}/{name}"
    )


# ---------------------------------------------------------------------------
# checks/storage_checks.py
# ---------------------------------------------------------------------------
from checks.storage_checks import (
    check_public_blob_access,
    check_secure_transfer,
    check_minimum_tls_version,
    run_all_storage_checks,
)


def _make_storage_account(
    name: str,
    rg: str = "rg-test",
    allow_blob_public_access=False,
    enable_https_traffic_only=True,
    minimum_tls_version="TLS1_2",
) -> MagicMock:
    acct = MagicMock()
    acct.id = _arm_id(rg, "Microsoft.Storage", "storageAccounts", name)
    acct.name = name
    acct.allow_blob_public_access = allow_blob_public_access
    acct.enable_https_traffic_only = enable_https_traffic_only
    # SDK returns an enum-like object whose `.value` is the string
    tls_enum = MagicMock()
    tls_enum.value = minimum_tls_version
    acct.minimum_tls_version = tls_enum
    return acct


def _clients_with_storage(accounts: list) -> MagicMock:
    clients = MagicMock()
    clients.storage.storage_accounts.list.return_value = accounts
    return clients


class TestPublicBlobAccess:
    def test_flagged_when_true(self):
        acct = _make_storage_account("st1", allow_blob_public_access=True)
        findings = check_public_blob_access(_clients_with_storage([acct]))
        assert len(findings) == 1
        f = findings[0]
        assert f["check"] == "public_blob_access"
        assert f["severity"] == "High"
        assert f["resource"] == "st1"
        assert f["compliance"] == "CIS Azure 3.7"

    def test_flagged_when_none(self):
        """Azure defaults to True when None — must still be flagged."""
        acct = _make_storage_account("st2", allow_blob_public_access=None)
        findings = check_public_blob_access(_clients_with_storage([acct]))
        assert len(findings) == 1
        assert findings[0]["resource"] == "st2"

    def test_clean_when_false(self):
        acct = _make_storage_account("st3", allow_blob_public_access=False)
        findings = check_public_blob_access(_clients_with_storage([acct]))
        assert findings == []

    def test_mixed_accounts(self):
        """Only the vulnerable account should appear in findings."""
        good = _make_storage_account("good", allow_blob_public_access=False)
        bad = _make_storage_account("bad", allow_blob_public_access=True)
        findings = check_public_blob_access(_clients_with_storage([good, bad]))
        assert len(findings) == 1
        assert findings[0]["resource"] == "bad"

    def test_resource_group_extracted_correctly(self):
        acct = _make_storage_account("st4", rg="rg-prod", allow_blob_public_access=True)
        findings = check_public_blob_access(_clients_with_storage([acct]))
        assert findings[0]["resource_group"] == "rg-prod"


class TestSecureTransfer:
    def test_flagged_when_https_disabled(self):
        acct = _make_storage_account("st5", enable_https_traffic_only=False)
        findings = check_secure_transfer(_clients_with_storage([acct]))
        assert len(findings) == 1
        assert findings[0]["severity"] == "Medium"
        assert findings[0]["compliance"] == "CIS Azure 3.1"

    def test_clean_when_https_enabled(self):
        acct = _make_storage_account("st6", enable_https_traffic_only=True)
        assert check_secure_transfer(_clients_with_storage([acct])) == []

    def test_clean_when_https_is_none(self):
        """None is not False — should not be flagged."""
        acct = _make_storage_account("st7", enable_https_traffic_only=None)
        assert check_secure_transfer(_clients_with_storage([acct])) == []


class TestMinimumTlsVersion:
    @pytest.mark.parametrize("weak_tls", ["TLS1_0", "TLS1_1"])
    def test_flagged_for_weak_tls(self, weak_tls):
        acct = _make_storage_account("stTLS", minimum_tls_version=weak_tls)
        findings = check_minimum_tls_version(_clients_with_storage([acct]))
        assert len(findings) == 1
        assert findings[0]["severity"] == "Medium"
        assert findings[0]["compliance"] == "CIS Azure 3.15"

    def test_flagged_when_tls_none(self):
        """None defaults to TLS1_0 in Azure — must be flagged."""
        acct = _make_storage_account("stNone", minimum_tls_version=None)
        # minimum_tls_version is None → getattr(None, 'value', None) → None
        acct.minimum_tls_version = None
        findings = check_minimum_tls_version(_clients_with_storage([acct]))
        assert len(findings) == 1

    def test_clean_for_tls12(self):
        acct = _make_storage_account("stSafe", minimum_tls_version="TLS1_2")
        assert check_minimum_tls_version(_clients_with_storage([acct])) == []

    def test_run_all_aggregates_all_three(self):
        """run_all_storage_checks must combine findings from all three checks."""
        acct = _make_storage_account(
            "stBad",
            allow_blob_public_access=True,
            enable_https_traffic_only=False,
            minimum_tls_version="TLS1_0",
        )
        findings = run_all_storage_checks(_clients_with_storage([acct]))
        check_ids = [f["check"] for f in findings]
        assert "public_blob_access" in check_ids
        assert "secure_transfer" in check_ids
        assert "minimum_tls_version" in check_ids
        assert len(findings) == 3


# ---------------------------------------------------------------------------
# checks/nsg_checks.py
# ---------------------------------------------------------------------------
from checks.nsg_checks import (
    _port_matches_risky,
    _source_is_open,
    _compliance_for_port,
    check_open_management_ports,
    run_all_nsg_checks,
)


class TestNsgHelpers:
    @pytest.mark.parametrize("port,expected", [
        ("22", "22"),
        ("3389", "3389"),
        ("*", "*"),
        ("20-30", "22"),    # range that includes SSH
        ("3380-3400", "3389"),  # range that includes RDP
        ("80", None),
        ("443", None),
        ("8080", None),
        ("10-20", None),    # safe range
    ])
    def test_port_matches_risky(self, port, expected):
        assert _port_matches_risky(port) == expected

    @pytest.mark.parametrize("source", [
        "0.0.0.0/0", "*", "Internet", "Any",
        "INTERNET", "internet", "any",
    ])
    def test_source_is_open_for_public_sources(self, source):
        assert _source_is_open(source) is True

    @pytest.mark.parametrize("source", [
        "10.0.0.0/8", "192.168.1.1/32", "172.16.0.0/12", "VirtualNetwork",
    ])
    def test_source_is_not_open_for_private(self, source):
        assert _source_is_open(source) is False

    def test_compliance_rdp(self):
        assert _compliance_for_port("3389") == "CIS Azure 6.1"

    def test_compliance_ssh(self):
        assert _compliance_for_port("22") == "CIS Azure 6.2"

    def test_compliance_wildcard(self):
        assert _compliance_for_port("*") == "CIS Azure 6.1, 6.2"


def _make_nsg_rule(
    name: str,
    direction: str = "Inbound",
    access: str = "Allow",
    source_prefix: str = "0.0.0.0/0",
    dest_port: str = "22",
) -> MagicMock:
    rule = MagicMock()
    rule.name = name
    rule.direction = direction
    rule.access = access
    rule.source_address_prefix = source_prefix
    rule.source_address_prefixes = []
    rule.destination_port_range = dest_port
    rule.destination_port_ranges = []
    return rule


def _make_nsg(name: str, rg: str = "rg-net", rules=None) -> MagicMock:
    nsg = MagicMock()
    nsg.id = _arm_id(rg, "Microsoft.Network", "networkSecurityGroups", name)
    nsg.name = name
    nsg.security_rules = rules or []
    return nsg


def _clients_with_nsgs(nsgs: list) -> MagicMock:
    clients = MagicMock()
    clients.network.network_security_groups.list_all.return_value = nsgs
    return clients


class TestNsgChecks:
    def test_ssh_flagged(self):
        rule = _make_nsg_rule("allow-ssh", dest_port="22")
        nsg = _make_nsg("nsg1", rules=[rule])
        findings = check_open_management_ports(_clients_with_nsgs([nsg]))
        assert len(findings) == 1
        assert findings[0]["check"] == "open_management_port"
        assert findings[0]["severity"] == "High"
        assert "22" in findings[0]["issue"]
        assert findings[0]["compliance"] == "CIS Azure 6.2"

    def test_rdp_flagged(self):
        rule = _make_nsg_rule("allow-rdp", dest_port="3389")
        nsg = _make_nsg("nsg2", rules=[rule])
        findings = check_open_management_ports(_clients_with_nsgs([nsg]))
        assert len(findings) == 1
        assert findings[0]["compliance"] == "CIS Azure 6.1"

    def test_wildcard_port_flagged(self):
        rule = _make_nsg_rule("allow-all-ports", dest_port="*")
        nsg = _make_nsg("nsg3", rules=[rule])
        findings = check_open_management_ports(_clients_with_nsgs([nsg]))
        assert len(findings) == 1
        assert findings[0]["compliance"] == "CIS Azure 6.1, 6.2"

    def test_outbound_rule_not_flagged(self):
        rule = _make_nsg_rule("outbound-ssh", direction="Outbound", dest_port="22")
        nsg = _make_nsg("nsg4", rules=[rule])
        assert check_open_management_ports(_clients_with_nsgs([nsg])) == []

    def test_deny_rule_not_flagged(self):
        rule = _make_nsg_rule("deny-ssh", access="Deny", dest_port="22")
        nsg = _make_nsg("nsg5", rules=[rule])
        assert check_open_management_ports(_clients_with_nsgs([nsg])) == []

    def test_private_source_not_flagged(self):
        rule = _make_nsg_rule("internal-ssh", source_prefix="10.0.0.0/8", dest_port="22")
        nsg = _make_nsg("nsg6", rules=[rule])
        assert check_open_management_ports(_clients_with_nsgs([nsg])) == []

    def test_safe_port_not_flagged(self):
        rule = _make_nsg_rule("allow-http", dest_port="80")
        nsg = _make_nsg("nsg7", rules=[rule])
        assert check_open_management_ports(_clients_with_nsgs([nsg])) == []

    def test_source_address_prefixes_list_detected(self):
        """Multi-value source_address_prefixes (list) must also be checked."""
        rule = MagicMock()
        rule.name = "multi-source"
        rule.direction = "Inbound"
        rule.access = "Allow"
        rule.source_address_prefix = None
        rule.source_address_prefixes = ["10.0.0.1", "0.0.0.0/0"]
        rule.destination_port_range = "22"
        rule.destination_port_ranges = []
        nsg = _make_nsg("nsg8", rules=[rule])
        findings = check_open_management_ports(_clients_with_nsgs([nsg]))
        assert len(findings) == 1

    def test_no_rules_returns_empty(self):
        nsg = _make_nsg("nsg9", rules=[])
        assert check_open_management_ports(_clients_with_nsgs([nsg])) == []


# ---------------------------------------------------------------------------
# checks/keyvault_checks.py
# ---------------------------------------------------------------------------
from checks.keyvault_checks import check_key_vaults, run_all_keyvault_checks


def _make_vault_summary(name: str, rg: str = "rg-kv") -> MagicMock:
    summary = MagicMock()
    summary.id = _arm_id(rg, "Microsoft.KeyVault", "vaults", name)
    summary.name = name
    return summary


def _make_vault_detail(
    enable_soft_delete: bool = True,
    enable_purge_protection: bool = True,
) -> MagicMock:
    vault = MagicMock()
    vault.properties.enable_soft_delete = enable_soft_delete
    vault.properties.enable_purge_protection = enable_purge_protection
    return vault


def _clients_with_vaults(vault_pairs: list[tuple]) -> MagicMock:
    """
    vault_pairs: list of (summary_mock, detail_mock) tuples.
    The keyvault client will return summaries from list_by_subscription()
    and the matching detail from vaults.get().
    """
    clients = MagicMock()
    summaries = [pair[0] for pair in vault_pairs]
    detail_map = {pair[0].name: pair[1] for pair in vault_pairs}
    clients.keyvault.vaults.list_by_subscription.return_value = summaries
    clients.keyvault.vaults.get.side_effect = (
        lambda rg, name: detail_map[name]
    )
    return clients


class TestKeyVaultChecks:
    def test_soft_delete_disabled_flagged(self):
        summary = _make_vault_summary("kv1")
        detail = _make_vault_detail(enable_soft_delete=False, enable_purge_protection=True)
        findings = check_key_vaults(_clients_with_vaults([(summary, detail)]))
        checks = [f["check"] for f in findings]
        assert "soft_delete" in checks
        assert "purge_protection" not in checks

    def test_purge_protection_disabled_flagged(self):
        summary = _make_vault_summary("kv2")
        detail = _make_vault_detail(enable_soft_delete=True, enable_purge_protection=False)
        findings = check_key_vaults(_clients_with_vaults([(summary, detail)]))
        checks = [f["check"] for f in findings]
        assert "purge_protection" in checks
        assert "soft_delete" not in checks

    def test_both_disabled_produces_two_findings(self):
        summary = _make_vault_summary("kv3")
        detail = _make_vault_detail(enable_soft_delete=False, enable_purge_protection=False)
        findings = check_key_vaults(_clients_with_vaults([(summary, detail)]))
        assert len(findings) == 2
        checks = [f["check"] for f in findings]
        assert "soft_delete" in checks
        assert "purge_protection" in checks

    def test_compliant_vault_produces_no_findings(self):
        summary = _make_vault_summary("kv4")
        detail = _make_vault_detail(enable_soft_delete=True, enable_purge_protection=True)
        assert check_key_vaults(_clients_with_vaults([(summary, detail)])) == []

    def test_severity_is_high(self):
        summary = _make_vault_summary("kv5")
        detail = _make_vault_detail(enable_soft_delete=False, enable_purge_protection=False)
        for finding in check_key_vaults(_clients_with_vaults([(summary, detail)])):
            assert finding["severity"] == "High"
            assert finding["compliance"] == "CIS Azure 8.5"

    def test_multiple_vaults_independent(self):
        """Two vaults: one compliant, one not. Only the bad one is flagged."""
        s1, d1 = _make_vault_summary("good-vault"), _make_vault_detail()
        s2, d2 = _make_vault_summary("bad-vault"), _make_vault_detail(enable_soft_delete=False)
        findings = check_key_vaults(_clients_with_vaults([(s1, d1), (s2, d2)]))
        resources = [f["resource"] for f in findings]
        assert "bad-vault" in resources
        assert "good-vault" not in resources


# ---------------------------------------------------------------------------
# checks/vm_checks.py
# ---------------------------------------------------------------------------
from checks.vm_checks import (
    _managed_disks,
    check_disk_encryption,
    check_public_ip,
    run_all_vm_checks,
)


def _make_managed_disk(has_des: bool = True) -> MagicMock:
    """has_des: whether Disk Encryption Set is attached."""
    md = MagicMock()
    md.disk_encryption_set = MagicMock() if has_des else None
    return md


def _make_vm(
    name: str,
    rg: str = "rg-compute",
    os_disk_encrypted: bool = True,
    data_disks_encrypted: list[bool] | None = None,
    nic_ids: list[str] | None = None,
) -> MagicMock:
    vm = MagicMock()
    vm.id = _arm_id(rg, "Microsoft.Compute", "virtualMachines", name)
    vm.name = name

    # OS disk
    os_disk = MagicMock()
    os_disk.name = "os-disk"
    os_disk.managed_disk = _make_managed_disk(has_des=os_disk_encrypted)

    # Data disks
    data_disks = []
    for i, enc in enumerate(data_disks_encrypted or []):
        dd = MagicMock()
        dd.name = f"data-disk-{i}"
        dd.lun = i
        dd.managed_disk = _make_managed_disk(has_des=enc)
        data_disks.append(dd)

    vm.storage_profile.os_disk = os_disk
    vm.storage_profile.data_disks = data_disks

    # NICs
    nic_refs = []
    for nic_id in (nic_ids or []):
        ref = MagicMock()
        ref.id = nic_id
        nic_refs.append(ref)
    vm.network_profile.network_interfaces = nic_refs

    return vm


def _make_nic(name: str, rg: str, has_public_ip: bool) -> MagicMock:
    nic = MagicMock()
    ip_config = MagicMock()
    ip_config.public_ip_address = MagicMock() if has_public_ip else None
    nic.ip_configurations = [ip_config]
    return nic


class TestManagedDisksHelper:
    def test_returns_os_and_data_disks(self):
        vm = _make_vm("vm1", data_disks_encrypted=[True, False])
        disks = _managed_disks(vm)
        assert len(disks) == 3  # 1 OS + 2 data

    def test_unmanaged_disk_skipped(self):
        """Data disk with no managed_disk reference is not included."""
        vm = MagicMock()
        os_disk = MagicMock()
        os_disk.name = "os-disk"
        os_disk.managed_disk = _make_managed_disk()
        unmanaged_dd = MagicMock()
        unmanaged_dd.managed_disk = None
        vm.storage_profile.os_disk = os_disk
        vm.storage_profile.data_disks = [unmanaged_dd]
        disks = _managed_disks(vm)
        assert len(disks) == 1  # only OS disk


class TestDiskEncryptionCheck:
    def test_flagged_when_os_disk_not_encrypted(self):
        vm = _make_vm("vm-unenc", os_disk_encrypted=False)
        clients = MagicMock()
        clients.compute.virtual_machines.list_all.return_value = [vm]
        findings = check_disk_encryption(clients)
        assert len(findings) == 1
        assert findings[0]["check"] == "disk_cmk_encryption"
        assert findings[0]["severity"] == "Medium"

    def test_flagged_when_data_disk_not_encrypted(self):
        vm = _make_vm("vm-data-unenc", data_disks_encrypted=[True, False])
        clients = MagicMock()
        clients.compute.virtual_machines.list_all.return_value = [vm]
        findings = check_disk_encryption(clients)
        assert len(findings) == 1
        assert "data-disk-1" in findings[0]["issue"]

    def test_clean_when_all_disks_encrypted(self):
        vm = _make_vm("vm-safe", os_disk_encrypted=True, data_disks_encrypted=[True])
        clients = MagicMock()
        clients.compute.virtual_machines.list_all.return_value = [vm]
        assert check_disk_encryption(clients) == []


class TestPublicIpCheck:
    def _clients_with_vms_and_nic(self, vm, nic_name, rg, has_public_ip):
        clients = MagicMock()
        clients.compute.virtual_machines.list_all.return_value = [vm]
        nic = _make_nic(nic_name, rg, has_public_ip=has_public_ip)
        clients.network.network_interfaces.get.return_value = nic
        return clients

    def test_vm_with_public_ip_flagged(self):
        rg = "rg-compute"
        nic_id = _arm_id(rg, "Microsoft.Network", "networkInterfaces", "nic1")
        vm = _make_vm("vm-public", rg=rg, nic_ids=[nic_id])
        clients = self._clients_with_vms_and_nic(vm, "nic1", rg, has_public_ip=True)
        findings = check_public_ip(clients)
        assert len(findings) == 1
        assert findings[0]["check"] == "vm_public_ip"

    def test_vm_without_public_ip_clean(self):
        rg = "rg-compute"
        nic_id = _arm_id(rg, "Microsoft.Network", "networkInterfaces", "nic2")
        vm = _make_vm("vm-private", rg=rg, nic_ids=[nic_id])
        clients = self._clients_with_vms_and_nic(vm, "nic2", rg, has_public_ip=False)
        assert check_public_ip(clients) == []

    def test_vm_no_nics_clean(self):
        vm = _make_vm("vm-no-nic", nic_ids=[])
        clients = MagicMock()
        clients.compute.virtual_machines.list_all.return_value = [vm]
        assert check_public_ip(clients) == []


class TestRunAllVmChecks:
    def test_http_response_error_returns_empty(self):
        """run_all_vm_checks must return [] when Microsoft.Compute is not registered."""
        clients = MagicMock()
        clients.compute.virtual_machines.list_all.side_effect = HttpResponseError(
            message="The subscription is not registered to use namespace 'Microsoft.Compute'."
        )
        result = run_all_vm_checks(clients)
        assert result == []



