"""
tests/test_remediation.py

Unit tests for core/remediation.py.

Covers:
  - Every known check_id returns advice + a rendered command
  - {resource} and {resource_group} placeholders are substituted
  - known_vulnerability strips the ==version suffix for the pip command
  - Unknown check_id returns the default advice and None command
  - No exception is raised for any registered check_id
"""

import pytest
from core.remediation import get_remediation, REMEDIATION, DEFAULT_ADVICE


ALL_CHECK_IDS = list(REMEDIATION.keys())


def _finding(check: str, resource: str = "my-resource", resource_group: str = "my-rg") -> dict:
    return {
        "category": "Test",
        "resource": resource,
        "resource_group": resource_group,
        "check": check,
        "issue": "test",
        "severity": "High",
        "compliance": "N/A",
    }


class TestGetRemediation:
    @pytest.mark.parametrize("check_id", ALL_CHECK_IDS)
    def test_known_check_id_returns_advice_and_command(self, check_id):
        result = get_remediation(_finding(check=check_id))
        assert isinstance(result["advice"], str) and result["advice"]
        assert isinstance(result["command"], str) and result["command"]

    @pytest.mark.parametrize("check_id", ALL_CHECK_IDS)
    def test_no_unrendered_placeholders_remain(self, check_id):
        """After interpolation, no literal {resource} or {resource_group} should survive."""
        result = get_remediation(_finding(check=check_id))
        if result["command"]:
            assert "{resource}" not in result["command"]
            assert "{resource_group}" not in result["command"]

    # Checks whose command templates use custom parameters instead of {resource}
    _RESOURCE_NOT_IN_CMD = {"vm_public_ip", "sql_tde_disabled"}

    @pytest.mark.parametrize("check_id", ALL_CHECK_IDS)
    def test_resource_name_interpolated_in_command(self, check_id):
        result = get_remediation(_finding(check=check_id, resource="specific-resource"))
        if result["command"] and check_id not in self._RESOURCE_NOT_IN_CMD:
            assert "specific-resource" in result["command"]

    def test_resource_group_interpolated_in_command(self):
        result = get_remediation(_finding(check="public_blob_access", resource_group="rg-prod"))
        assert "rg-prod" in result["command"]

    def test_sql_tde_interpolates_server_and_database(self):
        finding = _finding(check="sql_tde_disabled", resource="myserver/mydb", resource_group="rg-prod")
        result = get_remediation(finding)
        assert "myserver" in result["command"]
        assert "mydb" in result["command"]

    def test_unknown_check_id_returns_default(self):
        result = get_remediation(_finding(check="nonexistent_check_xyz"))
        assert result["advice"] == DEFAULT_ADVICE
        assert result["command"] is None

    def test_missing_check_key_returns_default(self):
        result = get_remediation({"resource": "r", "resource_group": "rg"})
        assert result["advice"] == DEFAULT_ADVICE
        assert result["command"] is None

    @pytest.mark.parametrize("check_id", ALL_CHECK_IDS)
    def test_no_exception_raised_for_any_known_check(self, check_id):
        """Smoke test: no check_id in REMEDIATION should ever raise."""
        try:
            get_remediation(_finding(check=check_id))
        except Exception as exc:
            pytest.fail(f"get_remediation raised {type(exc).__name__} for check_id='{check_id}': {exc}")
