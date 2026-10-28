"""
tests/test_credentials.py

Public Mode and security tests:
1. Two simulated sessions: A's credentials are not used by B; B does not see A's findings.
2. With PUBLIC_MODE enabled, server .env credentials are fully rejected.
3. The canary secret never appears in logs, errors, exports or the results/ folder.
4. GUID and input validation rejects illegal input.
5. The rate limiter and inactivity timeout work correctly.
"""

import json
import logging
import time
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from core.auth import (
    get_clients,
    list_subscription_ids,
    has_env_credentials,
    get_credential_source,
    test_connection as azure_test_connection,
)
from core.scanner import run_scan
from core.security import (
    is_public_mode,
    validate_guid,
    validate_credentials_input,
    redact,
    check_rate_limit,
    check_inactivity,
    wipe_session_credentials,
    INACTIVITY_TIMEOUT_SECONDS,
)
from ui.export import export_json, export_html_report, export_csv
from ui.scanner_runner import list_session_scans, execute_parallel_scan

CANARY_SECRET = "CANARY_AZURE_SECRET_TOKEN_998877_XYZ"
VALID_TENANT = "11111111-1111-1111-1111-111111111111"
VALID_CLIENT = "22222222-2222-2222-2222-222222222222"
VALID_SUB_1 = "33333333-3333-3333-3333-333333333333"
VALID_SUB_2 = "44444444-4444-4444-4444-444444444444"


@pytest.fixture
def clean_env(monkeypatch):
    """Fixture to control PUBLIC_MODE and Azure environment variables."""
    monkeypatch.delenv("PUBLIC_MODE", raising=False)
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    monkeypatch.delenv("AZURE_SUBSCRIPTION_IDS", raising=False)


# ============================================================================
# 1. SESSION ISOLATION BETWEEN TWO SESSIONS
# ============================================================================
def test_two_simulated_sessions_isolation(monkeypatch):
    """
    Session A and Session B must be fully isolated within the same process:
    - A's credentials are never passed to B.
    - B never sees A's findings or scans.
    """
    monkeypatch.setenv("PUBLIC_MODE", "true")

    # Session A
    session_a_id = "user_session_aaa"
    session_a_creds = {
        "tenant_id": VALID_TENANT,
        "client_id": VALID_CLIENT,
        "client_secret": CANARY_SECRET,
        "subscription_ids": [VALID_SUB_1],
    }
    session_a_scans = []

    # Session B
    session_b_id = "user_session_bbb"
    session_b_creds = None
    session_b_scans = []

    # 1. When B passes no credentials, A's credentials must not leak to it
    with pytest.raises(PermissionError):
        get_clients(VALID_SUB_1, credentials=session_b_creds)

    # 2. A runs a scan (with a mocked SDK)
    mock_storage = MagicMock(return_value=[{"category": "Storage Account", "resource": "a_only_storage", "check": "HTTPS", "severity": "High"}])
    mock_definitions = [("Storage Accounts", mock_storage)]

    with patch("ui.scanner_runner.CHECK_DEFINITIONS", mock_definitions), \
         patch("ui.scanner_runner.get_clients") as mock_get_clients, \
         patch("ui.scanner_runner.run_all_dependency_checks", return_value=[]), \
         patch("streamlit.status") as mock_status, \
         patch("streamlit.progress") as mock_progress, \
         patch("streamlit.write"), \
         patch("streamlit.session_state", {"rate_limits": {}}):

        scan_result_a = execute_parallel_scan(
            session_id=session_a_id,
            credentials=session_a_creds,
            keep_connected=True,
            session_scans_store=session_a_scans,
        )

    assert len(session_a_scans) == 1
    assert session_a_scans[0]["findings"][0]["resource"] == "a_only_storage"

    # 3. Session B checks its own scan list
    scans_for_b = list_session_scans(session_b_id, session_scans_store=session_b_scans)
    assert len(scans_for_b) == 0  # B must NEVER see A's scan


# ============================================================================
# 2. PUBLIC_MODE REJECTS SERVER VALUES
# ============================================================================
def test_public_mode_blocks_server_env_credentials(monkeypatch):
    """
    With PUBLIC_MODE=true, server .env credentials and az cli must be rejected.
    """
    monkeypatch.setenv("PUBLIC_MODE", "true")
    monkeypatch.setenv("AZURE_TENANT_ID", "server-tenant")
    monkeypatch.setenv("AZURE_CLIENT_ID", "server-client")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "server-secret")
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)

    assert is_public_mode() is True
    # Server credentials must be reported as absent
    assert has_env_credentials() is False
    assert get_credential_source() == "none"

    # A visitor calling get_clients without credentials must get PermissionError
    with pytest.raises(PermissionError) as exc_info:
        get_clients("sub-123", credentials=None)
    assert "Using server credentials is forbidden in Public mode" in str(exc_info.value)

    # run_scan must also raise PermissionError without credentials
    with pytest.raises(PermissionError):
        run_scan(credentials=None)


# ============================================================================
# 3. CANARY SECRET SIZINTISI OLMAMASI (NO LEAKS)
# ============================================================================
def test_canary_secret_never_in_logs_exports_or_disk(tmp_path, monkeypatch, caplog):
    """
    The canary secret string must never end up on disk, in results/, in logs or in exports.
    """
    monkeypatch.setenv("PUBLIC_MODE", "true")

    import ui.scanner_runner as sr
    monkeypatch.setattr(sr, "RESULTS_DIR", tmp_path)

    sample_scan = {
        "scan_time": "2026-10-25T12:00:00Z",
        "subscription_ids": [VALID_SUB_1],
        "findings": [
            {
                "category": "Key Vault",
                "resource": "kv-test",
                "resource_group": "rg-test",
                "check": "Purge protection",
                "issue": "Purge protection disabled",
                "severity": "High",
                "compliance": "CIS 8.2",
            }
        ],
    }
    scores = {"overall": 70, "findings_by_severity": {"High": 1, "Medium": 0, "Low": 0}}

    # 1. Export check
    json_export = export_json(sample_scan)
    assert CANARY_SECRET not in json_export

    html_export = export_html_report(sample_scan, scores)
    assert CANARY_SECRET not in html_export

    csv_export = export_csv(sample_scan["findings"])
    assert CANARY_SECRET not in csv_export

    # 2. Masking in error messages
    creds = {
        "tenant_id": VALID_TENANT,
        "client_id": VALID_CLIENT,
        "client_secret": CANARY_SECRET,
        "subscription_ids": [VALID_SUB_1],
    }

    with patch("core.auth._build_credential") as mock_build:
        mock_build.side_effect = Exception(f"Detailed Auth Exception with token {CANARY_SECRET}")
        with caplog.at_level(logging.DEBUG):
            ok, msg = azure_test_connection(VALID_SUB_1, credentials=creds)

    assert ok is False
    assert CANARY_SECRET not in msg
    assert CANARY_SECRET not in caplog.text

    # 3. In public mode no file may be written to results/
    files_created = list(tmp_path.glob("*"))
    assert len(files_created) == 0

    # 4. Redact function
    raw_error = f"Error communicating with Entra: secret was {CANARY_SECRET}"
    redacted = redact(raw_error, [CANARY_SECRET])
    assert CANARY_SECRET not in redacted
    assert "[REDACTED_SECRET]" in redacted


# ============================================================================
# 4. STRICT GUID AND INPUT VALIDATION
# ============================================================================
def test_strict_guid_and_input_validation():
    """GUID and input fields must follow strict rules."""
    # Valid GUID
    ok, err = validate_guid(VALID_TENANT, "Tenant ID")
    assert ok is True
    assert err == ""

    # Illegal characters or format (too short)
    ok, err = validate_guid("not-a-guid-at-all", "Tenant ID")
    assert ok is False
    assert "36 characters" in err

    # 36-character GUID with the wrong format
    ok, err = validate_guid("11111111-1111-1111-1111-not-a-guid-!", "Tenant ID")
    assert ok is False
    assert "valid GUID" in err

    # SQL injection or excessive length
    ok, err = validate_guid("11111111-1111-1111-1111-111111111111'; DROP TABLE users;--", "Tenant ID")
    assert ok is False

    # Full form check: more than 3 subscriptions
    too_many_subs = f"{VALID_SUB_1}, {VALID_SUB_2}, 55555555-5555-5555-5555-555555555555, 66666666-6666-6666-6666-666666666666"
    ok, err, _ = validate_credentials_input(VALID_TENANT, VALID_CLIENT, "ValidSecret123!", too_many_subs)
    assert ok is False
    assert "At most 3" in err

    # Short secret
    ok, err, _ = validate_credentials_input(VALID_TENANT, VALID_CLIENT, "short", VALID_SUB_1)
    assert ok is False
    assert "between 8 and 128" in err

    # Success case
    ok, err, clean = validate_credentials_input(VALID_TENANT, VALID_CLIENT, "MySecureSecret_456!", f"{VALID_SUB_1}, {VALID_SUB_2}")
    assert ok is True
    assert len(clean["subscription_ids"]) == 2


# ============================================================================
# 5. RATE LIMITER AND INACTIVITY TIMEOUT
# ============================================================================
def test_rate_limiter_and_inactivity_timeout():
    """Rate limiter and inactivity timeout behaviour."""
    rate_store = {}

    # Allowed up to 5 times
    for i in range(5):
        allowed, _ = check_rate_limit(rate_store, "test_conn", max_count=5, window_seconds=60)
        assert allowed is True

    # The 6th attempt must be rejected
    allowed, msg = check_rate_limit(rate_store, "test_conn", max_count=5, window_seconds=60)
    assert allowed is False
    assert "Rate limit exceeded" in msg

    # Inactivity timeout
    mock_session = {
        "azure_creds": {"client_secret": CANARY_SECRET},
        "input_client_secret": CANARY_SECRET,
        "_last_activity_ts": time.time() - (INACTIVITY_TIMEOUT_SECONDS + 10),
    }

    # Check: secrets must be wiped after more than 15 minutes
    timed_out = check_inactivity(mock_session)
    assert timed_out is True
    assert mock_session["azure_creds"] is None
    assert "input_client_secret" not in mock_session

    # wipe_session_credentials check
    active_session = {
        "azure_creds": {"client_secret": "my-secret"},
        "input_client_secret": "my-secret",
        "input_tenant_id": VALID_TENANT,
    }
    wipe_session_credentials(active_session)
    assert active_session["azure_creds"] is None
    assert "input_client_secret" not in active_session
    assert "input_tenant_id" not in active_session


def test_redact_utility():
    """redact() hides tokens, secrets and suspicious parameters."""
    secret = "SuperSecretVal123"
    msg = f"Failed to authenticate with secret={secret} and Bearer eyJhbGciOiJIUzI1NiJ9.test.sig"
    cleaned = redact(msg, [secret])
    assert secret not in cleaned
    assert "[REDACTED_SECRET]" in cleaned
    assert "eyJ" not in cleaned


def test_device_code_credential_used_in_public_mode(clean_env, monkeypatch):
    """'Sign in with Microsoft' session: the ready credential is used directly, no secret required."""
    monkeypatch.setenv("PUBLIC_MODE", "true")
    fake_cred = MagicMock()
    creds = {"credential": fake_cred, "subscription_ids": [VALID_SUB_1]}

    clients = get_clients(credentials=creds)
    assert clients.subscription_id == VALID_SUB_1
    assert list_subscription_ids(creds) == [VALID_SUB_1]

    session = {"azure_creds": creds, "input_dc_sub_ids": VALID_SUB_1}
    wipe_session_credentials(session)
    assert session["azure_creds"] is None
    assert "input_dc_sub_ids" not in session


def test_validate_subscription_ids():
    from core.security import validate_subscription_ids

    assert validate_subscription_ids(f"{VALID_SUB_1}, {VALID_SUB_2}") == (True, "", [VALID_SUB_1, VALID_SUB_2])
    assert validate_subscription_ids("")[0] is False
    assert validate_subscription_ids("not-a-guid")[0] is False
