"""
tests/test_credentials.py

İctimai (Public Mode) və Təhlükəsizlik Testləri:
1. İki simulyasiya edilmiş sessiya: A-nın credential-ları B tərəfindən istifadə olunmur; B A-nın tapıntılarını görmür.
2. PUBLIC_MODE aktiv olduqda server .env credential-ları tamamilə inkar edilir.
3. Canary secret heç vaxt log-da, xətalarda, eksportlarda və ya results/ qovluğunda görünmür.
4. GUID və input validasiyası qeyri-qanuni daxiletmələri rədd edir.
5. Rate limiter və hərəkətsizlik taymautu düzgün işləyir.
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
    """PUBLIC_MODE və Azure mühit dəyişənlərini idarə etmək üçün fixture."""
    monkeypatch.delenv("PUBLIC_MODE", raising=False)
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    monkeypatch.delenv("AZURE_SUBSCRIPTION_IDS", raising=False)


# ============================================================================
# 1. İKİ SESSİYA ARASINDA TƏCRİD (SESSION ISOLATION)
# ============================================================================
def test_two_simulated_sessions_isolation(monkeypatch):
    """
    Sessiya A və Sessiya B eyni process daxilində tamamilə təcrid olunmalıdır:
    - A-nın credential-ları heç vaxt B-yə ötürülmür.
    - B heç vaxt A-nın tapıntılarını və skanlarını görmür.
    """
    monkeypatch.setenv("PUBLIC_MODE", "true")

    # Sessiya A
    session_a_id = "user_session_aaa"
    session_a_creds = {
        "tenant_id": VALID_TENANT,
        "client_id": VALID_CLIENT,
        "client_secret": CANARY_SECRET,
        "subscription_ids": [VALID_SUB_1],
    }
    session_a_scans = []

    # Sessiya B
    session_b_id = "user_session_bbb"
    session_b_creds = None
    session_b_scans = []

    # 1. B credential ötürmədikdə, A-nın credential-ları ona sızmamalıdır
    with pytest.raises(PermissionError):
        get_clients(VALID_SUB_1, credentials=session_b_creds)

    # 2. A skan aparır (mock SDK ilə)
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

    # 3. Sessiya B öz skan siyahısını yoxlayır
    scans_for_b = list_session_scans(session_b_id, session_scans_store=session_b_scans)
    assert len(scans_for_b) == 0  # B A-nın skanını QƏTİYYƏN görmür


# ============================================================================
# 2. PUBLIC_MODE SERVER DƏYƏRLƏRİNİ İNKAR EDİR
# ============================================================================
def test_public_mode_blocks_server_env_credentials(monkeypatch):
    """
    PUBLIC_MODE=true olduqda serverdəki .env credential-ları və az cli rədd edilməlidir.
    """
    monkeypatch.setenv("PUBLIC_MODE", "true")
    monkeypatch.setenv("AZURE_TENANT_ID", "server-tenant")
    monkeypatch.setenv("AZURE_CLIENT_ID", "server-client")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "server-secret")
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)

    assert is_public_mode() is True
    # Server credential-larının olması inkar edilməlidir
    assert has_env_credentials() is False
    assert get_credential_source() == "none"

    # Ziyarətçi credentials ötürmədən get_clients çağırarsa PermissionError almalıdır
    with pytest.raises(PermissionError) as exc_info:
        get_clients("sub-123", credentials=None)
    assert "Açıq (Public) rejimdə server credential-larının istifadəsi qadağandır" in str(exc_info.value)

    # run_scan də credentials olmadan PermissionError verməlidir
    with pytest.raises(PermissionError):
        run_scan(credentials=None)


# ============================================================================
# 3. CANARY SECRET SIZINTISI OLMAMASI (NO LEAKS)
# ============================================================================
def test_canary_secret_never_in_logs_exports_or_disk(tmp_path, monkeypatch, caplog):
    """
    Canary secret stringi heç vaxt diskə, results/ qovluğuna, log-a və ya eksporta düşməməlidir.
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

    # 1. Eksport yoxlanışı
    json_export = export_json(sample_scan)
    assert CANARY_SECRET not in json_export

    html_export = export_html_report(sample_scan, scores)
    assert CANARY_SECRET not in html_export

    csv_export = export_csv(sample_scan["findings"])
    assert CANARY_SECRET not in csv_export

    # 2. Xəta mesajında maskalanma
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

    # 3. Public rejimdə results/ qovluğuna heç bir fayl yazılmamalıdır
    files_created = list(tmp_path.glob("*"))
    assert len(files_created) == 0

    # 4. Redact funksiyası
    raw_error = f"Error communicating with Entra: secret was {CANARY_SECRET}"
    redacted = redact(raw_error, [CANARY_SECRET])
    assert CANARY_SECRET not in redacted
    assert "[REDACTED_SECRET]" in redacted


# ============================================================================
# 4. STRICT GUID VƏ INPUT VALİDASİYASI
# ============================================================================
def test_strict_guid_and_input_validation():
    """GUID və input sahələri sərt qaydalara riayət etməlidir."""
    # Etibarlı GUID
    ok, err = validate_guid(VALID_TENANT, "Tenant ID")
    assert ok is True
    assert err == ""

    # Qeyri-qanuni simvol və ya format (qısa)
    ok, err = validate_guid("not-a-guid-at-all", "Tenant ID")
    assert ok is False
    assert "uzunluğu 36" in err

    # 36 simvollu amma formatı səhv olan GUID
    ok, err = validate_guid("11111111-1111-1111-1111-not-a-guid-!", "Tenant ID")
    assert ok is False
    assert "formatında" in err

    # SQL inyeksiya və ya həddən artıq uzunluq
    ok, err = validate_guid("11111111-1111-1111-1111-111111111111'; DROP TABLE users;--", "Tenant ID")
    assert ok is False

    # Tam form yoxlanışı: 3-dən çox subscription
    too_many_subs = f"{VALID_SUB_1}, {VALID_SUB_2}, 55555555-5555-5555-5555-555555555555, 66666666-6666-6666-6666-666666666666"
    ok, err, _ = validate_credentials_input(VALID_TENANT, VALID_CLIENT, "ValidSecret123!", too_many_subs)
    assert ok is False
    assert "ən çox 3" in err

    # Qısa secret
    ok, err, _ = validate_credentials_input(VALID_TENANT, VALID_CLIENT, "short", VALID_SUB_1)
    assert ok is False
    assert "8 ilə 128" in err

    # Uğurlu hal
    ok, err, clean = validate_credentials_input(VALID_TENANT, VALID_CLIENT, "MySecureSecret_456!", f"{VALID_SUB_1}, {VALID_SUB_2}")
    assert ok is True
    assert len(clean["subscription_ids"]) == 2


# ============================================================================
# 5. RATE LIMITER VƏ INACTIVITY TIMEOUT
# ============================================================================
def test_rate_limiter_and_inactivity_timeout():
    """Rate limiter və hərəkətsizlik taymautunun işləməsi."""
    rate_store = {}

    # 5 dəfəyə qədər icazə verilir
    for i in range(5):
        allowed, _ = check_rate_limit(rate_store, "test_conn", max_count=5, window_seconds=60)
        assert allowed is True

    # 6-cı cəhd rədd edilməlidir
    allowed, msg = check_rate_limit(rate_store, "test_conn", max_count=5, window_seconds=60)
    assert allowed is False
    assert "Sorğu limiti aşıldı" in msg

    # Hərəkətsizlik taymautu
    mock_session = {
        "azure_creds": {"client_secret": CANARY_SECRET},
        "input_client_secret": CANARY_SECRET,
        "_last_activity_ts": time.time() - (INACTIVITY_TIMEOUT_SECONDS + 10),
    }

    # Yoxlayırıq: 15 dəqiqədən çox keçibsə sirlər silinməlidir
    timed_out = check_inactivity(mock_session)
    assert timed_out is True
    assert mock_session["azure_creds"] is None
    assert "input_client_secret" not in mock_session

    # wipe_session_credentials yoxlanışı
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
    """redact() funksiyası token, sirr və şübhəli parametrləri gizlədir."""
    secret = "SuperSecretVal123"
    msg = f"Failed to authenticate with secret={secret} and Bearer eyJhbGciOiJIUzI1NiJ9.test.sig"
    cleaned = redact(msg, [secret])
    assert secret not in cleaned
    assert "[REDACTED_SECRET]" in cleaned
    assert "eyJ" not in cleaned
