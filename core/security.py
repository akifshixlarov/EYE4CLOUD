"""
core/security.py

Security and public mode module:
- PUBLIC_MODE check
- Strict GUID and input validation
- Central redact() function (scrubs secrets from logs and errors)
- Session-based rate limiting
- Global scan concurrency limiter (Semaphore)
- Session inactivity timeout and memory wipe
"""

import os
import re
import time
import logging
from threading import Semaphore
from typing import Any

# Global scan concurrency limit: at most 2 scans can run at the same time
MAX_CONCURRENT_SCANS = 2
GLOBAL_SCAN_SEMAPHORE = Semaphore(MAX_CONCURRENT_SCANS)

# Strict GUID regex (8-4-4-4-12 hex)
GUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Rate limiting parameters (10-minute window)
RATE_LIMIT_WINDOW_SECONDS = 600
MAX_TEST_CONNECTIONS_PER_WINDOW = 5
MAX_SCANS_PER_WINDOW = 3

# Inactivity timeout (15 minutes)
INACTIVITY_TIMEOUT_SECONDS = 900


def is_public_mode() -> bool:
    """Determines whether the system runs in open (Public Mode) mode."""
    val = os.getenv("PUBLIC_MODE", "").strip().lower()
    return val in ("true", "1", "yes", "on")


def validate_guid(value: str, field_name: str) -> tuple[bool, str]:
    """Checks that the value is in standard GUID format."""
    if not value or not isinstance(value, str):
        return False, f"{field_name} cannot be empty."
    val_clean = value.strip()
    if len(val_clean) != 36:
        return False, f"{field_name} must be 36 characters long."
    if not GUID_REGEX.match(val_clean):
        return False, f"{field_name} must be a valid GUID (8-4-4-4-12)."
    return True, ""


def validate_credentials_input(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    raw_sub_ids: list[str] | str,
) -> tuple[bool, str, dict]:
    """
    Validates all user-entered fields and returns a cleaned dict.
    No error message ever includes the entered secret.
    """
    # 1. Tenant ID
    ok, err = validate_guid(tenant_id, "Tenant ID")
    if not ok:
        return False, err, {}

    # 2. Client ID
    ok, err = validate_guid(client_id, "Client ID")
    if not ok:
        return False, err, {}

    # 3. Client Secret
    if not client_secret or not isinstance(client_secret, str):
        return False, "Client Secret is required.", {}
    secret_clean = client_secret.strip()
    if len(secret_clean) < 8 or len(secret_clean) > 128:
        return False, "Client Secret must be between 8 and 128 characters.", {}
    # Reject control chars / newlines to prevent injection attempts
    if any(ord(c) < 32 or ord(c) == 127 for c in secret_clean):
        return False, "Client Secret contains invalid characters.", {}

    # 4. Subscription IDs
    ok, err, cleaned_subs = validate_subscription_ids(raw_sub_ids)
    if not ok:
        return False, err, {}

    clean_creds = {
        "tenant_id": tenant_id.strip(),
        "client_id": client_id.strip(),
        "client_secret": secret_clean,
        "subscription_ids": cleaned_subs,
    }
    return True, "", clean_creds


def validate_subscription_ids(raw_sub_ids: list[str] | str) -> tuple[bool, str, list[str]]:
    """Validates comma-separated (max 3) Subscription IDs as GUIDs."""
    if isinstance(raw_sub_ids, str):
        sub_list = [s.strip() for s in raw_sub_ids.split(",") if s.strip()]
    else:
        sub_list = [str(s).strip() for s in raw_sub_ids if str(s).strip()]

    if not sub_list:
        return False, "At least one Subscription ID is required.", []
    if len(sub_list) > 3:
        return False, "At most 3 Subscription IDs can be checked per session.", []

    for idx, s in enumerate(sub_list, 1):
        ok, err = validate_guid(s, f"Subscription #{idx}")
        if not ok:
            return False, err, []
    return True, "", sub_list


def redact(text: Any, secrets: list[str] | None = None) -> str:
    """
    Masks all known secrets or sensitive key patterns in the text with [REDACTED].
    """
    if text is None:
        return ""
    res = str(text)

    # 1. Scrub known secrets
    if secrets:
        for s in secrets:
            if s and isinstance(s, str) and len(s) >= 4:
                res = res.replace(s, "[REDACTED_SECRET]")

    # 2. Scrub generic token/secret regex patterns
    # Bearer tokens
    res = re.sub(r"(Bearer\s+)[A-Za-z0-9_\-\.]{15,}", r"\1[REDACTED_TOKEN]", res, flags=re.IGNORECASE)
    # URL query secret parameters
    res = re.sub(r"((?:client_secret|password|sig|key)=)[^&\s]+", r"\1[REDACTED]", res, flags=re.IGNORECASE)
    # JWT format
    res = re.sub(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", "[REDACTED_JWT]", res)

    return res


def check_rate_limit(
    rate_store: dict,
    action: str,
    max_count: int,
    window_seconds: int = RATE_LIMIT_WINDOW_SECONDS,
) -> tuple[bool, str]:
    """
    Limits the number of operations per session (rate limiter).
    rate_store format: {"test_connection": [timestamp1, timestamp2, ...]}
    """
    now = time.time()
    history = rate_store.setdefault(action, [])
    # Drop entries older than the window
    history = [t for t in history if now - t < window_seconds]
    rate_store[action] = history

    if len(history) >= max_count:
        rem = int(window_seconds - (now - history[0]))
        return False, f"Rate limit exceeded. Please try again in {rem} seconds."

    history.append(now)
    return True, ""


def check_inactivity(session_state: dict) -> bool:
    """
    Checks whether the session has been inactive for 15 minutes.
    If so, wipes the secrets immediately and returns True.
    """
    now = time.time()
    last_act = session_state.get("_last_activity_ts", now)
    session_state["_last_activity_ts"] = now

    if now - last_act > INACTIVITY_TIMEOUT_SECONDS:
        wipe_session_credentials(session_state)
        return True
    return False


def wipe_session_credentials(session_state: dict) -> None:
    """
    Fully wipes secrets and Streamlit widget values stored in the session.
    """
    # 1. Delete the azure_creds structure
    if "azure_creds" in session_state:
        creds = session_state.get("azure_creds")
        if isinstance(creds, dict):
            # Try to blank out the secret's contents in memory
            creds["client_secret"] = " " * len(creds.get("client_secret", ""))
            creds.clear()
        session_state["azure_creds"] = None

    # 2. Clear all Streamlit form widget keys
    widget_keys = [
        "input_tenant_id",
        "input_client_id",
        "input_client_secret",
        "input_sub_ids",
        "input_dc_sub_ids",
        "form_tenant_id",
        "form_client_id",
        "form_client_secret",
        "form_sub_ids",
    ]
    # Only delete: writing to an already-rendered widget key raises in Streamlit
    for k in widget_keys:
        session_state.pop(k, None)
