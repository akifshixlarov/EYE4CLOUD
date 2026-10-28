"""
ui/auth_panel.py

Hardened sidebar panel for connecting to Azure directly from the dashboard
(Microsoft sign-in via device code, or Service Principal).

SECURITY GUARANTEES:
1. No module-level global state.
2. Data lives only in the current session's st.session_state memory.
3. With PUBLIC_MODE=true, server credentials are rejected and consent is required.
4. Inputs pass strict GUID and length validation.
5. A rate limiter prevents request abuse.
6. On disconnect, all widget keys and secret values are wiped from memory.
"""

import logging
import uuid
import streamlit as st

from core.auth import (
    get_credential_source,
    has_env_credentials,
    sign_in_with_device_code,
    test_connection,
)
from core.security import (
    is_public_mode,
    redact,
    validate_credentials_input,
    validate_subscription_ids,
    check_rate_limit,
    check_inactivity,
    wipe_session_credentials,
    MAX_TEST_CONNECTIONS_PER_WINDOW,
)


def init_session_state() -> str:
    """Assigns a unique session_id and security stores for each user/session."""
    if "session_id" not in st.session_state:
        st.session_state["session_id"] = uuid.uuid4().hex[:12]
    if "azure_creds" not in st.session_state:
        st.session_state["azure_creds"] = None
    if "demo_mode" not in st.session_state:
        st.session_state["demo_mode"] = False
    if "rate_limits" not in st.session_state:
        st.session_state["rate_limits"] = {}
    if "session_scans" not in st.session_state:
        st.session_state["session_scans"] = []
    if "accepted_risks_store" not in st.session_state:
        st.session_state["accepted_risks_store"] = []
    if "keep_connected" not in st.session_state:
        st.session_state["keep_connected"] = False

    # 15-minute inactivity check
    if check_inactivity(st.session_state):
        st.warning("⏱️ Credentials were wiped from memory after 15 minutes of inactivity.")

    return st.session_state["session_id"]


def render_connect_panel() -> None:
    """Renders the secure 'Connect to Azure' panel in the sidebar."""
    st.subheader("🔑 Connect to Azure")

    public = is_public_mode()

    if public:
        st.warning(
            "⚠️ **Public Mode:** Only use an account or Service Principal with the **Reader** role "
            "and only a **test subscription**. Delete the Service Principal secret in the Azure Portal right after checking."
        )
        consent = st.checkbox(
            "I confirm that the account I use has only the Reader role on a test subscription "
            "and that the Service Principal secret will be deleted right after use.",
            key="public_consent_checkbox",
        )
        if not consent:
            st.info("Tick the consent box above to enable the form.")
            return
    else:
        st.warning(
            "⚠️ **Security:** Only use an account or Service Principal with the **Reader** (read-only) role."
        )

    session_creds = st.session_state.get("azure_creds")
    has_env = has_env_credentials()

    if session_creds:
        st.info("🟢 **Session credentials are active** (memory only)")
    elif has_env and not public:
        st.caption("ℹ️ *Server credentials (.env) are available, but you can override them below.*")
    else:
        st.caption("ℹ️ *Sign in with your Microsoft account or enter Service Principal details.*")

    mode = st.radio(
        "Sign-in method",
        ["Sign in with Microsoft", "Service Principal (advanced)"],
        key="auth_mode",
    )

    if mode == "Sign in with Microsoft":
        _render_device_code_login(session_creds)
    else:
        _render_service_principal_form(session_creds)

    keep_connected = st.checkbox(
        "Stay connected after the scan",
        value=st.session_state.get("keep_connected", False),
        key="chk_keep_connected",
        help="When off (recommended), credentials are wiped from memory as soon as the scan finishes",
    )
    st.session_state["keep_connected"] = keep_connected

    if session_creds:
        if st.button("🔌 Disconnect / Clear", type="secondary", width="stretch", key="btn_clear_creds"):
            wipe_session_credentials(st.session_state)
            st.info("Session credentials and input fields were fully cleared.")
            st.rerun()


def _render_device_code_login(session_creds: dict | None) -> None:
    """Sign-in with DeviceCodeCredential: only Subscription ID is required."""
    signed_in = bool(session_creds and session_creds.get("credential") is not None)
    sub_ids_val = ", ".join(session_creds.get("subscription_ids", [])) if signed_in else ""

    if signed_in:
        st.success("🟢 Signed in with Microsoft account")

    sub_ids_input = st.text_input(
        "Subscription ID(s)",
        value=sub_ids_val,
        placeholder="sub-id-1, sub-id-2 (max 3)",
        key="input_dc_sub_ids",
        max_chars=120,
        help="Up to 3 comma-separated Azure Subscription IDs",
    )

    if signed_in:
        if st.button("💾 Update subscriptions", width="stretch", key="btn_dc_save_subs"):
            ok, err, subs = validate_subscription_ids(sub_ids_input)
            if not ok:
                st.error(f"❌ {err}")
            else:
                session_creds["subscription_ids"] = subs
                st.rerun()
        return

    if not st.button("🔐 Sign in with Microsoft", type="primary", width="stretch", key="btn_dc_login"):
        return

    ok, err, subs = validate_subscription_ids(sub_ids_input)
    if not ok:
        st.error(f"❌ {err}")
        return
    allowed, rate_msg = check_rate_limit(
        st.session_state["rate_limits"], "test_conn", MAX_TEST_CONNECTIONS_PER_WINDOW
    )
    if not allowed:
        st.error(rate_msg)
        return

    prompt_box = st.empty()

    # azure-identity calls this callback on the get_token thread, before polling
    def _show_code(verification_uri: str, user_code: str, expires_on) -> None:
        with prompt_box.container():
            st.info("Copy the code, open the link and sign in with your Microsoft account:")
            st.code(user_code, language=None)
            st.link_button("🌐 Open microsoft.com/devicelogin", verification_uri, width="stretch")
            st.caption("Waiting for sign-in to complete (max 5 minutes)...")

    try:
        credential = sign_in_with_device_code(_show_code)
    except Exception as e:
        prompt_box.empty()
        logging.warning("Device code sign-in failed: %s", redact(str(e)))
        st.error("❌ Microsoft sign-in did not complete or timed out. Please try again.")
        return

    st.session_state["azure_creds"] = {"credential": credential, "subscription_ids": subs}
    st.rerun()


def _render_service_principal_form(session_creds: dict | None) -> None:
    """Existing ClientSecretCredential flow: Tenant/Client ID, Secret and Subscription ID."""
    if session_creds and session_creds.get("credential") is not None:
        session_creds = None  # a device code session has none of these fields

    with st.expander("Enter Azure Service Principal", expanded=(session_creds is None)):
        tenant_id_val = session_creds.get("tenant_id", "") if session_creds else ""
        client_id_val = session_creds.get("client_id", "") if session_creds else ""
        sub_ids_val = ", ".join(session_creds.get("subscription_ids", [])) if session_creds else ""

        tenant_id = st.text_input(
            "Tenant ID",
            value=tenant_id_val,
            placeholder="00000000-0000-0000-0000-000000000000",
            key="input_tenant_id",
            max_chars=36,
        )
        client_id = st.text_input(
            "Client ID (App ID)",
            value=client_id_val,
            placeholder="00000000-0000-0000-0000-000000000000",
            key="input_client_id",
            max_chars=36,
        )
        client_secret = st.text_input(
            "Client Secret",
            type="password",
            placeholder="••••••••••••••••",
            key="input_client_secret",
            max_chars=128,
            help="Never written to disk, logs or other sessions",
        )
        sub_ids_input = st.text_input(
            "Subscription ID(s)",
            value=sub_ids_val,
            placeholder="sub-id-1, sub-id-2 (max 3)",
            key="input_sub_ids",
            max_chars=120,
            help="Up to 3 comma-separated Azure Subscription IDs",
        )

        col_save, col_test = st.columns(2)

        with col_save:
            if st.button("💾 Save", width="stretch", key="btn_save_creds"):
                ok, err, clean_creds = validate_credentials_input(
                    tenant_id, client_id, client_secret, sub_ids_input
                )
                if not ok:
                    st.error(f"❌ {err}")
                else:
                    st.session_state["azure_creds"] = clean_creds
                    st.success("Credentials applied to the current session!")
                    st.rerun()

        with col_test:
            if st.button("🧪 Test connection", width="stretch", key="btn_test_conn"):
                # Rate limit check
                allowed, rate_msg = check_rate_limit(
                    st.session_state["rate_limits"],
                    "test_conn",
                    MAX_TEST_CONNECTIONS_PER_WINDOW,
                )
                if not allowed:
                    st.error(rate_msg)
                else:
                    # Validation
                    active_tenant = tenant_id.strip() or (session_creds.get("tenant_id") if session_creds else "")
                    active_client = client_id.strip() or (session_creds.get("client_id") if session_creds else "")
                    active_secret = client_secret.strip() or (session_creds.get("client_secret") if session_creds else "")
                    raw_subs = sub_ids_input.strip() or (", ".join(session_creds.get("subscription_ids", [])) if session_creds else "")

                    ok, err, clean_creds = validate_credentials_input(
                        active_tenant, active_client, active_secret, raw_subs
                    )
                    if not ok:
                        st.error(f"❌ {err}")
                    else:
                        with st.spinner("Testing the Azure connection (read-only)..."):
                            first_sub = clean_creds["subscription_ids"][0]
                            success, msg = test_connection(first_sub, credentials=clean_creds)
                            if success:
                                st.success(f"✅ {msg}")
                            else:
                                st.error(f"❌ {msg}")

