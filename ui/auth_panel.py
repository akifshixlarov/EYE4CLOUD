"""
ui/auth_panel.py

Dashboard-dan birbaşa Azure Service Principal məlumatlarını daxil etmək üçün
hardened (bərkidilmiş) sidebar paneli.

TƏHLÜKƏSİZLİK ZƏMANƏTLƏRİ:
1. Heç bir modul-səviyyəli qlobal vəziyyət (global state) yoxdur.
2. Məlumatlar yalnız cari sessiyanın st.session_state yaddaşında yaşayır.
3. PUBLIC_MODE=true olduqda server credential-ları rədd edilir, razılıq (consent) tələb olunur.
4. Inputlar dəqiq GUID və uzunluq yoxlamasından keçir.
5. Rate limiter ilə sorğu sui-istifadəsi əngəllənir.
6. Əlaqə kəsildikdə bütün widget açarları və gizli dəyərlər yaddaşdan təmizlənir.
"""

import uuid
import streamlit as st

from core.auth import (
    get_credential_source,
    has_env_credentials,
    test_connection,
)
from core.security import (
    is_public_mode,
    validate_credentials_input,
    check_rate_limit,
    check_inactivity,
    wipe_session_credentials,
    MAX_TEST_CONNECTIONS_PER_WINDOW,
)


def init_session_state() -> str:
    """Hər bir istifadəçi/sessiya üçün unikal session_id və təhlükəsizlik mağazalarını təyin edir."""
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

    # 15 dəqiqəlik hərəkətsizlik yoxlanışı
    if check_inactivity(st.session_state):
        st.warning("⏱️ 15 dəqiqəlik hərəkətsizlik səbəbilə credential-lar yaddaşdan təmizləndi.")

    return st.session_state["session_id"]


def render_connect_panel() -> None:
    """Sidebar-da təhlükəsiz 'Connect to Azure' panelini göstərir."""
    st.subheader("🔑 Connect to Azure")

    public = is_public_mode()

    if public:
        st.warning(
            "⚠️ **İctimai Rejim (Public Mode):** Yalnız **Reader** hüququ olan Service Principal "
            "və yalnız **test abunəliyi** istifadə edin. Yoxlamadan dərhal sonra açarı Azure Portal-dan silin."
        )
        consent = st.checkbox(
            "Mən bu Service Principal-ın test abunəliyində yalnız Reader hüququ olduğunu "
            "və istifadədən dərhal sonra silinəcəyini təsdiq edirəm.",
            key="public_consent_checkbox",
        )
        if not consent:
            st.info("Formu aktivləşdirmək üçün yuxarıdakı razılıq qutusunu işarələyin.")
            return
    else:
        st.warning(
            "⚠️ **Təhlükəsizlik:** Yalnız **Reader** (oxuma) hüququ olan Service Principal istifadə edin."
        )

    session_creds = st.session_state.get("azure_creds")
    has_env = has_env_credentials()

    if session_creds:
        st.info("🟢 **Sessiya credential-ları aktivdir** (yalnız yaddaşdadır)")
    elif has_env and not public:
        st.caption("ℹ️ *Server credential-ları mövcuddur (.env), lakin aşağıdan əvəzləyə bilərsiniz.*")
    else:
        st.caption("ℹ️ *Öz Service Principal məlumatlarınızı daxil edin.*")

    with st.expander("Azure Service Principal daxil et", expanded=(session_creds is None)):
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
            help="Heç vaxt diskə, loglara və ya digər sessiyalara yazılmır",
        )
        sub_ids_input = st.text_input(
            "Subscription ID(s)",
            value=sub_ids_val,
            placeholder="sub-id-1, sub-id-2 (maks 3)",
            key="input_sub_ids",
            max_chars=120,
            help="Vergüllə ayrılmış maksimum 3 Azure Subscription ID",
        )

        keep_connected = st.checkbox(
            "Skan bitdikdən sonra qoşulu saxla",
            value=st.session_state.get("keep_connected", False),
            key="chk_keep_connected",
            help="Deaktiv olduqda (tövsiyə olunur), skan bitən kimi credential-lar yaddaşdan silinir",
        )
        st.session_state["keep_connected"] = keep_connected

        col_save, col_test = st.columns(2)

        with col_save:
            if st.button("💾 Yadda saxla", width="stretch", key="btn_save_creds"):
                ok, err, clean_creds = validate_credentials_input(
                    tenant_id, client_id, client_secret, sub_ids_input
                )
                if not ok:
                    st.error(f"❌ {err}")
                else:
                    st.session_state["azure_creds"] = clean_creds
                    st.success("Credential-lar cari sessiyaya tətbiq edildi!")
                    st.rerun()

        with col_test:
            if st.button("🧪 Test connection", width="stretch", key="btn_test_conn"):
                # Rate limit yoxlanışı
                allowed, rate_msg = check_rate_limit(
                    st.session_state["rate_limits"],
                    "test_conn",
                    MAX_TEST_CONNECTIONS_PER_WINDOW,
                )
                if not allowed:
                    st.error(rate_msg)
                else:
                    # Validasiya
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
                        with st.spinner("Azure ilə əlaqə yoxlanılır (read-only)..."):
                            first_sub = clean_creds["subscription_ids"][0]
                            success, msg = test_connection(first_sub, credentials=clean_creds)
                            if success:
                                st.success(f"✅ {msg}")
                            else:
                                st.error(f"❌ {msg}")

        if session_creds:
            if st.button("🔌 Əlaqəni kəs / Təmizlə", type="secondary", width="stretch", key="btn_clear_creds"):
                wipe_session_credentials(st.session_state)
                st.info("Sessiya credential-ları və daxiletmə sahələri tam təmizləndi.")
                st.rerun()
