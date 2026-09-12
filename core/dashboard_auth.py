"""
core/dashboard_auth.py

Dashboard ucun sade giris ekrani (streamlit-authenticator).

**DIQQET - bu production-grade auth DEYIL.** Yalniz demo/lokal istifade ucun
nezerde tutulub: tek istifadeci, .env-de saxlanan parol, rol/icaze modeli yox,
Streamlit-in ozunde HTTPS terminasiyasi yoxdur. Internete acilan qurulusda
bunun evezine reverse proxy + duzgun identity provider istifade edilmelidir.

.env-de DASHBOARD_PASSWORD (ve ya DASHBOARD_PASSWORD_HASH) teyin edilmeyibse
giris ekrani umumiyyetle gosterilmir - dashboard evvelki kimi acig isleyir.
"""

import os

import streamlit as st
import streamlit_authenticator as stauth
from dotenv import load_dotenv

load_dotenv()

COOKIE_NAME = "azure_scanner_auth"
DEFAULT_USERNAME = "admin"
_AUTHENTICATOR_STATE_KEY = "_dashboard_authenticator"

_LOGIN_FIELDS = {
    "Form name": "Giriş",
    "Username": "İstifadəçi adı",
    "Password": "Parol",
    "Login": "Daxil ol",
}


def is_enabled() -> bool:
    """Parol qorumasi konfiqurasiya edilibmi?"""
    return bool(os.getenv("DASHBOARD_PASSWORD_HASH") or os.getenv("DASHBOARD_PASSWORD"))


def _build_authenticator(cookie_key: str) -> stauth.Authenticate:
    # Hash verilibse ondan istifade edirik - auto_hash hazir hash-i taniyib
    # toxunmur. Yalniz aciq parol verilibse, her rerun-da yeniden hash-lenir
    # (bcrypt qesden yavasdir) - ona gore HASH variantini tovsiye edirik.
    password = os.getenv("DASHBOARD_PASSWORD_HASH") or os.getenv("DASHBOARD_PASSWORD")
    username = os.getenv("DASHBOARD_USERNAME", DEFAULT_USERNAME)

    credentials = {
        "usernames": {
            username: {
                "name": username,
                "email": f"{username}@local",
                "password": password,
            }
        }
    }

    return stauth.Authenticate(credentials, COOKIE_NAME, cookie_key, cookie_expiry_days=1)


def require_login() -> bool:
    """
    Parol qorumasi aktivdirse giris formasini cizir. Dashboard-un qalan
    hissesi yalniz bu funksiya True qaytaranda cizilmelidir.

    Qoruma konfiqurasiya edilmeyibse hemise True qaytarir.
    """
    if not is_enabled():
        return True

    # Sessiya cookie-si bu acarla imzalanir. Defolt/bos acara icaze versek,
    # acar repoda aciq olacagi ucun kenar sexs ozune etibarli cookie duzeldib
    # giris ekranini tamamile kece biler - ona gore burada "fail closed" edirik.
    cookie_key = (os.getenv("DASHBOARD_COOKIE_KEY") or "").strip()
    if not cookie_key:
        st.error(
            "Parol qoruması aktivdir, amma `DASHBOARD_COOKIE_KEY` təyin edilməyib. "
            "Sessiya cookie-si bu açarla imzalanır — açar olmadan giriş ekranını "
            "keçmək mümkün olardı, ona görə dashboard açılmır.\n\n"
            "`.env`-ə təsadüfi bir dəyər əlavə et:\n\n"
            "`python -c \"import secrets; print(secrets.token_hex(32))\"`"
        )
        return False

    authenticator = _build_authenticator(cookie_key)
    st.session_state[_AUTHENTICATOR_STATE_KEY] = authenticator

    authenticator.login(fields=_LOGIN_FIELDS)

    status = st.session_state.get("authentication_status")
    if status:
        return True

    if status is False:
        st.error("İstifadəçi adı və ya parol yanlışdır.")
    else:
        st.info("Dashboard-a baxmaq üçün daxil olun.")

    return False


def render_logout() -> None:
    """Sidebar-da 'Çıxış' düyməsi - yalniz qoruma aktiv olanda gosterilir."""
    authenticator = st.session_state.get(_AUTHENTICATOR_STATE_KEY)
    if authenticator is None:
        return

    authenticator.logout("Çıxış", "sidebar")
