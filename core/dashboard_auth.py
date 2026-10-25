"""
core/dashboard_auth.py

Dashboard üçün giriş ekranı (streamlit-authenticator) və Brute-force qorunması.
"""

import os
import time

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
    """Parol qoruması konfiqurasiya edilibmi?"""
    return bool(os.getenv("DASHBOARD_PASSWORD_HASH") or os.getenv("DASHBOARD_PASSWORD"))


def _build_authenticator(cookie_key: str) -> stauth.Authenticate:
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
    Parol qoruması aktivdirsə giriş formasını göstərir.
    Uğursuz cəhdlərə qarşı eksponensial lockout (kilidləmə) təmin edir.
    """
    if not is_enabled():
        return True

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

    # Brute-force lockout yoxlanışı
    now = time.time()
    lockout_until = st.session_state.get("_auth_lockout_until", 0)
    if now < lockout_until:
        rem_sec = int(lockout_until - now)
        st.error(f"🛑 Çox sayda uğursuz cəhd aşkarlandı. Zəhmət olmasa {rem_sec} saniyə gözləyin.")
        return False

    authenticator = _build_authenticator(cookie_key)
    st.session_state[_AUTHENTICATOR_STATE_KEY] = authenticator

    authenticator.login(fields=_LOGIN_FIELDS)

    status = st.session_state.get("authentication_status")
    if status is True:
        # Uğurlu giriş - cəhd sayğacını sıfırla
        st.session_state["_auth_failed_attempts"] = 0
        st.session_state.pop("_auth_lockout_until", None)
        return True

    if status is False:
        attempts = st.session_state.get("_auth_failed_attempts", 0) + 1
        st.session_state["_auth_failed_attempts"] = attempts

        if attempts >= 3:
            # Eksponensial gözləmə: 3 cəhddən sonra 10s, 20s, 40s... maks 300s
            delay = min(300, (2 ** (attempts - 3)) * 10)
            st.session_state["_auth_lockout_until"] = now + delay
            st.error(f"İstifadəçi adı və ya parol yanlışdır. Hesab {delay} saniyəlik kilidləndi.")
        else:
            st.error(f"İstifadəçi adı və ya parol yanlışdır. (Qalan cəhd: {3 - attempts})")
    else:
        st.info("Dashboard-a baxmaq üçün daxil olun.")

    return False


def render_logout() -> None:
    """Sidebar-da 'Çıxış' düyməsi."""
    authenticator = st.session_state.get(_AUTHENTICATOR_STATE_KEY)
    if authenticator is None:
        return

    authenticator.logout("Çıxış", "sidebar")
