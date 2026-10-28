"""
core/dashboard_auth.py

Login screen for the dashboard (streamlit-authenticator) and brute-force protection.
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
    "Form name": "Login",
    "Username": "Username",
    "Password": "Password",
    "Login": "Log in",
}


def is_enabled() -> bool:
    """Is password protection configured?"""
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
    Shows the login form if password protection is enabled.
    Enforces exponential lockout against failed attempts.
    """
    if not is_enabled():
        return True

    cookie_key = (os.getenv("DASHBOARD_COOKIE_KEY") or "").strip()
    if not cookie_key:
        st.error(
            "Password protection is enabled, but `DASHBOARD_COOKIE_KEY` is not set. "
            "The session cookie is signed with this key — without it the login screen "
            "could be bypassed, so the dashboard will not open.\n\n"
            "Add a random value to `.env`:\n\n"
            "`python -c \"import secrets; print(secrets.token_hex(32))\"`"
        )
        return False

    # Brute-force lockout check
    now = time.time()
    lockout_until = st.session_state.get("_auth_lockout_until", 0)
    if now < lockout_until:
        rem_sec = int(lockout_until - now)
        st.error(f"🛑 Too many failed attempts detected. Please wait {rem_sec} seconds.")
        return False

    authenticator = _build_authenticator(cookie_key)
    st.session_state[_AUTHENTICATOR_STATE_KEY] = authenticator

    authenticator.login(fields=_LOGIN_FIELDS)

    status = st.session_state.get("authentication_status")
    if status is True:
        # Successful login - reset the attempt counter
        st.session_state["_auth_failed_attempts"] = 0
        st.session_state.pop("_auth_lockout_until", None)
        return True

    if status is False:
        attempts = st.session_state.get("_auth_failed_attempts", 0) + 1
        st.session_state["_auth_failed_attempts"] = attempts

        if attempts >= 3:
            # Exponential backoff: after 3 attempts 10s, 20s, 40s... max 300s
            delay = min(300, (2 ** (attempts - 3)) * 10)
            st.session_state["_auth_lockout_until"] = now + delay
            st.error(f"Incorrect username or password. Account locked for {delay} seconds.")
        else:
            st.error(f"Incorrect username or password. (Attempts left: {3 - attempts})")
    else:
        st.info("Log in to view the dashboard.")

    return False


def render_logout() -> None:
    """'Logout' button in the sidebar."""
    authenticator = st.session_state.get(_AUTHENTICATOR_STATE_KEY)
    if authenticator is None:
        return

    authenticator.logout("Logout", "sidebar")
