"""
ui/automation_panel.py

Sidebar panels for local (non-public) mode:
- ⏰ Scheduled scan: configures core/scheduler.py (runs with the server's
  .env Service Principal or `az login`, never with dashboard sign-ins)
- 📨 Telegram: bot token + chat ID for scan-complete notifications

Settings are saved to results/settings.json (core/settings.py). The saved bot
token is never sent back to the browser - an empty token field keeps it.
"""

from datetime import datetime, time, timezone

import requests
import streamlit as st

from core.auth import get_credential_source
from core.notifications import send_telegram_message
from core.scheduler import compute_next_run
from core.security import validate_subscription_ids, validate_telegram_config
from core.settings import load_settings, update_settings

_MODE_LABELS = {"daily": "Daily at a fixed time", "interval": "Every N hours"}


def _fmt(iso: str | None) -> str:
    return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M UTC") if iso else "—"


def render_automation_panel() -> None:
    settings = load_settings()
    _render_schedule(settings["schedule"])
    _render_telegram(settings["telegram"])


def _render_schedule(schedule: dict) -> None:
    with st.expander("⏰ Scheduled scan", expanded=schedule["enabled"]):
        source = get_credential_source()
        if source == "environment":
            st.caption("Runs with the Service Principal from `.env`.")
        else:
            st.caption(
                "Runs with the server's `az login` session (no Service Principal in `.env`). "
                "Dashboard sign-ins are not used for background scans."
            )

        enabled = st.toggle("Enable scheduled scan", value=schedule["enabled"], key="sched_enabled")
        mode = st.radio(
            "Frequency",
            list(_MODE_LABELS),
            index=list(_MODE_LABELS).index(schedule["mode"]),
            format_func=_MODE_LABELS.get,
            key="sched_mode",
        )
        if mode == "daily":
            run_time = st.time_input("Time (UTC)", value=time.fromisoformat(schedule["time"]), step=900, key="sched_time")
            interval_hours = schedule["interval_hours"]
        else:
            run_time = time.fromisoformat(schedule["time"])
            interval_hours = st.number_input(
                "Every N hours", min_value=1, max_value=168, value=int(schedule["interval_hours"]), key="sched_hours"
            )
        raw_subs = st.text_input(
            "Subscription ID(s) (optional)",
            value=", ".join(schedule["subscription_ids"]),
            placeholder="Empty = AZURE_SUBSCRIPTION_ID(S) from .env",
            key="sched_subs",
        )

        if st.button("💾 Save schedule", width="stretch", key="btn_save_schedule"):
            subs = []
            if raw_subs.strip():
                ok, err, subs = validate_subscription_ids(raw_subs)
                if not ok:
                    st.error(err)
                    return
            new_schedule = {
                "enabled": enabled,
                "mode": mode,
                "time": run_time.strftime("%H:%M"),
                "interval_hours": int(interval_hours),
                "subscription_ids": subs,
            }
            next_run = compute_next_run(new_schedule, datetime.now(timezone.utc)) if enabled else None
            schedule = update_settings(
                "schedule", **new_schedule, next_run=next_run.isoformat() if next_run else None
            )["schedule"]
            st.success("Schedule saved." if enabled else "Scheduled scan disabled.")

        st.caption(
            f"Next run: **{_fmt(schedule['next_run'])}**  \n"
            f"Last run: {_fmt(schedule['last_run'])} — {schedule['last_status'] or '—'}"
        )


def _render_telegram(telegram: dict) -> None:
    with st.expander("📨 Telegram notifications", expanded=telegram["enabled"]):
        st.caption(
            "Sends a summary after every manual and scheduled scan. Create a bot with "
            "@BotFather, send it a message, then get your chat ID (e.g. from @userinfobot)."
        )
        enabled = st.toggle("Enable Telegram notifications", value=telegram["enabled"], key="tg_enabled")
        token_input = st.text_input(
            "Bot token",
            type="password",
            placeholder="Saved — leave empty to keep" if telegram["bot_token"] else "123456789:ABC...",
            key="input_tg_bot_token",
        )
        chat_id = st.text_input("Chat ID", value=telegram["chat_id"], key="tg_chat_id")

        bot_token = token_input.strip() or telegram["bot_token"]
        col_save, col_test = st.columns(2)
        with col_save:
            if st.button("💾 Save", width="stretch", key="btn_save_tg"):
                ok, err = validate_telegram_config(bot_token, chat_id) if enabled else (True, "")
                if not ok:
                    st.error(err)
                else:
                    update_settings("telegram", enabled=enabled, bot_token=bot_token.strip(), chat_id=chat_id.strip())
                    st.success("Telegram settings saved." if enabled else "Telegram notifications disabled.")
        with col_test:
            if st.button("📤 Send test", width="stretch", key="btn_test_tg"):
                ok, err = validate_telegram_config(bot_token, chat_id)
                if not ok:
                    st.error(err)
                    return
                try:
                    send_telegram_message(bot_token.strip(), chat_id.strip(), "✅ EYE4CLOUD test message — notifications work.")
                    st.success("Test message sent.")
                except requests.RequestException as e:
                    # Never show str(e): it contains the request URL, i.e. the bot token
                    status = getattr(e.response, "status_code", None)
                    hint = {401: "the bot token is wrong", 400: "chat not found — send the bot a message first"}
                    st.error(f"Telegram rejected the message ({hint.get(status, status or type(e).__name__)}).")
