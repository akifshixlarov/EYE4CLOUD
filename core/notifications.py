"""
core/notifications.py

Sends a short summary after the scan: posture score, total findings,
new/resolved findings.

Channels:
- Telegram: bot token + chat ID saved from the dashboard (core/settings.py),
  or TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID from .env
- Teams or Slack: TEAMS_WEBHOOK_URL / SLACK_WEBHOOK_URL from .env (Teams wins if both)

If nothing is configured, the notification step is skipped entirely - scan
functionality does not depend on it.
"""

import logging
import os

import requests
from dotenv import load_dotenv

from core.diff import diff_scans
from core.scoring import calculate_scores
from core.settings import load_settings

load_dotenv()

TIMEOUT_SECONDS = 10
TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/sendMessage"

# Card colour by score (Teams MessageCard "themeColor" hex, without "#")
_THEME_COLORS = {
    "good": "2EB886",
    "warning": "E3B341",
    "bad": "D93F3F",
}


def build_summary(result: dict, previous: dict | None = None, trigger: str = "Manual") -> dict:
    """Notification summary for a scan result; `previous` is the scan to diff against (if any)."""
    diff = diff_scans(previous, result) if previous else None
    return {
        "trigger": trigger,
        "score": calculate_scores(result["findings"])["overall"],
        "total_findings": result["total_findings"],
        "subscription_id": ", ".join(result["subscription_ids"]),
        "new_findings": len(diff["new_findings"]) if diff else None,
        "resolved_findings": len(diff["resolved_findings"]) if diff else None,
        "score_change": diff["score_change"] if diff else None,
    }


def _theme_color(score: int) -> str:
    if score >= 80:
        return _THEME_COLORS["good"]
    if score >= 50:
        return _THEME_COLORS["warning"]
    return _THEME_COLORS["bad"]


def _facts(summary: dict) -> list[tuple[str, str]]:
    """
    "name: value" pairs shown in the notification. There is no diff on the first scan -
    in that case the new/resolved rows are not shown at all (they come as None).
    """
    facts = [
        ("Posture Score", f"{summary['score']}/100"),
        ("Total findings", str(summary["total_findings"])),
        ("Subscription", summary["subscription_id"]),
    ]
    if summary.get("trigger"):
        facts.append(("Trigger", summary["trigger"]))

    if summary.get("new_findings") is not None:
        facts.append(("New findings", str(summary["new_findings"])))
        facts.append(("Resolved", str(summary["resolved_findings"])))

        change = summary["score_change"]
        facts.append(("Score change", f"+{change}" if change > 0 else str(change)))

    return facts


def _teams_payload(summary: dict) -> dict:
    """Teams "MessageCard" (Office 365 connector) format."""
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": "Azure Misconfiguration Scan completed",
        "themeColor": _theme_color(summary["score"]),
        "title": "🛡️ Azure Misconfiguration Scan completed",
        "sections": [
            {
                "facts": [{"name": name, "value": value} for name, value in _facts(summary)],
            }
        ],
    }


def _slack_payload(summary: dict) -> dict:
    """Slack "Incoming Webhook" format - plain text is enough."""
    lines = [f"*{name}:* {value}" for name, value in _facts(summary)]
    return {"text": "🛡️ *Azure Misconfiguration Scan completed*\n" + "\n".join(lines)}


def _telegram_text(summary: dict) -> str:
    # Plain text (no parse_mode) - resource names never need escaping
    lines = [f"{name}: {value}" for name, value in _facts(summary)]
    return "🛡️ EYE4CLOUD — Azure scan completed\n\n" + "\n".join(lines)


def send_teams_notification(webhook_url: str, summary: dict) -> bool:
    """Sends a MessageCard to the Teams webhook. Returns True on success."""
    response = requests.post(webhook_url, json=_teams_payload(summary), timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    return True


def send_slack_notification(webhook_url: str, summary: dict) -> bool:
    """Sends a message to the Slack webhook. Returns True on success."""
    response = requests.post(webhook_url, json=_slack_payload(summary), timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    return True


def send_telegram_message(bot_token: str, chat_id: str, text: str) -> bool:
    """
    Sends a text message via the Telegram Bot API. Returns True on success.
    Raises requests.RequestException on failure - its message contains the URL,
    i.e. the bot token, so callers must never log or show str(e).
    """
    response = requests.post(
        TELEGRAM_API_URL.format(token=bot_token),
        json={"chat_id": chat_id, "text": text},
        timeout=TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return True


def telegram_config() -> tuple[str, str] | None:
    """(bot_token, chat_id) from the dashboard settings, else from .env, else None."""
    telegram = load_settings()["telegram"]
    if telegram["enabled"] and telegram["bot_token"] and telegram["chat_id"]:
        return telegram["bot_token"], telegram["chat_id"]

    token, chat_id = os.getenv("TELEGRAM_BOT_TOKEN"), os.getenv("TELEGRAM_CHAT_ID")
    return (token, chat_id) if token and chat_id else None


def notify_scan_complete(summary: dict) -> bool:
    """
    Sends the summary to every configured channel; returns True if at least one
    succeeded. Network errors are swallowed - a missed notification is no reason
    to treat the scan as failed.
    """
    sent = False

    teams_url = os.getenv("TEAMS_WEBHOOK_URL")
    slack_url = os.getenv("SLACK_WEBHOOK_URL")
    try:
        if teams_url:
            sent = send_teams_notification(teams_url, summary)
        elif slack_url:
            sent = send_slack_notification(slack_url, summary)
    except requests.RequestException as e:
        logging.warning("Webhook notification failed (%s)", type(e).__name__)

    telegram = telegram_config()
    if telegram:
        try:
            sent = send_telegram_message(*telegram, _telegram_text(summary)) or sent
        except requests.RequestException as e:
            logging.warning("Telegram notification failed (%s)", type(e).__name__)

    return sent
