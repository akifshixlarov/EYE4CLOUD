"""
core/notifications.py

Sends a short summary to a Teams (or Slack) webhook after the scan:
posture score, total findings, new/resolved findings.

The webhook URL is read from .env (TEAMS_WEBHOOK_URL / SLACK_WEBHOOK_URL).
If neither is set, the notification step is skipped entirely - scan
functionality does not depend on the webhook.
"""

import os

import requests
from dotenv import load_dotenv

load_dotenv()

TIMEOUT_SECONDS = 10

# Card colour by score (Teams MessageCard "themeColor" hex, without "#")
_THEME_COLORS = {
    "good": "2EB886",
    "warning": "E3B341",
    "bad": "D93F3F",
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


def notify_scan_complete(summary: dict) -> bool:
    """
    Sends a notification if a webhook URL is set in .env, otherwise quietly returns
    False. Network errors are swallowed - a missed notification is no reason
    to treat the scan as failed.
    """
    teams_url = os.getenv("TEAMS_WEBHOOK_URL")
    slack_url = os.getenv("SLACK_WEBHOOK_URL")

    try:
        if teams_url:
            return send_teams_notification(teams_url, summary)
        if slack_url:
            return send_slack_notification(slack_url, summary)
    except requests.RequestException:
        return False

    return False
