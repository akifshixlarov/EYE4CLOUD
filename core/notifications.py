"""
core/notifications.py

Skan bitdikden sonra Teams (ve ya Slack) webhook-una qisa xulase gonderir:
posture score, umumi tapinti sayi, yeni/hell olunan tapinti sayi.

Webhook URL-i .env-den oxunur (TEAMS_WEBHOOK_URL / SLACK_WEBHOOK_URL).
Hec biri teyin edilmeyibse bildiris merhelesi tamamile atlanir - skan
funksionalligi webhook-dan asili deyil.
"""

import os

import requests
from dotenv import load_dotenv

load_dotenv()

TIMEOUT_SECONDS = 10

# Score-a gore kart rengi (Teams MessageCard "themeColor" hex, "#"-siz)
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
    Bildirisde gosterilecek "ad: deyer" cutlukleri. Ilk skanda diff olmur -
    o zaman yeni/hell olunan setirleri hec gosterilmir (None kimi gelir).
    """
    facts = [
        ("Posture Score", f"{summary['score']}/100"),
        ("Ümumi tapıntı", str(summary["total_findings"])),
        ("Subscription", summary["subscription_id"]),
    ]

    if summary.get("new_findings") is not None:
        facts.append(("Yeni tapıntı", str(summary["new_findings"])))
        facts.append(("Həll olunan", str(summary["resolved_findings"])))

        change = summary["score_change"]
        facts.append(("Score dəyişimi", f"+{change}" if change > 0 else str(change)))

    return facts


def _teams_payload(summary: dict) -> dict:
    """Teams "MessageCard" (Office 365 connector) formati."""
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": "Azure Misconfiguration Scan tamamlandı",
        "themeColor": _theme_color(summary["score"]),
        "title": "🛡️ Azure Misconfiguration Scan tamamlandı",
        "sections": [
            {
                "facts": [{"name": name, "value": value} for name, value in _facts(summary)],
            }
        ],
    }


def _slack_payload(summary: dict) -> dict:
    """Slack "Incoming Webhook" formati - sade metn kifayet edir."""
    lines = [f"*{name}:* {value}" for name, value in _facts(summary)]
    return {"text": "🛡️ *Azure Misconfiguration Scan tamamlandı*\n" + "\n".join(lines)}


def send_teams_notification(webhook_url: str, summary: dict) -> bool:
    """Teams webhook-una MessageCard gonderir. Ugurlu olarsa True qaytarir."""
    response = requests.post(webhook_url, json=_teams_payload(summary), timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    return True


def send_slack_notification(webhook_url: str, summary: dict) -> bool:
    """Slack webhook-una mesaj gonderir. Ugurlu olarsa True qaytarir."""
    response = requests.post(webhook_url, json=_slack_payload(summary), timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    return True


def notify_scan_complete(summary: dict) -> bool:
    """
    .env-de webhook URL-i varsa bildiris gonderir, yoxdursa sakitce False
    qaytarir. Sebeke xetalari udulur - bildirisin catmamasi skani ugursuz
    saymaq ucun sebeb deyil.
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
