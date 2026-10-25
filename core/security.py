"""
core/security.py

Təhlükəsizlik və ictimai (public) rejim modulu:
- PUBLIC_MODE yoxlanışı
- Strict GUID və input validasiyası
- Mərkəzi redact() funksiyası (log və xətalardan sirlərin təmizlənməsi)
- Sessiya əsaslı Rate Limiting (sorğu həddi)
- Qlobal skan concurrency məhdudlaşdırıcı (Semaphore)
- Sessiya hərəkətsizlik (inactivity) taymautu və yaddaş təmizləmə
"""

import os
import re
import time
import logging
from threading import Semaphore
from typing import Any

# Qlobal skan concurrency limiti: eyni anda ən çox 2 skan icra edilə bilər
MAX_CONCURRENT_SCANS = 2
GLOBAL_SCAN_SEMAPHORE = Semaphore(MAX_CONCURRENT_SCANS)

# Dəqiq GUID regex (8-4-4-4-12 hex)
GUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Rate limiting parametrləri (10 dəqiqəlik pəncərə)
RATE_LIMIT_WINDOW_SECONDS = 600
MAX_TEST_CONNECTIONS_PER_WINDOW = 5
MAX_SCANS_PER_WINDOW = 3

# Hərəkətsizlik taymautu (15 dəqiqə)
INACTIVITY_TIMEOUT_SECONDS = 900


def is_public_mode() -> bool:
    """Sistemin açıq (Public Mode) rejimində işlədiyini müəyyən edir."""
    val = os.getenv("PUBLIC_MODE", "").strip().lower()
    return val in ("true", "1", "yes", "on")


def validate_guid(value: str, field_name: str) -> tuple[bool, str]:
    """Dəyərin standart GUID formatında olduğunu yoxlayır."""
    if not value or not isinstance(value, str):
        return False, f"{field_name} boş ola bilməz."
    val_clean = value.strip()
    if len(val_clean) != 36:
        return False, f"{field_name} uzunluğu 36 simvol olmalıdır."
    if not GUID_REGEX.match(val_clean):
        return False, f"{field_name} etibarlı GUID formatında (8-4-4-4-12) olmalıdır."
    return True, ""


def validate_credentials_input(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    raw_sub_ids: list[str] | str,
) -> tuple[bool, str, dict]:
    """
    İstifadəçi tərəfindən daxil edilən bütün sahələri yoxlayır və təmizlənmiş dict qaytarır.
    Heç bir xəta mesajında daxil edilən sirr əks olunmur.
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
        return False, "Client Secret daxil edilməlidir.", {}
    secret_clean = client_secret.strip()
    if len(secret_clean) < 8 or len(secret_clean) > 128:
        return False, "Client Secret uzunluğu 8 ilə 128 simvol arasında olmalıdır.", {}
    # İdarəetmə simvolları (control chars / newlines) inyeksiya cəhdlərinin qarşısını almaq
    if any(ord(c) < 32 or ord(c) == 127 for c in secret_clean):
        return False, "Client Secret etibarsız simvollar ehtiva edir.", {}

    # 4. Subscription IDs
    if isinstance(raw_sub_ids, str):
        sub_list = [s.strip() for s in raw_sub_ids.split(",") if s.strip()]
    else:
        sub_list = [str(s).strip() for s in raw_sub_ids if str(s).strip()]

    if not sub_list:
        return False, "Ən azı bir Subscription ID daxil edilməlidir.", {}
    if len(sub_list) > 3:
        return False, "Bir sessiyada ən çox 3 Subscription ID yoxlanıla bilər.", {}

    cleaned_subs = []
    for idx, s in enumerate(sub_list, 1):
        ok, err = validate_guid(s, f"Subscription #{idx}")
        if not ok:
            return False, err, {}
        cleaned_subs.append(s)

    clean_creds = {
        "tenant_id": tenant_id.strip(),
        "client_id": client_id.strip(),
        "client_secret": secret_clean,
        "subscription_ids": cleaned_subs,
    }
    return True, "", clean_creds


def redact(text: Any, secrets: list[str] | None = None) -> str:
    """
    Mətndəki bütün məlum sirləri və ya həssas açar nümunələrini [REDACTED] ilə maskalayır.
    """
    if text is None:
        return ""
    res = str(text)

    # 1. Məlum sirləri təmizlə
    if secrets:
        for s in secrets:
            if s and isinstance(s, str) and len(s) >= 4:
                res = res.replace(s, "[REDACTED_SECRET]")

    # 2. Ümumi token/sirr regex nümunələrini təmizlə
    # Bearer tokenlər
    res = re.sub(r"(Bearer\s+)[A-Za-z0-9_\-\.]{15,}", r"\1[REDACTED_TOKEN]", res, flags=re.IGNORECASE)
    # URL query secret parametrləri
    res = re.sub(r"((?:client_secret|password|sig|key)=)[^&\s]+", r"\1[REDACTED]", res, flags=re.IGNORECASE)
    # JWT formatı
    res = re.sub(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", "[REDACTED_JWT]", res)

    return res


def check_rate_limit(
    rate_store: dict,
    action: str,
    max_count: int,
    window_seconds: int = RATE_LIMIT_WINDOW_SECONDS,
) -> tuple[bool, str]:
    """
    Sessiya üzrə əməliyyatların sayını məhdudlaşdırır (Rate limiter).
    rate_store formatı: {"test_connection": [timestamp1, timestamp2, ...]}
    """
    now = time.time()
    history = rate_store.setdefault(action, [])
    # Pəncərədən köhnə qeydləri silirik
    history = [t for t in history if now - t < window_seconds]
    rate_store[action] = history

    if len(history) >= max_count:
        rem = int(window_seconds - (now - history[0]))
        return False, f"Sorğu limiti aşıldı. Zəhmət olmasa {rem} saniyə sonra yenidən cəhd edin."

    history.append(now)
    return True, ""


def check_inactivity(session_state: dict) -> bool:
    """
    Sessiyanın 15 dəqiqə hərəkətsiz qalıb-qalmadığını yoxlayır.
    Əgər hərəkətsizdirsə, sirləri dərhal silir və True qaytarır.
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
    Sessiyada saxlanan sirləri və Streamlit widget dəyərlərini tam silir və təmizləyir.
    """
    # 1. azure_creds strukturunu sil
    if "azure_creds" in session_state:
        creds = session_state.get("azure_creds")
        if isinstance(creds, dict):
            # Yaddaşdakı sirrin məzmununu boşaltmağa cəhd
            creds["client_secret"] = " " * len(creds.get("client_secret", ""))
            creds.clear()
        session_state["azure_creds"] = None

    # 2. Bütün Streamlit form widget açarlarını təmizlə
    widget_keys = [
        "input_tenant_id",
        "input_client_id",
        "input_client_secret",
        "input_sub_ids",
        "form_tenant_id",
        "form_client_id",
        "form_client_secret",
        "form_sub_ids",
    ]
    for k in widget_keys:
        if k in session_state:
            session_state[k] = ""
            session_state.pop(k, None)
