"""
core/exceptions.py

"Accepted Risk" mexanizmi: istifadəçi bir tapıntını bilərəkdən qəbul edib
score hesablamasından çıxara bilər.

Public Mode dəstəyi:
- Açıq rejimdə (və ya sessiya mağazası verildikdə) qəbul edilmiş risklər
  YALNIZ sessiyanın yaddaşında (st.session_state) saxlanılır.
- Diskdəki `results/accepted_risks.json` faylı public rejimdə oxunmur və yazılmır.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from core.security import is_public_mode

EXCEPTIONS_FILE = Path(__file__).resolve().parent.parent / "results" / "accepted_risks.json"


def _finding_key(finding: dict) -> tuple:
    """(category, resource, check) tapıntını unikal tanıyır."""
    return (finding["category"], finding["resource"], finding["check"])


def _load(store: list[dict] | None = None) -> list[dict]:
    if store is not None:
        return store
    if is_public_mode():
        return []
    if not EXCEPTIONS_FILE.exists():
        return []
    try:
        with open(EXCEPTIONS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save(records: list[dict], store: list[dict] | None = None) -> None:
    if store is not None:
        store.clear()
        store.extend(records)
        return
    if is_public_mode():
        # Public rejimdə heç vaxt diskə yazılmır
        return

    EXCEPTIONS_FILE.parent.mkdir(exist_ok=True)
    with open(EXCEPTIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)


def list_accepted_risks(store: list[dict] | None = None) -> list[dict]:
    """Bütün qəbul edilmiş riskləri qaytarır."""
    return list(_load(store))


def accepted_keys_set(store: list[dict] | None = None) -> set:
    """(category, resource, check) tuple dəstini qaytarır."""
    return {_finding_key(r) for r in _load(store)}


def accept_risk(
    finding: dict,
    reason: str,
    accepted_by: str = "visitor",
    store: list[dict] | None = None,
) -> None:
    """Bir tapıntını qəbul edilmiş risk kimi qeyd edir."""
    records = _load(store)
    key = _finding_key(finding)

    if any(_finding_key(r) == key for r in records):
        return

    new_record = {
        "category": finding["category"],
        "resource": finding["resource"],
        "check": finding["check"],
        "accepted_by": accepted_by,
        "reason": reason,
        "accepted_at": datetime.now(timezone.utc).isoformat(),
    }
    updated = list(records) + [new_record]
    _save(updated, store)


def revoke_acceptance(
    category: str,
    resource: str,
    check: str,
    store: list[dict] | None = None,
) -> None:
    """Bir qəbul edilmiş riski ləğv edir."""
    records = _load(store)
    key = (category, resource, check)
    updated = [r for r in records if _finding_key(r) != key]
    _save(updated, store)


def is_accepted(
    finding: dict,
    accepted_keys: set | None = None,
    store: list[dict] | None = None,
) -> bool:
    """Bir tapıntının qəbul edilib-edilmədiyini yoxlayır."""
    if accepted_keys is None:
        accepted_keys = accepted_keys_set(store)
    return _finding_key(finding) in accepted_keys
