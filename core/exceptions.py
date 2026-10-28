"""
core/exceptions.py

"Accepted Risk" mechanism: the user can deliberately accept a finding and
exclude it from the score calculation.

Public Mode support:
- In public mode (or when a session store is given), accepted risks are
  kept ONLY in the session's memory (st.session_state).
- The on-disk `results/accepted_risks.json` file is never read or written in public mode.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from core.security import is_public_mode

EXCEPTIONS_FILE = Path(__file__).resolve().parent.parent / "results" / "accepted_risks.json"


def _finding_key(finding: dict) -> tuple:
    """Uniquely identifies a finding by (category, resource, check)."""
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
        # Never written to disk in public mode
        return

    EXCEPTIONS_FILE.parent.mkdir(exist_ok=True)
    with open(EXCEPTIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)


def list_accepted_risks(store: list[dict] | None = None) -> list[dict]:
    """Returns all accepted risks."""
    return list(_load(store))


def accepted_keys_set(store: list[dict] | None = None) -> set:
    """Returns the set of (category, resource, check) tuples."""
    return {_finding_key(r) for r in _load(store)}


def accept_risk(
    finding: dict,
    reason: str,
    accepted_by: str = "visitor",
    store: list[dict] | None = None,
) -> None:
    """Marks a finding as an accepted risk."""
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
    """Revokes an accepted risk."""
    records = _load(store)
    key = (category, resource, check)
    updated = [r for r in records if _finding_key(r) != key]
    _save(updated, store)


def is_accepted(
    finding: dict,
    accepted_keys: set | None = None,
    store: list[dict] | None = None,
) -> bool:
    """Checks whether a finding has been accepted."""
    if accepted_keys is None:
        accepted_keys = accepted_keys_set(store)
    return _finding_key(finding) in accepted_keys
