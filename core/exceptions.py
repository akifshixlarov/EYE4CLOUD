"""
core/exceptions.py

"Accepted Risk" mexanizmi: istifadəçi bir tapıntını bilərəkdən qəbul edib
score hesablamasından çıxara bilər. Tapıntı özü heç yerdən silinmir - yalnız
`results/accepted_risks.json`-da qeyd olunur və göstərmə zamanı fərqli
etiketlənir (bax: app.py).
"""

import json
from datetime import datetime, timezone
from pathlib import Path

EXCEPTIONS_FILE = Path(__file__).resolve().parent.parent / "results" / "accepted_risks.json"


def _finding_key(finding: dict) -> tuple:
    """core/diff.py-dakı ilə eyni məntiq: (category, resource, check) tapıntını unikal tanıyır."""
    return (finding["category"], finding["resource"], finding["check"])


def _load() -> list[dict]:
    if not EXCEPTIONS_FILE.exists():
        return []
    with open(EXCEPTIONS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(records: list[dict]) -> None:
    EXCEPTIONS_FILE.parent.mkdir(exist_ok=True)
    with open(EXCEPTIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)


def list_accepted_risks() -> list[dict]:
    """Bütün qəbul edilmiş riskləri qaytarır."""
    return _load()


def accepted_keys_set() -> set:
    """
    list_accepted_risks()-i (category, resource, check) tuple dəstinə
    çevirir - scoring.py-da və app.py-da sürətli üzvlük yoxlaması üçün.
    """
    return {_finding_key(r) for r in _load()}


def accept_risk(finding: dict, reason: str, accepted_by: str = "local-user") -> None:
    """
    Bir tapıntını qəbul edilmiş risk kimi qeyd edir. Eyni tapıntı artıq
    qəbul edilibsə, təkrar əlavə etmir (idempotent).
    """
    records = _load()
    key = _finding_key(finding)

    if any(_finding_key(r) == key for r in records):
        return

    records.append({
        "category": finding["category"],
        "resource": finding["resource"],
        "check": finding["check"],
        "accepted_by": accepted_by,
        "reason": reason,
        "accepted_at": datetime.now(timezone.utc).isoformat(),
    })
    _save(records)


def revoke_acceptance(category: str, resource: str, check: str) -> None:
    """Bir qəbul edilmiş riski ləğv edir (siyahıdan çıxarır)."""
    records = _load()
    key = (category, resource, check)
    records = [r for r in records if _finding_key(r) != key]
    _save(records)


def is_accepted(finding: dict, accepted_keys: set | None = None) -> bool:
    """
    Bir tapıntının qəbul edilib-edilmədiyini yoxlayır. Çoxlu finding üçün
    təkrar-təkrar fayl oxumamaq üçün əvvəlcədən hesablanmış `accepted_keys`
    dəsti ötürülə bilər (bax: accepted_keys_set()).
    """
    if accepted_keys is None:
        accepted_keys = accepted_keys_set()
    return _finding_key(finding) in accepted_keys
