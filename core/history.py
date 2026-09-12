"""
core/history.py

Skan tarixçəsini idarə edir: results/ qovluğundakı scan_*.json fayllarını
sadalamaq, birini yükləmək, silmək, hamısını təmizləmək.

core/diff.py analiz (müqayisə/trend) üçün bu modulu istifadə edir - fayl
sisteminə birbaşa toxunan yer yalnız buradadır.
"""

import json
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def list_scan_files() -> list[Path]:
    """results/ qovluğundakı bütün scan fayllarını xronoloji sırada qaytarır."""
    if not RESULTS_DIR.exists():
        return []
    return sorted(RESULTS_DIR.glob("scan_*.json"))


def load_scan(file_path: Path) -> dict:
    """Bir scan_*.json faylını oxuyub dict kimi qaytarır."""
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def delete_scan(file_path: Path) -> None:
    """Tək bir skan faylını silir. Fayl artıq yoxdursa səssizcə keçir."""
    Path(file_path).unlink(missing_ok=True)


def clear_history() -> None:
    """results/ qovluğundakı bütün skan fayllarını silir."""
    for file_path in list_scan_files():
        file_path.unlink()
