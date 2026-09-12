"""
checks/dependency_checks.py

Layihənin öz Python asılılıqlarında (requirements.lock.txt) OSV.dev
(Open Source Vulnerabilities) bazasına görə bilinən CVE/GHSA-ları axtarır.
Bu, "öz kitabxanalarında CVE yoxlaması" (SCA - Software Composition
Analysis) hissəsidir, Azure resurslarına deyil, layihənin özünə baxır.

Niyə requirements.lock.txt: OSV sorğusu dəqiq versiya tələb edir, amma
requirements.txt-də `>=` işlədilib. İstifadəçi əvvəlcə bunu çalışdırmalıdır:
    pip freeze > requirements.lock.txt
Bu fayl yoxdursa, check sakitcə boş siyahı qaytarır - xəta atmır.
"""

import re
from pathlib import Path

import requests

LOCK_FILE = Path(__file__).resolve().parent.parent / "requirements.lock.txt"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def _finding(package: str, version: str, vuln_id: str, summary: str, severity: str) -> dict:
    return {
        "category": "Dependency",
        "resource": f"{package}=={version}",
        "resource_group": "N/A",
        "check": "known_vulnerability",
        "issue": f"{vuln_id}: {summary}",
        "severity": severity,
        # CIS Microsoft Azure Foundations Benchmark bulud infrastrukturuna
        # fokuslanib, tetbiq asililiqlarinin (SCA) CVE-lerini ehate etmir -
        # ona gore burada tetbiq oluna bilecek CIS Azure ID-si yoxdur
        "compliance": "N/A (CIS Azure Foundations-un əhatə dairəsindən kənar)",
    }


def _parse_lock_file(lock_path: Path) -> list[tuple[str, str]]:
    """`paket==versiya` sətirlərini (paket, versiya) cütlüklərinə çevirir."""
    packages = []
    for line in lock_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.\-]+)$", line)
        if match:
            packages.append((match.group(1), match.group(2)))
    return packages


def _map_severity(vuln: dict) -> str:
    """
    OSV yazıları severity-ni müxtəlif formatlarda verə bilir (CVSS vektor
    sətri və ya database_specific.severity). Sadəlik üçün yalnız
    database_specific.severity oxunur; o da yoxdursa, ehtiyatlı yanaşıb
    Medium təyin edilir (naməlum severity-ni Low saymaq risklidir).
    """
    db_severity = (vuln.get("database_specific") or {}).get("severity", "").upper()
    if db_severity in ("CRITICAL", "HIGH"):
        return "High"
    if db_severity in ("MODERATE", "MEDIUM"):
        return "Medium"
    if db_severity == "LOW":
        return "Low"
    return "Medium"


def _query_osv(package: str, version: str) -> list[dict]:
    payload = {"version": version, "package": {"name": package, "ecosystem": "PyPI"}}
    response = requests.post(OSV_QUERY_URL, json=payload, timeout=10)
    response.raise_for_status()
    return response.json().get("vulns", [])


def run_all_dependency_checks() -> list[dict]:
    """
    requirements.lock.txt yoxdursa (hələ `pip freeze > requirements.lock.txt`
    icra edilməyibsə), boş siyahı qaytarır. OSV.dev-ə hər hansı paket üçün
    şəbəkə xətası olarsa, yalnız o paket atlanır - bütün skan dayanmır.
    """
    if not LOCK_FILE.exists():
        return []

    findings = []
    for package, version in _parse_lock_file(LOCK_FILE):
        try:
            vulns = _query_osv(package, version)
        except requests.RequestException:
            continue

        for vuln in vulns:
            findings.append(_finding(
                package=package,
                version=version,
                vuln_id=vuln.get("id", "UNKNOWN"),
                summary=vuln.get("summary", "No summary provided by OSV.dev"),
                severity=_map_severity(vuln),
            ))

    return findings
