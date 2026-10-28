"""
checks/dependency_checks.py

Looks up known CVEs/GHSAs in the project's own Python dependencies
(requirements.lock.txt) using the OSV.dev (Open Source Vulnerabilities) database.
This is the "CVE check of its own libraries" (SCA - Software Composition
Analysis) part; it looks at the project itself, not at Azure resources.

Why requirements.lock.txt: OSV queries need exact versions, but
requirements.txt uses `>=`. The user should run this first:
    pip freeze > requirements.lock.txt
If this file is missing, the check quietly returns an empty list - it does not raise.
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
        # CIS Microsoft Azure Foundations Benchmark focuses on cloud infrastructure
        # and does not cover CVEs in application dependencies (SCA) -
        # so there is no applicable CIS Azure ID here
        "compliance": "N/A (outside the scope of CIS Azure Foundations)",
    }


def _parse_lock_file(lock_path: Path) -> list[tuple[str, str]]:
    """Turns `package==version` lines into (package, version) pairs."""
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
    OSV entries can report severity in different formats (a CVSS vector
    string or database_specific.severity). For simplicity only
    database_specific.severity is read; if that is missing too, we play it safe
    and assign Medium (treating an unknown severity as Low is risky).
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
    If requirements.lock.txt is missing (`pip freeze > requirements.lock.txt`
    has not been run yet), returns an empty list. If there is a network error
    talking to OSV.dev for some package, only that package is skipped - the whole scan does not stop.
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
