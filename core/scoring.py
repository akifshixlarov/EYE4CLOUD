"""
core/scoring.py

Tapintilar siyahisini alib 0-100 araliginda "posture score" hesablayir.
Hem umumi score, hem de kateqoriya uzre (Storage / NSG / Key Vault) ayri
score qaytarir - beleliklə Streamlit-de "Storage: 85/100, NSG: 40/100"
kimi parcalanmis gorunus vermek mumkun olur.

Metodologiya sade tutulub (weighted deduction) - meqsed akademik cehetden
"dogru" bir risk modeli qurmaq deyil, tapintilari prioritetlesdirmek ucun
anlasilan ve izah oluna bilen bir reqem vermekdir.
"""

SEVERITY_WEIGHTS = {
    "High": 15,
    "Medium": 7,
    "Low": 3,
}


def _score_from_findings(findings: list[dict]) -> int:
    """Verilen tapinti siyahisi ucun 100-den basliyib cixan score hesablayir."""
    score = 100
    for finding in findings:
        weight = SEVERITY_WEIGHTS.get(finding.get("severity"), 5)
        score -= weight
    return max(0, min(100, score))


def calculate_scores(findings: list[dict], accepted_keys: set | None = None) -> dict:
    """
    Umumi ve kateqoriya uzre score-lari qaytarir:

    {
        "overall": 62,
        "by_category": {
            "Storage Account": 85,
            "Network Security Group": 40,
            "Key Vault": 70
        },
        "findings_by_severity": {"High": 3, "Medium": 2, "Low": 0}
    }

    `accepted_keys` verilibse ("Accepted Risk" mexanizmi - bax:
    core/exceptions.py), (category, resource, check) acari bu setde olan
    tapintilar score hesablamasindan (ve severity sayindan) cixarilir -
    findings siyahisinin ozunde onlar hele de qalir, sadece score-a tesir
    etmirler.
    """
    accepted_keys = accepted_keys or set()
    active_findings = [
        f for f in findings
        if (f["category"], f["resource"], f["check"]) not in accepted_keys
    ]

    overall = _score_from_findings(active_findings)

    categories = {f["category"] for f in active_findings}
    # Findings bos olsa bele, standart Azure kateqoriyalarini 100 ile
    # gostermek ucun (Dependency burada yoxdur - o, opsional check-dir ve
    # requirements.lock.txt olmayanda umumiyyetle islemir)
    all_categories = {
        "Storage Account",
        "Network Security Group",
        "Key Vault",
        "Virtual Machine",
    } | categories

    by_category = {}
    for category in all_categories:
        category_findings = [f for f in active_findings if f["category"] == category]
        by_category[category] = _score_from_findings(category_findings)

    findings_by_severity = {"High": 0, "Medium": 0, "Low": 0}
    for finding in active_findings:
        sev = finding.get("severity", "Low")
        findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1

    return {
        "overall": overall,
        "by_category": by_category,
        "findings_by_severity": findings_by_severity,
    }
