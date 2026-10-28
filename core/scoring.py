"""
core/scoring.py

Takes a list of findings and computes a 0-100 "posture score".
Returns both an overall score and a separate score per category
(Storage / NSG / Key Vault) - so Streamlit can show a breakdown like
"Storage: 85/100, NSG: 40/100".

The methodology is kept simple (weighted deduction) - the goal is not to build an
academically "correct" risk model, but to give an understandable, explainable
number for prioritising findings.
"""

SEVERITY_WEIGHTS = {
    "High": 15,
    "Medium": 7,
    "Low": 3,
}


def _score_from_findings(findings: list[dict]) -> int:
    """Computes a score for the given findings list, starting at 100 and deducting."""
    score = 100
    for finding in findings:
        weight = SEVERITY_WEIGHTS.get(finding.get("severity"), 5)
        score -= weight
    return max(0, min(100, score))


def calculate_scores(findings: list[dict], accepted_keys: set | None = None) -> dict:
    """
    Returns the overall and per-category scores:

    {
        "overall": 62,
        "by_category": {
            "Storage Account": 85,
            "Network Security Group": 40,
            "Key Vault": 70
        },
        "findings_by_severity": {"High": 3, "Medium": 2, "Low": 0}
    }

    `accepted_keys` given ("Accepted Risk" mechanism - see
    core/exceptions.py): findings whose (category, resource, check) key is in this set
    are excluded from the score calculation (and severity counts) -
    they still remain in the findings list itself, they just don't affect
    the score.
    """
    accepted_keys = accepted_keys or set()
    active_findings = [
        f for f in findings
        if (f["category"], f["resource"], f["check"]) not in accepted_keys
    ]

    overall = _score_from_findings(active_findings)

    categories = {f["category"] for f in active_findings}
    # Even if findings are empty, show the standard Azure categories at 100
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
