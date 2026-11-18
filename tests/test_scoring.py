"""
tests/test_scoring.py

Unit tests for core/scoring.py — the weighted posture score engine.

Covers:
  - Perfect score (no findings)
  - Minimum score floor (clamped at 0)
  - Correct weight per severity (High=15, Medium=7, Low=3)
  - Accepted-risk exclusions
  - Per-category score breakdown
  - findings_by_severity counter
  - All four default Azure categories always present in by_category
"""

import pytest
from core.scoring import calculate_scores, SEVERITY_WEIGHTS, _score_from_findings


# ---------------------------------------------------------------------------
# Shared factory
# ---------------------------------------------------------------------------
def _finding(
    category: str = "Storage Account",
    resource: str = "st1",
    check: str = "public_blob_access",
    severity: str = "High",
) -> dict:
    return {
        "category": category,
        "resource": resource,
        "resource_group": "rg-test",
        "check": check,
        "issue": "test issue",
        "severity": severity,
        "compliance": "CIS Azure 3.7",
    }


# ---------------------------------------------------------------------------
# _score_from_findings (internal helper)
# ---------------------------------------------------------------------------
class TestScoreFromFindings:
    def test_no_findings_gives_100(self):
        assert _score_from_findings([]) == 100

    def test_single_high_deducts_15(self):
        assert _score_from_findings([_finding(severity="High")]) == 85

    def test_single_medium_deducts_7(self):
        assert _score_from_findings([_finding(severity="Medium")]) == 93

    def test_single_low_deducts_3(self):
        assert _score_from_findings([_finding(severity="Low")]) == 97

    def test_unknown_severity_deducts_5(self):
        """Unrecognised severity falls back to weight 5."""
        f = _finding(severity="Critical")  # not in SEVERITY_WEIGHTS
        assert _score_from_findings([f]) == 95

    def test_score_clamped_at_zero(self):
        """7 High findings = 7×15 = 105 deduction → clamped to 0."""
        findings = [_finding(severity="High") for _ in range(7)]
        assert _score_from_findings(findings) == 0

    def test_score_never_exceeds_100(self):
        """Verifies upper clamp — empty findings should not go above 100."""
        assert _score_from_findings([]) == 100

    def test_mixed_severities(self):
        # 1 High (15) + 2 Medium (14) + 1 Low (3) = 32 → score = 68
        findings = [
            _finding(severity="High"),
            _finding(severity="Medium"),
            _finding(severity="Medium"),
            _finding(severity="Low"),
        ]
        assert _score_from_findings(findings) == 68


# ---------------------------------------------------------------------------
# calculate_scores — main public function
# ---------------------------------------------------------------------------
class TestCalculateScores:
    def test_no_findings_perfect_score(self):
        result = calculate_scores([])
        assert result["overall"] == 100
        assert result["findings_by_severity"] == {"High": 0, "Medium": 0, "Low": 0}

    def test_overall_score_correct(self):
        # 2 High = 30 → 70
        findings = [_finding(severity="High"), _finding(severity="High", resource="st2")]
        result = calculate_scores(findings)
        assert result["overall"] == 70

    def test_all_five_categories_always_present(self):
        """Even with no findings the five Azure categories must appear in by_category."""
        result = calculate_scores([])
        for cat in ("Storage Account", "Network Security Group", "Key Vault", "Virtual Machine", "Azure SQL"):
            assert cat in result["by_category"]
            assert result["by_category"][cat] == 100

    def test_category_score_only_counts_its_own_findings(self):
        storage_finding = _finding(category="Storage Account", severity="High")
        nsg_finding = _finding(
            category="Network Security Group",
            resource="nsg1",
            check="open_management_port",
            severity="Medium",
        )
        result = calculate_scores([storage_finding, nsg_finding])
        assert result["by_category"]["Storage Account"] == 85    # 100 - 15
        assert result["by_category"]["Network Security Group"] == 93  # 100 - 7
        assert result["by_category"]["Key Vault"] == 100         # no findings

    def test_findings_by_severity_counts_correctly(self):
        findings = [
            _finding(severity="High"),
            _finding(severity="High", resource="st2"),
            _finding(severity="Medium", resource="st3"),
            _finding(severity="Low", resource="st4"),
        ]
        result = calculate_scores(findings)
        assert result["findings_by_severity"]["High"] == 2
        assert result["findings_by_severity"]["Medium"] == 1
        assert result["findings_by_severity"]["Low"] == 1

    def test_accepted_risk_excluded_from_score(self):
        """An accepted finding must not reduce the overall score."""
        f = _finding(category="Storage Account", resource="st1", check="public_blob_access")
        accepted_keys = {("Storage Account", "st1", "public_blob_access")}
        result = calculate_scores([f], accepted_keys=accepted_keys)
        assert result["overall"] == 100

    def test_accepted_risk_excluded_from_severity_count(self):
        f = _finding(severity="High")
        accepted_keys = {(f["category"], f["resource"], f["check"])}
        result = calculate_scores([f], accepted_keys=accepted_keys)
        assert result["findings_by_severity"]["High"] == 0

    def test_accepted_risk_partial_exclusion(self):
        """Only the accepted finding is excluded; others still count."""
        f1 = _finding(resource="st1", check="public_blob_access", severity="High")
        f2 = _finding(resource="st2", check="secure_transfer", severity="Medium")
        accepted_keys = {("Storage Account", "st1", "public_blob_access")}
        result = calculate_scores([f1, f2], accepted_keys=accepted_keys)
        # Only Medium (7) counts → 93
        assert result["overall"] == 93
        assert result["findings_by_severity"]["High"] == 0
        assert result["findings_by_severity"]["Medium"] == 1

    def test_accepted_keys_none_treated_as_empty_set(self):
        """Passing accepted_keys=None must behave identically to empty set."""
        f = _finding(severity="High")
        result_none = calculate_scores([f], accepted_keys=None)
        result_empty = calculate_scores([f], accepted_keys=set())
        assert result_none == result_empty

    def test_extra_category_from_findings_added_dynamically(self):
        """Any extra categories outside the default 5 should still appear."""
        custom_finding = _finding(
            category="Custom Category",
            resource="custom-res",
            check="custom_check",
            severity="High",
        )
        result = calculate_scores([custom_finding])
        assert "Custom Category" in result["by_category"]
        assert result["by_category"]["Custom Category"] == 85
