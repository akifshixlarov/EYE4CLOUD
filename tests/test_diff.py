"""
tests/test_diff.py

Unit tests for core/diff.py and ui/session_manager.py diff/history helpers.

Avoids file I/O entirely by testing:
  - _finding_key()
  - compute_scan_diff() (ui/session_manager.py — works on in-memory scan list)
  - compute_score_history()

The file-system-dependent compare_last_two_scans() and score_history()
from core/diff.py are tested via patching list_scan_files + load_scan.
"""

import pytest
from unittest.mock import patch, MagicMock

from core.diff import _finding_key, compare_last_two_scans, score_history
from ui.session_manager import compute_scan_diff, compute_score_history


# ---------------------------------------------------------------------------
# Shared factories
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


def _scan(findings: list[dict], scan_time: str = "2026-10-25T10:00:00+00:00") -> dict:
    return {
        "scan_time": scan_time,
        "subscription_ids": ["sub-1111"],
        "total_findings": len(findings),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# _finding_key
# ---------------------------------------------------------------------------
class TestFindingKey:
    def test_key_is_category_resource_check_tuple(self):
        f = _finding(category="Key Vault", resource="kv1", check="soft_delete")
        assert _finding_key(f) == ("Key Vault", "kv1", "soft_delete")

    def test_different_resources_produce_different_keys(self):
        f1 = _finding(resource="st1")
        f2 = _finding(resource="st2")
        assert _finding_key(f1) != _finding_key(f2)

    def test_different_checks_produce_different_keys(self):
        f1 = _finding(check="public_blob_access")
        f2 = _finding(check="secure_transfer")
        assert _finding_key(f1) != _finding_key(f2)

    def test_same_resource_same_check_same_key(self):
        f1 = _finding(resource="st1", check="public_blob_access", severity="High")
        f2 = _finding(resource="st1", check="public_blob_access", severity="Low")
        # Severity intentionally NOT part of the key — same finding across scans
        assert _finding_key(f1) == _finding_key(f2)


# ---------------------------------------------------------------------------
# compute_scan_diff (ui/session_manager.py)
# ---------------------------------------------------------------------------
class TestComputeScanDiff:
    def test_returns_none_with_fewer_than_two_scans(self):
        assert compute_scan_diff([]) is None
        assert compute_scan_diff([_scan([])]) is None

    def test_new_finding_detected(self):
        """A finding in latest but not in previous → new_findings."""
        previous = _scan([_finding(resource="st1")], scan_time="2026-10-24T10:00:00+00:00")
        new_f = _finding(resource="st2", check="secure_transfer", severity="Medium")
        latest = _scan([_finding(resource="st1"), new_f], scan_time="2026-10-25T10:00:00+00:00")

        diff = compute_scan_diff([previous, latest])
        assert diff is not None
        new_resources = [f["resource"] for f in diff["new_findings"]]
        assert "st2" in new_resources
        assert "st1" not in new_resources

    def test_resolved_finding_detected(self):
        """A finding in previous but not in latest → resolved_findings."""
        f1 = _finding(resource="st1")
        f2 = _finding(resource="st2", check="secure_transfer")
        previous = _scan([f1, f2], scan_time="2026-10-24T10:00:00+00:00")
        latest = _scan([f1], scan_time="2026-10-25T10:00:00+00:00")

        diff = compute_scan_diff([previous, latest])
        resolved_resources = [f["resource"] for f in diff["resolved_findings"]]
        assert "st2" in resolved_resources
        assert "st1" not in resolved_resources

    def test_no_change_produces_empty_new_and_resolved(self):
        f = _finding()
        scan1 = _scan([f], scan_time="2026-10-24T10:00:00+00:00")
        scan2 = _scan([f], scan_time="2026-10-25T10:00:00+00:00")

        diff = compute_scan_diff([scan1, scan2])
        assert diff["new_findings"] == []
        assert diff["resolved_findings"] == []

    def test_score_change_calculated_correctly(self):
        """
        previous: 1 High finding → score 85
        latest:   no findings → score 100
        score_change = +15
        """
        previous = _scan([_finding(severity="High")], scan_time="2026-10-24T10:00:00+00:00")
        latest = _scan([], scan_time="2026-10-25T10:00:00+00:00")

        diff = compute_scan_diff([previous, latest])
        assert diff["previous_score"] == 85
        assert diff["latest_score"] == 100
        assert diff["score_change"] == 15

    def test_score_worsens(self):
        """Score should go down when new findings are introduced."""
        previous = _scan([], scan_time="2026-10-24T10:00:00+00:00")
        latest = _scan([_finding(severity="High")], scan_time="2026-10-25T10:00:00+00:00")

        diff = compute_scan_diff([previous, latest])
        assert diff["score_change"] == -15

    def test_diff_uses_last_two_scans_only(self):
        """
        With 3 scans, diff must compare scan[1] vs scan[2],
        not scan[0] vs scan[2].
        """
        f_old = _finding(resource="old", check="public_blob_access")
        f_prev = _finding(resource="prev", check="secure_transfer", severity="Medium")
        f_latest = _finding(resource="latest", check="minimum_tls_version", severity="Medium")

        scan0 = _scan([f_old], scan_time="2026-10-23T10:00:00+00:00")
        scan1 = _scan([f_prev], scan_time="2026-10-24T10:00:00+00:00")
        scan2 = _scan([f_latest], scan_time="2026-10-25T10:00:00+00:00")

        diff = compute_scan_diff([scan0, scan1, scan2])
        new_resources = [f["resource"] for f in diff["new_findings"]]
        resolved_resources = [f["resource"] for f in diff["resolved_findings"]]

        # "latest" is new (appeared in scan2 but not scan1)
        assert "latest" in new_resources
        # "prev" was resolved (disappeared from scan2)
        assert "prev" in resolved_resources
        # "old" should not appear — it's only in scan0 which is not compared
        assert "old" not in new_resources
        assert "old" not in resolved_resources

    def test_timestamps_included_in_result(self):
        t1 = "2026-10-24T10:00:00+00:00"
        t2 = "2026-10-25T10:00:00+00:00"
        diff = compute_scan_diff([_scan([], scan_time=t1), _scan([], scan_time=t2)])
        assert diff["previous_time"] == t1
        assert diff["latest_time"] == t2


# ---------------------------------------------------------------------------
# compute_score_history (ui/session_manager.py)
# ---------------------------------------------------------------------------
class TestComputeScoreHistory:
    def test_empty_list_returns_empty(self):
        assert compute_score_history([]) == []

    def test_single_scan_history(self):
        scan = _scan([_finding(severity="High")])  # score = 85
        history = compute_score_history([scan])
        assert len(history) == 1
        assert history[0]["score"] == 85

    def test_history_ordered_by_input_order(self):
        """Score history preserves the insertion order of the input scan list."""
        s1 = _scan([_finding(severity="High")], scan_time="2026-10-24T10:00:00+00:00")   # 85
        s2 = _scan([], scan_time="2026-10-25T10:00:00+00:00")                             # 100
        history = compute_score_history([s1, s2])
        assert history[0]["score"] == 85
        assert history[1]["score"] == 100

    def test_history_contains_scan_time(self):
        t = "2026-10-25T10:00:00+00:00"
        history = compute_score_history([_scan([], scan_time=t)])
        assert history[0]["time"] == t


# ---------------------------------------------------------------------------
# core/diff.py file-system functions (patched)
# ---------------------------------------------------------------------------
class TestCoreDiffWithPatchedFs:
    def test_compare_last_two_scans_returns_none_with_one_file(self):
        with patch("core.diff.list_scan_files", return_value=["only-one.json"]), \
             patch("core.diff.compare_last_two_scans",
                   wraps=compare_last_two_scans):
            # list_scan_files returns 1 file → function returns None
            with patch("core.diff.list_scan_files", return_value=["f1.json"]):
                result = compare_last_two_scans()
            assert result is None

    def test_compare_last_two_scans_detects_new_finding(self):
        f_common = _finding(resource="st1")
        f_new = _finding(resource="st-new", check="secure_transfer")
        prev_scan = _scan([f_common], scan_time="2026-10-24T10:00:00+00:00")
        latest_scan = _scan([f_common, f_new], scan_time="2026-10-25T10:00:00+00:00")

        with patch("core.diff.list_scan_files", return_value=["prev.json", "latest.json"]), \
             patch("core.diff._load_scan", side_effect=[prev_scan, latest_scan]):
            result = compare_last_two_scans()

        assert result is not None
        new_resources = [f["resource"] for f in result["new_findings"]]
        assert "st-new" in new_resources

    def test_score_history_aggregates_all_scans(self):
        scans = [
            _scan([_finding(severity="High")], scan_time="2026-10-23T10:00:00+00:00"),  # 85
            _scan([], scan_time="2026-10-24T10:00:00+00:00"),                            # 100
        ]
        with patch("core.diff.list_scan_files", return_value=["s1.json", "s2.json"]), \
             patch("core.diff._load_scan", side_effect=scans):
            history = score_history()

        assert len(history) == 2
        assert history[0]["score"] == 85
        assert history[1]["score"] == 100
