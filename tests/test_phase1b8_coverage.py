"""
Phase 1B8 — Assessment Coverage Calculation Tests

Validates that the coverage formula produces truthful percentages
from module_execution metadata, fails closed on invalid data,
and does not alter score/findings.
"""
import unittest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.scanner.scoring import _calculate_assessment_coverage


def _make_module(state="RETURNED", outcome=None, progress=None):
    """Helper to create a module_execution entry."""
    entry = {"state": state}
    if outcome is not None:
        entry["assessment_outcome"] = outcome
    if progress is not None:
        entry["assessment_progress"] = progress
    return entry


class TestAssessmentCoverage(unittest.TestCase):

    # --- Happy Path ---

    def test_all_completed_100(self):
        """All modules COMPLETED -> 100%."""
        me = {
            "ModA": _make_module(outcome="COMPLETED"),
            "ModB": _make_module(outcome="COMPLETED"),
            "ModC": _make_module(outcome="COMPLETED"),
        }
        result = _calculate_assessment_coverage(me)
        self.assertTrue(result["available"])
        self.assertAlmostEqual(result["percentage"], 100.0)
        self.assertEqual(result["completed_modules"], 3)
        self.assertEqual(result["applicable_modules"], 3)

    def test_one_failed_lowers_coverage(self):
        """One FAILED assessment among 3 modules -> 66.67%."""
        me = {
            "ModA": _make_module(outcome="COMPLETED"),
            "ModB": _make_module(outcome="COMPLETED"),
            "ModC": _make_module(outcome="FAILED"),
        }
        result = _calculate_assessment_coverage(me)
        self.assertTrue(result["available"])
        self.assertAlmostEqual(result["percentage"], 200.0 / 3, places=2)
        self.assertEqual(result["failed_modules"], 1)

    def test_partial_uses_completed_over_attempted(self):
        """PARTIAL with 2/4 completed -> contribution of 0.5."""
        me = {
            "ModA": _make_module(outcome="COMPLETED"),
            "ModB": _make_module(outcome="PARTIAL", progress={"attempted": 4, "completed": 2, "failed": 2}),
        }
        result = _calculate_assessment_coverage(me)
        self.assertTrue(result["available"])
        # (1.0 + 0.5) / 2 * 100 = 75.0
        self.assertAlmostEqual(result["percentage"], 75.0)
        self.assertEqual(result["partial_modules"], 1)

    def test_equal_module_weighting(self):
        """Each module has equal weight regardless of internal check count."""
        me = {
            "ModA": _make_module(outcome="COMPLETED"),
            "ModB": _make_module(outcome="PARTIAL", progress={"attempted": 100, "completed": 1, "failed": 99}),
        }
        result = _calculate_assessment_coverage(me)
        self.assertTrue(result["available"])
        # (1.0 + 1/100) / 2 * 100 = 50.5
        self.assertAlmostEqual(result["percentage"], 50.5)

    def test_na_excluded_from_denominator(self):
        """NOT_APPLICABLE modules don't count in denominator."""
        me = {
            "ModA": _make_module(outcome="COMPLETED"),
            "ModB": _make_module(outcome="NOT_APPLICABLE"),
        }
        result = _calculate_assessment_coverage(me)
        self.assertTrue(result["available"])
        self.assertAlmostEqual(result["percentage"], 100.0)
        self.assertEqual(result["applicable_modules"], 1)
        self.assertEqual(result["not_applicable_modules"], 1)

    def test_blocked_counts_incomplete(self):
        """BLOCKED contributes 0.0."""
        me = {
            "ModA": _make_module(outcome="COMPLETED"),
            "ModB": _make_module(outcome="BLOCKED"),
        }
        result = _calculate_assessment_coverage(me)
        self.assertTrue(result["available"])
        self.assertAlmostEqual(result["percentage"], 50.0)
        self.assertEqual(result["blocked_modules"], 1)

    def test_execution_failed_counts_incomplete(self):
        """Execution FAILED contributes 0.0."""
        me = {
            "ModA": _make_module(outcome="COMPLETED"),
            "ModB": _make_module(state="FAILED"),
        }
        result = _calculate_assessment_coverage(me)
        self.assertTrue(result["available"])
        self.assertAlmostEqual(result["percentage"], 50.0)
        self.assertEqual(result["execution_incomplete_modules"], 1)

    def test_timed_out_counts_incomplete(self):
        """Execution TIMED_OUT contributes 0.0."""
        me = {
            "ModA": _make_module(outcome="COMPLETED"),
            "ModB": _make_module(state="TIMED_OUT"),
        }
        result = _calculate_assessment_coverage(me)
        self.assertTrue(result["available"])
        self.assertAlmostEqual(result["percentage"], 50.0)

    def test_not_completed_counts_incomplete(self):
        """Execution NOT_COMPLETED contributes 0.0."""
        me = {
            "ModA": _make_module(outcome="COMPLETED"),
            "ModB": _make_module(state="NOT_COMPLETED"),
        }
        result = _calculate_assessment_coverage(me)
        self.assertTrue(result["available"])
        self.assertAlmostEqual(result["percentage"], 50.0)

    # --- Fail-Closed ---

    def test_invalid_partial_no_progress(self):
        """PARTIAL without progress -> unavailable."""
        me = {
            "ModA": _make_module(outcome="COMPLETED"),
            "ModB": _make_module(outcome="PARTIAL"),
        }
        result = _calculate_assessment_coverage(me)
        self.assertFalse(result["available"])
        self.assertIsNone(result["percentage"])
        self.assertIn("progress", result["reason"])

    def test_invalid_partial_zero_attempted(self):
        """PARTIAL with attempted=0 -> unavailable."""
        me = {
            "ModA": _make_module(outcome="PARTIAL", progress={"attempted": 0, "completed": 0, "failed": 0}),
        }
        result = _calculate_assessment_coverage(me)
        self.assertFalse(result["available"])
        self.assertIsNone(result["percentage"])

    def test_invalid_partial_overflow(self):
        """PARTIAL with completed+failed > attempted -> unavailable."""
        me = {
            "ModA": _make_module(outcome="PARTIAL", progress={"attempted": 3, "completed": 2, "failed": 2}),
        }
        result = _calculate_assessment_coverage(me)
        self.assertFalse(result["available"])

    def test_unknown_outcome(self):
        """Unknown outcome string -> unavailable."""
        me = {
            "ModA": _make_module(outcome="COMPLETED"),
            "ModB": _make_module(outcome="SOMETHING_NEW"),
        }
        result = _calculate_assessment_coverage(me)
        self.assertFalse(result["available"])
        self.assertIsNone(result["percentage"])
        self.assertIn("unknown outcome", result["reason"])

    def test_returned_no_outcome(self):
        """RETURNED without outcome -> unavailable."""
        me = {
            "ModA": _make_module(outcome="COMPLETED"),
            "ModB": _make_module(state="RETURNED"),
        }
        result = _calculate_assessment_coverage(me)
        self.assertFalse(result["available"])
        self.assertIsNone(result["percentage"])

    def test_old_scan_no_metadata(self):
        """None module_execution -> unavailable."""
        result = _calculate_assessment_coverage(None)
        self.assertFalse(result["available"])
        self.assertIsNone(result["percentage"])

    def test_empty_dict_metadata(self):
        """Empty dict -> no applicable modules."""
        result = _calculate_assessment_coverage({})
        self.assertFalse(result["available"])
        self.assertIsNone(result["percentage"])

    # --- Edge Cases ---

    def test_no_division_by_zero(self):
        """All N/A -> no applicable -> unavailable, not crash."""
        me = {
            "ModA": _make_module(outcome="NOT_APPLICABLE"),
            "ModB": _make_module(outcome="NOT_APPLICABLE"),
        }
        result = _calculate_assessment_coverage(me)
        self.assertFalse(result["available"])
        self.assertIsNone(result["percentage"])

    def test_json_safe_output(self):
        """Output must be JSON-safe (no NaN, no Inf)."""
        import json
        me = {
            "ModA": _make_module(outcome="COMPLETED"),
            "ModB": _make_module(outcome="PARTIAL", progress={"attempted": 3, "completed": 1, "failed": 2}),
        }
        result = _calculate_assessment_coverage(me)
        serialized = json.dumps(result)
        self.assertNotIn("NaN", serialized)
        self.assertNotIn("Infinity", serialized)

    def test_non_integer_progress_values(self):
        """Float progress values -> unavailable."""
        me = {
            "ModA": _make_module(outcome="PARTIAL", progress={"attempted": 3.5, "completed": 1, "failed": 2}),
        }
        result = _calculate_assessment_coverage(me)
        self.assertFalse(result["available"])

    def test_single_completed_module(self):
        """Single COMPLETED module -> 100%."""
        me = {"ModA": _make_module(outcome="COMPLETED")}
        result = _calculate_assessment_coverage(me)
        self.assertTrue(result["available"])
        self.assertAlmostEqual(result["percentage"], 100.0)

    def test_mixed_comprehensive(self):
        """Mix of all states verifies full formula."""
        me = {
            "Mod1": _make_module(outcome="COMPLETED"),
            "Mod2": _make_module(outcome="COMPLETED"),
            "Mod3": _make_module(outcome="PARTIAL", progress={"attempted": 4, "completed": 3, "failed": 1}),
            "Mod4": _make_module(outcome="FAILED"),
            "Mod5": _make_module(outcome="BLOCKED"),
            "Mod6": _make_module(state="TIMED_OUT"),
            "Mod7": _make_module(outcome="NOT_APPLICABLE"),
        }
        result = _calculate_assessment_coverage(me)
        self.assertTrue(result["available"])
        # applicable = 6 (all except N/A)
        # contributions: 1.0 + 1.0 + 0.75 + 0 + 0 + 0 = 2.75
        # coverage = 100 * 2.75 / 6 = 45.833...
        self.assertEqual(result["applicable_modules"], 6)
        self.assertAlmostEqual(result["percentage"], 100.0 * 2.75 / 6, places=4)
        self.assertEqual(result["completed_modules"], 2)
        self.assertEqual(result["partial_modules"], 1)
        self.assertEqual(result["failed_modules"], 1)
        self.assertEqual(result["blocked_modules"], 1)
        self.assertEqual(result["execution_incomplete_modules"], 1)
        self.assertEqual(result["not_applicable_modules"], 1)


class TestCoverageInScanResult(unittest.TestCase):
    """Verify coverage is embedded in calculate_score output correctly."""

    def test_coverage_in_result(self):
        """calculate_score includes assessment_coverage key."""
        from api.scanner.scoring import calculate_score
        module_exec = {
            "Mod1": {"state": "RETURNED", "assessment_outcome": "COMPLETED"},
        }
        result = calculate_score(
            "https://example.com", [], {}, None,
            module_execution=module_exec
        )
        self.assertIn("assessment_coverage", result)
        self.assertTrue(result["assessment_coverage"]["available"])
        self.assertAlmostEqual(result["assessment_coverage"]["percentage"], 100.0)

    def test_coverage_without_module_execution(self):
        """No module_execution -> coverage unavailable."""
        from api.scanner.scoring import calculate_score
        result = calculate_score(
            "https://example.com", [], {}, None
        )
        self.assertIn("assessment_coverage", result)
        self.assertFalse(result["assessment_coverage"]["available"])

    def test_score_unchanged_by_coverage(self):
        """Coverage does not affect score calculation."""
        from api.scanner.scoring import calculate_score
        result_without = calculate_score(
            "https://example.com", [], {}, None
        )
        module_exec = {
            "Mod1": {"state": "RETURNED", "assessment_outcome": "FAILED"},
        }
        result_with = calculate_score(
            "https://example.com", [], {}, None,
            module_execution=module_exec
        )
        self.assertEqual(result_without["score"], result_with["score"])

    def test_findings_unchanged_by_coverage(self):
        """Coverage does not alter findings list."""
        from api.scanner.scoring import calculate_score
        findings = [{"name": "Test", "severity": "High", "category": "test", "description": "d", "evidence": "e", "confidence": "High", "remediation": "r", "remediation_snippets": {}, "owasp": "A01", "compliance": {"pci_dss": "N/A", "nist": "N/A", "iso27001": "N/A"}}]
        module_exec = {
            "Mod1": {"state": "RETURNED", "assessment_outcome": "COMPLETED"},
        }
        result = calculate_score(
            "https://example.com", findings, {}, None,
            module_execution=module_exec
        )
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["name"], "Test")


if __name__ == "__main__":
    unittest.main()
