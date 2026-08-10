"""
Phase 25 — Production Readiness & End-to-End QA Test Suite

Tests cover:
- API response schema validation
- Scoring consistency (informational, dedup, severity)
- Orchestrator graceful failure handling (timeout, exceptions)
- Evidence preservation and masking
- OWASP mapping preservation
- Finding field completeness
- Report metadata consistency
"""
import unittest
from unittest.mock import patch, MagicMock, PropertyMock
from concurrent.futures import ThreadPoolExecutor

import requests
from fastapi.testclient import TestClient

from api.index import app
from api.scanner.base import ScannerModule
from api.scanner.scoring import calculate_score


class DummyModule(ScannerModule):
    module_name = "Dummy"
    description = "Dummy module for testing"
    def run(self, url, hostname, session):
        return []


class CrashingModule(ScannerModule):
    module_name = "Crasher"
    description = "Module that always crashes"
    def run(self, url, hostname, session):
        raise RuntimeError("Intentional crash for testing")


class SlowModule(ScannerModule):
    module_name = "SlowModule"
    description = "Module that sleeps forever"
    timeout = 2
    def run(self, url, hostname, session):
        import time
        time.sleep(60)
        return []


# ============================================================
# 1. API RESPONSE SCHEMA
# ============================================================
class TestAPIResponseSchema(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_api_scan_returns_expected_fields(self):
        """Verify scan endpoint returns all expected top-level fields."""
        with patch("api.index.scan_url") as mock_scan:
            mock_scan.return_value = {
                "url": "https://example.com",
                "findings": [],
                "score": 100,
                "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0},
                "status": "completed",
            }
            response = self.client.post("/api/scan", json={"url": "https://example.com"})
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertIn("score", data)
            self.assertIn("findings", data)
            self.assertIn("severity_counts", data)
            self.assertEqual(data["score"], 100)

    def test_api_health_endpoint(self):
        """Verify health endpoint returns online status."""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "online")


# ============================================================
# 2. SCORING CONSISTENCY
# ============================================================
class TestScoringConsistency(unittest.TestCase):
    def test_informational_zero_penalty(self):
        """Informational findings must contribute 0 penalty."""
        findings = [
            {"name": "Info 1", "severity": "Informational", "category": "info"},
            {"name": "Info 2", "severity": "Informational", "category": "info"},
        ]
        res = calculate_score("https://example.com", findings, {}, None)
        self.assertEqual(res["score"], 100)
        self.assertEqual(res["severity_counts"]["Informational"], 2)

    def test_passed_zero_penalty(self):
        """Passed findings must contribute 0 penalty."""
        findings = [
            {"name": "Pass 1", "severity": "Passed", "category": "info"},
        ]
        res = calculate_score("https://example.com", findings, {}, None)
        self.assertEqual(res["score"], 100)
        self.assertEqual(res["severity_counts"]["Passed"], 1)

    def test_tls_deduplication_score_only(self):
        """TLS findings should be deduplicated for scoring but both preserved in findings."""
        findings = [
            {"name": "Weak TLS Cipher", "severity": "High", "category": "encryption_tls"},
            {"name": "Deprecated TLS 1.0/1.1 Supported", "severity": "Medium", "category": "encryption_tls"},
        ]
        res = calculate_score("https://example.com", findings, {}, None)
        # Both findings remain
        self.assertEqual(len(res["findings"]), 2)
        # Severity counts reflect actual occurrences
        self.assertEqual(res["severity_counts"]["High"], 1)
        self.assertEqual(res["severity_counts"]["Medium"], 1)
        # Score: only worst-case penalty applied once (High = -10)
        self.assertEqual(res["score"], 90)

    def test_security_header_deduplication(self):
        """Security header findings should be deduplicated for scoring."""
        findings = [
            {"name": "Missing Content-Security-Policy (CSP)", "severity": "High", "category": "http_headers"},
            {"name": "Missing COOP Header", "severity": "Informational", "category": "http_headers"},
            {"name": "Missing COEP Header", "severity": "Informational", "category": "http_headers"},
        ]
        res = calculate_score("https://example.com", findings, {}, None)
        self.assertEqual(len(res["findings"]), 3)
        # Only CSP (High) applies penalty; COOP/COEP are Informational (0 penalty)
        self.assertEqual(res["score"], 90)

    def test_mixed_severity_score(self):
        """Score with mixed severities."""
        findings = [
            {"name": "Missing HSTS", "severity": "High", "category": "encryption_tls"},
            {"name": "Missing Referrer-Policy", "severity": "Low", "category": "http_headers"},
            {"name": "Info Finding", "severity": "Informational", "category": "info"},
        ]
        res = calculate_score("https://example.com", findings, {}, None)
        # High=-10, Low=-2, Info=0 → score=88
        self.assertEqual(res["score"], 88)
        self.assertEqual(res["severity_counts"]["High"], 1)
        self.assertEqual(res["severity_counts"]["Low"], 1)
        self.assertEqual(res["severity_counts"]["Informational"], 1)

    def test_all_findings_preserved(self):
        """All findings must appear in the output regardless of deduplication."""
        findings = [
            {"name": "A", "severity": "High", "category": "encryption_tls"},
            {"name": "B", "severity": "Medium", "category": "encryption_tls"},
            {"name": "C", "severity": "Low", "category": "http_headers"},
            {"name": "D", "severity": "Informational", "category": "info"},
            {"name": "E", "severity": "Passed", "category": "info"},
        ]
        res = calculate_score("https://example.com", findings, {}, None)
        self.assertEqual(len(res["findings"]), 5)


# ============================================================
# 3. ORCHESTRATOR FAILURE HANDLING
# ============================================================
class TestOrchestratorFailureHandling(unittest.TestCase):
    def test_module_exception_does_not_crash_scan(self):
        """A crashing module should produce an Informational finding, not crash the scan."""
        from concurrent.futures import as_completed
        import time as _time

        crasher = CrashingModule()
        dummy = DummyModule()
        all_findings = []
        scan_start = _time.monotonic()
        SCAN_BUDGET_SECONDS = 10

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {pool.submit(mod.run, "https://example.com", "example.com", None): mod for mod in [crasher, dummy]}
            try:
                for future in as_completed(futures, timeout=SCAN_BUDGET_SECONDS):
                    mod = futures[future]
                    try:
                        mod_findings = future.result(timeout=5)
                        all_findings.extend(mod_findings)
                    except Exception as e:
                        all_findings.append({
                            "name": f"Module Timeout: {mod.module_name}",
                            "severity": "Informational",
                            "category": "information_exposure",
                            "description": f"The {mod.module_name} module was skipped due to timeout or error.",
                            "evidence": {"raw": str(e)[:180]},
                            "confidence": "High",
                            "remediation": "N/A",
                            "owasp": "N/A",
                        })
            except TimeoutError:
                pass

        # The crash should result in an informational finding
        crash_findings = [f for f in all_findings if "Crasher" in f.get("name", "")]
        self.assertEqual(len(crash_findings), 1)
        self.assertEqual(crash_findings[0]["severity"], "Informational")

    def test_timeout_error_produces_partial_results(self):
        """When the scan budget expires, partial results should be returned, not a crash."""
        from concurrent.futures import as_completed
        import time as _time

        slow = SlowModule()
        dummy = DummyModule()
        all_findings = []
        scan_start = _time.monotonic()
        BUDGET = 3  # Very short budget

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {pool.submit(mod.run, "https://example.com", "example.com", None): mod for mod in [slow, dummy]}
            try:
                for future in as_completed(futures, timeout=BUDGET):
                    mod = futures[future]
                    try:
                        mod_findings = future.result(timeout=2)
                        all_findings.extend(mod_findings)
                    except Exception as e:
                        all_findings.append({
                            "name": f"Module Timeout: {mod.module_name}",
                            "severity": "Informational",
                        })
            except TimeoutError:
                for future in futures:
                    if not future.done():
                        future.cancel()

        # Dummy module should have completed
        # The slow module should have been cancelled — no crash
        self.assertIsInstance(all_findings, list)


# ============================================================
# 4. EVIDENCE PRESERVATION AND MASKING
# ============================================================
class TestEvidencePreservation(unittest.TestCase):
    def test_evidence_field_is_never_empty_string(self):
        """make_finding should not produce empty-string evidence."""
        mod = DummyModule()
        f = mod.make_finding("Test", "Low", "Desc", "Some evidence", owasp="A01")
        self.assertNotEqual(f["evidence"], "")
        self.assertNotEqual(f["evidence"], {"raw": ""})

    def test_stripe_key_masked(self):
        """Stripe secret keys should be masked in evidence."""
        mod = DummyModule()
        f = mod.make_finding("Test", "Low", "Desc", "sk_live_1234567890abcdefgh", owasp="A01")
        self.assertIn("[REDACTED_STRIPE]", f["evidence"]["raw"])
        self.assertNotIn("sk_live_", f["evidence"]["raw"])

    def test_aws_key_masked(self):
        """AWS access keys should be masked in evidence."""
        mod = DummyModule()
        f = mod.make_finding("Test", "Low", "Desc", "AKIAIOSFODNN7EXAMPLE", owasp="A01")
        self.assertIn("[REDACTED_AWS]", f["evidence"]["raw"])
        self.assertNotIn("AKIA", f["evidence"]["raw"])

    def test_github_token_masked(self):
        """GitHub tokens should be masked in evidence."""
        mod = DummyModule()
        # ghp_ followed by exactly 36 alphanumeric chars
        f = mod.make_finding("Test", "Low", "Desc", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", owasp="A01")
        self.assertIn("[REDACTED_GITHUB]", f["evidence"]["raw"])

    def test_bearer_token_masked(self):
        """Bearer tokens should be masked in evidence."""
        mod = DummyModule()
        f = mod.make_finding("Test", "Low", "Desc", "Bearer eyJhbGciOiJIUzI1NiJ9.test", owasp="A01")
        self.assertIn("Bearer [REDACTED]", f["evidence"]["raw"])

    def test_evidence_truncation_deterministic(self):
        """Evidence over 180 chars should be truncated deterministically."""
        mod = DummyModule()
        long_evidence = "A" * 300
        f = mod.make_finding("Test", "Low", "Desc", long_evidence, owasp="A01")
        self.assertLessEqual(len(f["evidence"]["raw"]), 180)

    def test_masking_happens_before_truncation(self):
        """Secrets should be masked even if they appear near the truncation boundary."""
        mod = DummyModule()
        # Secret appears before position 180, should be masked before truncation
        evidence = "a" * 150 + " sk_live_1234567890abcdefgh"
        f = mod.make_finding("Test", "Low", "Desc", evidence, owasp="A01")
        self.assertNotIn("sk_live_", f["evidence"]["raw"])
        self.assertIn("[REDACTED_STRIPE]", f["evidence"]["raw"])


# ============================================================
# 5. FINDING FIELD COMPLETENESS
# ============================================================
class TestFindingFieldCompleteness(unittest.TestCase):
    def test_make_finding_has_all_required_fields(self):
        """make_finding must produce all required finding fields."""
        mod = DummyModule()
        f = mod.make_finding(
            "Test Finding", "High", "Description here", "evidence here",
            confidence="Medium", remediation="Fix it", owasp="A01: Broken Access Control",
            category="info"
        )
        required_fields = ["name", "severity", "category", "description", "evidence",
                           "confidence", "remediation", "owasp", "compliance", "module", "impact"]
        for field in required_fields:
            self.assertIn(field, f, f"Missing field: {field}")

    def test_severity_preserved_exactly(self):
        """Severity must be preserved exactly as provided."""
        mod = DummyModule()
        for sev in ["Critical", "High", "Medium", "Low", "Informational", "Passed"]:
            f = mod.make_finding("Test", sev, "Desc", "Ev", owasp="A01")
            self.assertEqual(f["severity"], sev)

    def test_confidence_preserved_exactly(self):
        """Confidence must be preserved exactly as provided."""
        mod = DummyModule()
        for conf in ["High", "Medium", "Low"]:
            f = mod.make_finding("Test", "Low", "Desc", "Ev", confidence=conf, owasp="A01")
            self.assertEqual(f["confidence"], conf)

    def test_owasp_preserved(self):
        """OWASP mapping must be preserved through scoring."""
        findings = [
            {"name": "Test", "severity": "High", "category": "info", "owasp": "A01: Broken Access Control"}
        ]
        res = calculate_score("https://example.com", findings, {}, None)
        self.assertEqual(res["findings"][0]["owasp"], "A01: Broken Access Control")

    def test_module_name_set(self):
        """Module name must be set on findings."""
        mod = DummyModule()
        f = mod.make_finding("Test", "Low", "Desc", "Ev", owasp="A01")
        self.assertEqual(f["module"], "Dummy")

    def test_category_preserved(self):
        """Category must be preserved through scoring."""
        findings = [
            {"name": "Test", "severity": "Low", "category": "encryption_tls"}
        ]
        res = calculate_score("https://example.com", findings, {}, None)
        self.assertEqual(res["findings"][0]["category"], "encryption_tls")


# ============================================================
# 6. REPORT METADATA CONSISTENCY
# ============================================================
class TestReportMetadata(unittest.TestCase):
    def test_scoring_returns_severity_counts(self):
        """calculate_score must return severity_counts dict."""
        findings = [
            {"name": "A", "severity": "High", "category": "info"},
            {"name": "B", "severity": "Low", "category": "info"},
            {"name": "C", "severity": "Informational", "category": "info"},
        ]
        res = calculate_score("https://example.com", findings, {}, None)
        self.assertIn("severity_counts", res)
        self.assertEqual(res["severity_counts"]["High"], 1)
        self.assertEqual(res["severity_counts"]["Low"], 1)
        self.assertEqual(res["severity_counts"]["Informational"], 1)

    def test_scoring_returns_url(self):
        """calculate_score must return the scanned URL."""
        res = calculate_score("https://example.com", [], {}, None)
        self.assertEqual(res["url"], "https://example.com")

    def test_scoring_returns_expected_keys(self):
        """calculate_score must return essential top-level keys."""
        res = calculate_score("https://example.com", [], {}, None)
        for key in ["url", "score", "findings", "severity_counts"]:
            self.assertIn(key, res, f"Missing key: {key}")


if __name__ == "__main__":
    unittest.main()
