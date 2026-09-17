"""
Phase 1C - Exposure Model Tests
Validates the deterministic exposure calculation logic.
"""
import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.scanner.scoring import _calculate_exposure

class TestPhase1CExposure(unittest.TestCase):

    def test_private_local_only_low(self):
        metadata = {"ip_address": "192.168.1.10", "http_status": "200 OK"}
        findings = []
        result = _calculate_exposure(metadata, findings)
        self.assertEqual(result["level"], "LOW")
        self.assertIn("private/local", result["signals"][0])

    def test_public_ip_reachable_web_moderate(self):
        metadata = {"ip_address": "93.184.216.34", "http_status": "200 OK", "performance_rating": "Optimal Latency"}
        findings = []
        result = _calculate_exposure(metadata, findings)
        self.assertEqual(result["level"], "MODERATE")

    def test_public_ip_exposed_network_service_high(self):
        metadata = {"ip_address": "93.184.216.34", "http_status": "200 OK", "performance_rating": "Optimal Latency"}
        findings = [{"rule_id": "network_port_exposed", "name": "Exposed SSH Port"}]
        result = _calculate_exposure(metadata, findings)
        self.assertEqual(result["level"], "HIGH")

    def test_public_ip_privileged_admin_surface_high(self):
        metadata = {"ip_address": "93.184.216.34", "http_status": "200 OK", "performance_rating": "Optimal Latency"}
        findings = [{"rule_id": "exposed_admin_interface", "name": "Exposed Admin Panel"}]
        result = _calculate_exposure(metadata, findings)
        self.assertEqual(result["level"], "HIGH")

    def test_public_ip_graphql_ide_high(self):
        metadata = {"ip_address": "93.184.216.34", "http_status": "200 OK", "performance_rating": "Optimal Latency"}
        findings = [{"rule_id": "api_graphql_ide_exposed", "name": "GraphQL IDE"}]
        result = _calculate_exposure(metadata, findings)
        self.assertEqual(result["level"], "HIGH")

    def test_public_ip_ordinary_api_moderate(self):
        metadata = {"ip_address": "93.184.216.34", "http_status": "200 OK", "performance_rating": "Optimal Latency"}
        findings = [{"rule_id": "api_openapi_exposed", "name": "OpenAPI Documentation"}]
        result = _calculate_exposure(metadata, findings)
        self.assertEqual(result["level"], "MODERATE")

    def test_failed_dns_ip_metadata_unknown(self):
        metadata = {"ip_address": "Unknown IP"}
        findings = []
        result = _calculate_exposure(metadata, findings)
        self.assertEqual(result["level"], "UNKNOWN")

    def test_failed_reachability_without_private_proof_unknown(self):
        metadata = {"ip_address": "93.184.216.34", "http_status": "Connection Timeout", "performance_rating": "REQUEST TIMEOUT"}
        findings = []
        result = _calculate_exposure(metadata, findings)
        self.assertEqual(result["level"], "UNKNOWN")
        self.assertIn("Exposure level cannot be determined", result["limitations"][-1])

    def test_auth_login_observation_does_not_lower_level(self):
        metadata = {"ip_address": "93.184.216.34", "http_status": "401 Unauthorized"}
        findings = [{"rule_id": "api_graphql_ide_exposed", "name": "GraphQL IDE"}, {"name": "Authentication Required"}]
        result = _calculate_exposure(metadata, findings)
        self.assertEqual(result["level"], "HIGH")

        limitation_text = " ".join(result["limitations"])
        self.assertTrue("Authentication" in limitation_text or "401" in limitation_text)

    def test_waf_cdn_geolocation_do_not_affect_level(self):
        metadata = {"ip_address": "93.184.216.34", "http_status": "403 Forbidden", "waf_cdn_detection": "Cloudflare WAF / CDN"}
        findings = [{"rule_id": "api_graphql_ide_exposed", "name": "GraphQL IDE"}]
        result = _calculate_exposure(metadata, findings)
        self.assertEqual(result["level"], "HIGH")
        limitation_text = " ".join(result["limitations"])
        self.assertTrue("403 Forbidden observed" in limitation_text)

    def test_finding_severity_count_do_not_affect_level(self):
        metadata = {"ip_address": "93.184.216.34", "http_status": "200 OK"}
        # 100 criticals but none match the high exposure triggers
        findings = [{"name": "Generic Critical", "severity": "Critical"} for _ in range(100)]
        result = _calculate_exposure(metadata, findings)
        self.assertEqual(result["level"], "MODERATE")

    def test_historical_missing_metadata_unknown(self):
        result = _calculate_exposure({}, [])
        self.assertEqual(result["level"], "UNKNOWN")

    def test_json_safe_output(self):
        import json
        metadata = {"ip_address": "93.184.216.34", "http_status": "200 OK"}
        findings = [{"rule_id": "api_graphql_ide_exposed", "name": "GraphQL IDE"}]
        result = _calculate_exposure(metadata, findings)
        serialized = json.dumps(result)
        self.assertNotIn("NaN", serialized)

    def test_score_and_findings_unchanged(self):
        from api.scanner.scoring import calculate_score
        metadata = {"ip_address": "93.184.216.34", "http_status": "200 OK"}
        findings = [{"name": "Test", "severity": "High", "category": "test", "description": "d", "evidence": "e", "confidence": "High", "remediation": "r", "remediation_snippets": {}, "owasp": "A01", "compliance": {"pci_dss": "N/A", "nist": "N/A", "iso27001": "N/A"}, "rule_id": "api_graphql_ide_exposed"}]

        # Test full pipeline to ensure it's attached but doesn't modify score/findings
        result = calculate_score("https://example.com", list(findings), metadata, None)
        self.assertIn("exposure", result)
        self.assertEqual(result["exposure"]["level"], "HIGH")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["name"], "Test")
        self.assertIsInstance(result["score"], int)

if __name__ == "__main__":
    unittest.main()

    def test_context_only_rules_do_not_elevate_to_high(self):
        metadata = {"ip_address": "93.184.216.34", "http_status": "200 OK", "performance_rating": "Optimal Latency"}
        context_rules = [
            "robots_txt_admin_surface",
            "api_xmlrpc_exposed",
            "api_actuator_endpoint_exposed",
            "api_openapi_privileged_routes",
            "api_openapi_unprotected_privileged_routes"
        ]
        for rule in context_rules:
            findings = [{"rule_id": rule, "name": "Test " + rule}]
            result = _calculate_exposure(metadata, findings)
            self.assertEqual(result["level"], "MODERATE", f"{rule} should not elevate to HIGH")
