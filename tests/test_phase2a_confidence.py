"""
Phase 2A - Confidence Hardening Tests
Validates that targeted heuristic rules no longer default to High confidence.
"""
import unittest
import sys
import os
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.scanner.base import ScannerModule
from api.scanner.modules.discovery import InformationDisclosureModule, RobotsTxtModule, OpenApiModule
from api.scanner.modules.javascript_security import JavaScriptSecurityModule
from api.scanner.modules.headers import TechFingerprintModule
from api.scanner.scoring import calculate_score

class DummyModule(ScannerModule):
    def run(self, url, hostname, session):
        pass

class TestPhase2AConfidence(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock()
        self.url = "http://example.com"
        self.hostname = "example.com"
        self.mod = DummyModule()

    def _get_finding_by_rule_id(self, result, rule_id):
        from api.scanner.core import ModuleResult
        findings = result.findings if isinstance(result, ModuleResult) else result
        for f in findings:
            if f.get("rule_id") == rule_id:
                return f
        return None

    def test_canonical_values_and_defaults(self):
        # make_finding default is still High
        f = self.mod.make_finding("Test", "High", "Desc", "Ev")
        self.assertEqual(f.get("confidence"), "High")

        # We can pass Medium or Low
        f2 = self.mod.make_finding("Test", "High", "Desc", "Ev", confidence="Medium")
        self.assertEqual(f2.get("confidence"), "Medium")

    def test_info_disclosure_stack_trace_medium(self):
        resp = MagicMock()
        resp.is_redirect = False
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/plain"}
        resp.text = ""
        resp.url = "http://example.com/robots.txt"
        resp.text = "Traceback (most recent call last): error at line 1"
        self.session.request.return_value = resp
        mod = InformationDisclosureModule()
        result = mod.run(self.url, self.hostname, self.session)
        finding = self._get_finding_by_rule_id(result, "info_disclosure_stack_trace")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["confidence"], "Medium")

    def test_info_disclosure_private_ip_medium(self):
        resp = MagicMock()
        resp.is_redirect = False
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/plain"}
        resp.text = ""
        resp.url = "http://example.com/robots.txt"
        resp.text = "internal ip 192.168.1.55"
        self.session.request.return_value = resp
        mod = InformationDisclosureModule()
        result = mod.run(self.url, self.hostname, self.session)
        finding = self._get_finding_by_rule_id(result, "info_disclosure_private_ip")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["confidence"], "Medium")

    def test_robots_txt_admin_surface_medium(self):
        resp = MagicMock()
        resp.is_redirect = False
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/plain"}
        resp.text = ""
        resp.url = "http://example.com/robots.txt"
        resp.text = "User-agent: *\nDisallow: /admin"
        resp.status_code = 200
        self.session.request.return_value = resp
        mod = RobotsTxtModule()
        mod.is_spa_fallback = MagicMock(return_value=False)
        import logging
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
        result = mod.run(self.url, self.hostname, self.session)
        finding = self._get_finding_by_rule_id(result, "robots_txt_admin_surface")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["confidence"], "Medium")

    def test_openapi_documentation_inference_medium(self):
        resp = MagicMock()
        resp.is_redirect = False
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/plain"}
        resp.text = ""
        resp.url = "http://example.com/robots.txt"
        resp.status_code = 200
        resp.headers = {"Content-Type": "application/json"}
        # valid openapi spec with a privileged route
        resp.json.return_value = {
            "openapi": "3.0.0",
            "paths": {
                "/api/admin/users": {
                    "get": {
                        "security": []
                    }
                }
            }
        }
        self.session.request.return_value = resp
        mod = OpenApiModule()
        result = mod.run(self.url, self.hostname, self.session)

        f1 = self._get_finding_by_rule_id(result, "api_openapi_privileged_routes")
        self.assertIsNotNone(f1)
        self.assertEqual(f1["confidence"], "Medium")

        f2 = self._get_finding_by_rule_id(result, "api_openapi_unprotected_privileged_routes")
        self.assertIsNotNone(f2)
        self.assertEqual(f2["confidence"], "Medium")

        f3 = self._get_finding_by_rule_id(result, "api_openapi_exposed")
        self.assertIsNotNone(f3)
        self.assertEqual(f3["confidence"], "High") # The exposed OpenAPI itself is a deterministic observation

    def test_js_string_discoveries_medium(self):
        resp = MagicMock()
        resp.is_redirect = False
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/plain"}
        resp.text = ""
        resp.url = "http://example.com/robots.txt"
        resp.text = 'const roles = ["admin"]; fetch("/api/admin");'
        resp.status_code = 200
        self.session.request.return_value = resp
        mod = JavaScriptSecurityModule()
        result = mod.run(self.url, self.hostname, self.session)

        f1 = self._get_finding_by_rule_id(result, "js_auth_roles_disclosed")
        if f1:
            self.assertEqual(f1["confidence"], "Medium")

        f2 = self._get_finding_by_rule_id(result, "js_privileged_api_surface")
        if f2:
            self.assertEqual(f2["confidence"], "Medium")

    def test_generic_technology_fingerprint_medium(self):
        resp = MagicMock()
        resp.is_redirect = False
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/plain"}
        resp.text = ""
        resp.url = "http://example.com/robots.txt"
        resp.headers = {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4"}
        self.session.request.return_value = resp
        mod = TechFingerprintModule()
        result = mod.run(self.url, self.hostname, self.session)

        f1 = self._get_finding_by_rule_id(result, "technology_detected")
        self.assertIsNotNone(f1)
        self.assertEqual(f1["confidence"], "Medium")

    def test_confidence_does_not_alter_score(self):
        metadata = {"ip_address": "93.184.216.34", "http_status": "200 OK"}
        findings = [
            self.mod.make_finding("Test", "High", "d", "e", confidence="Medium", rule_id="api_openapi_privileged_routes"),
            self.mod.make_finding("Test2", "High", "d", "e", confidence="High", rule_id="network_port_exposed")
        ]

        result = calculate_score(self.url, findings, metadata, None)
        self.assertIsInstance(result["score"], int)

        # changing confidence shouldn't change score
        findings[0]["confidence"] = "Low"
        result2 = calculate_score(self.url, findings, metadata, None)
        self.assertEqual(result["score"], result2["score"])

    def test_rule_id_and_instance_key_preserved(self):
        f = self.mod.make_finding("Test", "High", "d", "e", confidence="Medium", rule_id="r1", instance_key="i1")
        self.assertEqual(f["rule_id"], "r1")
        self.assertEqual(f["instance_key"], "i1")
        self.assertEqual(f["confidence"], "Medium")


    def test_info_disclosure_server_banner_high(self):
        resp = MagicMock()
        resp.is_redirect = False
        resp.status_code = 200
        resp.headers = {"Server": "nginx/1.18.0"}
        self.session.request.return_value = resp
        mod = InformationDisclosureModule()
        result = mod.run(self.url, self.hostname, self.session)
        finding = self._get_finding_by_rule_id(result, "info_disclosure_server_banner")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["confidence"], "High")

if __name__ == "__main__":
    unittest.main()
