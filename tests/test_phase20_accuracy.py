import unittest
from unittest.mock import MagicMock
import requests
from api.scanner.modules.headers import PermissionsPolicyModule
from api.scanner.modules.http_security import SecurityHeadersModule
from api.scanner.base import ScannerModule

class DummyModule(ScannerModule):
    def run(self, url, hostname, session):
        pass

class TestPhase20Accuracy(unittest.TestCase):
    def setUp(self):
        self.url = "http://example.com"
        self.hostname = "example.com"
        self.session = MagicMock()
        self.perm_module = PermissionsPolicyModule()
        self.sec_module = SecurityHeadersModule()
        self.dummy_module = DummyModule()

    def test_json_api_permissions_policy_suppressed(self):
        # A. JSON API + missing Permissions-Policy
        resp = MagicMock()
        resp.headers = {"Content-Type": "application/json"}
        resp.url = self.url
        resp.text = "{}"
        
        # Patch safe_request to return our mock
        import api.scanner.modules.headers
        original_safe = api.scanner.modules.headers.safe_request
        api.scanner.modules.headers.safe_request = lambda *a, **k: resp
        
        try:
            findings = self.perm_module.run(self.url, self.hostname, self.session)
            # Should be suppressed because it's JSON
            self.assertEqual(len(findings), 0)
        finally:
            api.scanner.modules.headers.safe_request = original_safe

    def test_html_permissions_policy_not_suppressed(self):
        # B. HTML + missing Permissions-Policy
        resp = MagicMock()
        resp.headers = {"Content-Type": "text/html"}
        resp.url = self.url
        resp.text = "<html></html>"
        
        import api.scanner.modules.headers
        original_safe = api.scanner.modules.headers.safe_request
        api.scanner.modules.headers.safe_request = lambda *a, **k: resp
        
        try:
            findings = self.perm_module.run(self.url, self.hostname, self.session)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["name"], "Missing Permissions-Policy")
        finally:
            api.scanner.modules.headers.safe_request = original_safe

    def test_json_api_hsts_not_suppressed(self):
        # C. JSON API missing HSTS -> detected
        resp = MagicMock()
        resp.headers = {"Content-Type": "application/json"}
        resp.url = self.url
        resp.text = "{}"
        
        import api.scanner.modules.http_security
        original_safe = api.scanner.modules.http_security.safe_request
        api.scanner.modules.http_security.safe_request = lambda *a, **k: resp
        
        try:
            findings = self.sec_module.run(self.url, self.hostname, self.session)
            hsts_findings = [f for f in findings if f["name"] == "Missing Strict-Transport-Security (HSTS)"]
            self.assertEqual(len(hsts_findings), 1)
        finally:
            api.scanner.modules.http_security.safe_request = original_safe

    def test_credential_masking(self):
        # D & E. Credential masking checks
        evidence = {
            "proof_snippet": "Here is my token ghp_123456789012345678901234567890123456 and glpat-abcdefghijklmnopqrst and xoxb-1234-5678 and npm_098765432109876543210987654321098765. Also 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."
        }
        
        finding = self.dummy_module.make_finding("Test", "High", "Desc", evidence)
        ev_str = finding["evidence"]["proof_snippet"]
        
        self.assertIn("[REDACTED_GITHUB]", ev_str)
        self.assertNotIn("ghp_123456789012345678901234567890123456", ev_str)
        
        self.assertIn("[REDACTED_GITLAB]", ev_str)
        self.assertNotIn("glpat-abcdefghijklmnopqrst", ev_str)
        
        self.assertIn("[REDACTED_SLACK]", ev_str)
        self.assertNotIn("xoxb-1234-5678", ev_str)
        
        self.assertIn("[REDACTED_NPM]", ev_str)
        self.assertNotIn("npm_098765432109876543210987654321098765", ev_str)
        
        self.assertIn("[REDACTED_GITHUB_PAT]", ev_str)
        self.assertNotIn("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", ev_str)
        
        # Test existing
        evidence_aws = "Here is my AKIAIOSFODNN7EXAMPLE and sk-proj-12345678901234567890123456789012"
        finding_aws = self.dummy_module.make_finding("Test", "High", "Desc", evidence_aws)
        self.assertIn("[REDACTED_AWS]", finding_aws["evidence"]["raw"])
        self.assertIn("[REDACTED_OPENAI]", finding_aws["evidence"]["raw"])
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", finding_aws["evidence"]["raw"])

if __name__ == '__main__':
    unittest.main()
