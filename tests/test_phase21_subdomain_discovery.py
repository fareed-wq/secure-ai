import unittest
from unittest.mock import MagicMock
import requests
from api.scanner.modules.network_checks import PassiveSubdomainDiscoveryModule
from api.scanner.data.registry import REGISTERED_MODULES

class TestPhase21SubdomainDiscovery(unittest.TestCase):
    def setUp(self):
        self.url = "http://example.com"
        self.hostname = "example.com"
        self.session = MagicMock()
        self.module = PassiveSubdomainDiscoveryModule()

    def _run_with_mock_resp(self, json_data, status_code=200):
        resp = MagicMock()
        resp.is_redirect = False
        del resp.raw
        resp.status_code = status_code
        resp.json = MagicMock(return_value=json_data)
        
        import api.scanner.modules.network_checks
        original_safe = api.scanner.modules.network_checks.safe_request
        api.scanner.modules.network_checks.safe_request = lambda *a, **k: resp
        
        try:
            findings = self.module.run(self.url, self.hostname, self.session)
            return findings
        finally:
            api.scanner.modules.network_checks.safe_request = original_safe

    def _run_with_exception(self, exc):
        import api.scanner.modules.network_checks
        original_safe = api.scanner.modules.network_checks.safe_request
        
        def raiser(*a, **k):
            raise exc
            
        api.scanner.modules.network_checks.safe_request = raiser
        
        try:
            findings = self.module.run(self.url, self.hostname, self.session)
            return findings
        finally:
            api.scanner.modules.network_checks.safe_request = original_safe

    def test_basic_parsing_and_normalization(self):
        data = [
            {"name_value": "api.example.com"},
            {"name_value": "*.example.com\nDEV.example.com."}, # wildcard, uppercase, newline, trailing dot
            {"name_value": "example.com"} # root
        ]
        findings = self._run_with_mock_resp(data)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "Subdomains Discovered")
        self.assertEqual(findings[0]["severity"], "Informational")
        self.assertEqual(findings[0]["category"], "information_exposure")
        
        evidence = findings[0]["evidence"]["raw"]
        self.assertIn("api.example.com", evidence)
        self.assertIn("dev.example.com", evidence)
        self.assertIn("example.com", evidence)
        self.assertNotIn("*.example.com", evidence)
        self.assertIn("3 unique subdomains discovered", evidence)

    def test_cross_domain_filtering(self):
        data = [
            {"name_value": "example.com.attacker.com"},
            {"name_value": "attackerexample.com"},
            {"name_value": "example.com.evil"},
            {"name_value": "valid.example.com"}
        ]
        findings = self._run_with_mock_resp(data)
        self.assertEqual(len(findings), 1)
        evidence = findings[0]["evidence"]["raw"]
        self.assertIn("valid.example.com", evidence)
        self.assertNotIn("attacker", evidence)
        self.assertNotIn("evil", evidence)

    def test_deduplication(self):
        data = [
            {"name_value": "api.example.com"},
            {"name_value": "api.example.com."},
            {"name_value": "API.example.com"}
        ]
        findings = self._run_with_mock_resp(data)
        self.assertEqual(len(findings), 1)
        evidence = findings[0]["evidence"]["raw"]
        self.assertIn("1 unique subdomains discovered", evidence)

    def test_malformed_empty_json(self):
        # Empty list
        findings = self._run_with_mock_resp([])
        self.assertEqual(len(findings), 0)
        
        # Not a list
        findings = self._run_with_mock_resp({"error": "foo"})
        self.assertEqual(len(findings), 0)
        
        # Missing name_value
        findings = self._run_with_mock_resp([{"other": "value"}])
        self.assertEqual(len(findings), 0)

    def test_http_error(self):
        findings = self._run_with_mock_resp([], status_code=503)
        self.assertEqual(len(findings), 0)

    def test_exceptions_graceful(self):
        findings = self._run_with_exception(requests.exceptions.Timeout("Timeout!"))
        self.assertEqual(len(findings), 0)
        
        findings = self._run_with_exception(ValueError("Invalid JSON"))
        self.assertEqual(len(findings), 0)

    def test_is_registered(self):
        module_names = [type(m).__name__ for m in REGISTERED_MODULES]
        self.assertIn("PassiveSubdomainDiscoveryModule", module_names)
        self.assertNotIn("SubdomainProbingModule", module_names) # Verify existing is still dynamic only

if __name__ == '__main__':
    unittest.main()
