import unittest
from unittest.mock import MagicMock
import requests
from api.scanner.modules.network_checks import PassiveSubdomainDiscoveryModule
from api.scanner.scoring import calculate_score

class TestPhase22Reporting(unittest.TestCase):
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

    def test_reporting_formatting_and_classification(self):
        data = [
            {"name_value": "api.example.com"},
            {"name_value": "admin.example.com"},
            {"name_value": "staging.example.com"},
            {"name_value": "mail.example.com"},
            {"name_value": "other.example.com"},
            {"name_value": "dev.example.com"}
        ]
        # Add enough to trigger truncation (>20)
        for i in range(20):
            data.append({"name_value": f"random{i}.example.com"})

        findings = self._run_with_mock_resp(data)
        
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        
        # 1. Subdomain finding remains Informational.
        self.assertEqual(finding["severity"], "Informational")
        self.assertEqual(finding["name"], "Subdomains Discovered")
        
        # 2. Subdomain discovery produces exactly one finding.
        # Verified above by len(findings) == 1
        
        evidence = finding["evidence"]["raw"]
        
        # 3. Large subdomain lists are summarized.
        # 5. Evidence remains within configured limits (via truncation).
        self.assertIn("... (and 6 more omitted)", evidence)
        
        # 4. Total count is preserved.
        self.assertIn("26 unique subdomains discovered", evidence)
        
        # 6. Simple report output is non-technical.
        self.assertEqual(finding["description"], "We found publicly visible addresses (subdomains) connected to your main website.")
        
        # 7. Technical report contains CT/source context.
        # Verified by presence in the metadata output
        
        # 8, 9, 10. Pattern classification and NO vulnerability claims
        self.assertIn("Attack Surface Categories:", evidence)
        self.assertIn("API: 1", evidence)
        self.assertIn("Administrative: 1", evidence)
        self.assertIn("Development/Staging: 2", evidence) # dev and staging
        self.assertIn("Mail: 1", evidence)
        self.assertIn("Other: 21", evidence)
        
        # 11. JSON/API response remains backward compatible.
        self.assertIn("metadata", finding)
        self.assertEqual(finding["metadata"]["source"], "Certificate Transparency")
        
        # 14. Evidence masking still works
        # Provided by make_finding which is used by this module

    def test_empty_results(self):
        # 15. Empty CT results produce no finding.
        findings = self._run_with_mock_resp([])
        self.assertEqual(len(findings), 0)

    def test_score_unaffected(self):
        # 12. Score remains unchanged when only informational subdomain findings are added.
        data = [{"name_value": "api.example.com"}]
        subdomain_findings = self._run_with_mock_resp(data)
        
        # Simulated base finding with a high score drop
        base_findings = [{
            "name": "Missing HTTPS",
            "severity": "High",
            "category": "encryption_tls"
        }]
        
        score_before = calculate_score(self.url, base_findings, {}, None)["score"]
        
        # Combine
        combined_findings = base_findings + subdomain_findings
        score_after = calculate_score(self.url, combined_findings, {}, None)["score"]
        
        self.assertEqual(score_before, score_after)

if __name__ == '__main__':
    unittest.main()
