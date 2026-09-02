import unittest
import requests
from unittest.mock import patch, MagicMock

from api.scanner.base import ScannerModule
from api.scanner.modules.headers import CORSModule
from api.scanner.modules.network_checks import SubdomainTakeoverModule, PassiveSubdomainDiscoveryModule
class TestScannerBase(ScannerModule):
    def run(self, url: str, hostname: str, session: requests.Session) -> list:
        return []

class TestPhase23Audit(unittest.TestCase):
    def setUp(self):
        self.session = requests.Session()
        self.url = "http://example.com"
        self.hostname = "example.com"
        self.base = TestScannerBase()
        
    def test_masking_beginning(self):
        evidence = "Bearer sk_live_1234567890abcdef is my token"
        finding = self.base.make_finding("Test", "Low", "Desc", evidence)
        self.assertIn("Bearer [REDACTED_STRIPE] is my token", finding["evidence"]["raw"])
        self.assertNotIn("sk_live_1234567890abcdef", finding["evidence"]["raw"])
        
    def test_masking_middle(self):
        evidence = "The token is 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X for real"
        finding = self.base.make_finding("Test", "Low", "Desc", evidence)
        self.assertIn("[REDACTED_GITHUB_PAT]", finding["evidence"]["raw"])
        self.assertNotIn("github_pat_11AAAAA22BBBBB33CCCCC44DDDDD55EEEEE66FFFFF77GGGGG88HHHHH99IIIII00JJJJJ11KKKKK22LL", finding["evidence"]["raw"])
        
    def test_masking_end(self):
        evidence = "Look at this token=secret_token_123"
        finding = self.base.make_finding("Test", "Low", "Desc", evidence)
        self.assertIn("token=[REDACTED]", finding["evidence"]["raw"])
        self.assertNotIn("secret_token_123", finding["evidence"]["raw"])
        
    def test_masking_truncation_boundary(self):
        # 180 char limit
        padding = "A" * 150
        secret = "AKIAIOSFODNN7EXAMPLE" # 20 chars
        evidence = padding + secret + "B" * 50
        finding = self.base.make_finding("Test", "Low", "Desc", evidence)
        
        raw = finding["evidence"]["raw"]
        self.assertEqual(len(raw), 180)
        # Secret should be redacted
        self.assertIn("[REDACTED_AWS]", raw)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", raw)

    def test_masking_beyond_truncation_boundary(self):
        # 180 char limit
        padding = "A" * 200
        secret = "AKIAIOSFODNN7EXAMPLE" # 20 chars
        evidence = padding + secret
        finding = self.base.make_finding("Test", "Low", "Desc", evidence)
        
        raw = finding["evidence"]["raw"]
        self.assertEqual(len(raw), 180)
        self.assertNotIn("AKIA", raw)
        
    @patch("api.scanner.modules.headers.safe_request")
    def test_cors_confidence(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.headers = {"Access-Control-Allow-Origin": "*"}
        mock_resp.status_code = 200
        mock_req.return_value = mock_resp
        
        module = CORSModule()
        findings = module.run(self.url, self.hostname, self.session)
        
        cors_finding = next((f for f in findings if "CORS" in f["name"]), None)
        self.assertIsNotNone(cors_finding)
        self.assertEqual(cors_finding["confidence"], "Medium")
        self.assertEqual(cors_finding["severity"], "Informational")

    @patch("api.scanner.modules.network_checks.safe_request")
    def test_subdomain_takeover_confidence(self, mock_req):
        mock_cname_resp = MagicMock()
        mock_cname_resp.status_code = 200
        mock_cname_resp.json.return_value = {"Answer": [{"data": "test.github.io."}]}
        
        mock_probe_resp = MagicMock()
        mock_probe_resp.text = "There isn't a GitHub Pages site here"
        
        mock_req.side_effect = [mock_cname_resp, mock_probe_resp]
        
        module = SubdomainTakeoverModule()
        findings = module.run(self.url, self.hostname, self.session)
        
        cname_finding = next((f for f in findings if f["name"] == "Subdomain Takeover Vulnerability (Dangling CNAME)"), None)
        self.assertIsNotNone(cname_finding)
        self.assertEqual(cname_finding["confidence"], "Medium")
        self.assertEqual(cname_finding["severity"], "High")

    @patch("api.scanner.modules.discovery.safe_request")
    def test_administrative_interface_confidence(self, mock_req):
        hp_resp = MagicMock()
        hp_resp.status_code = 200
        hp_resp.headers = {"Content-Type": "text/html"}
        hp_resp.text = "Just a short homepage"
        
        target_resp = MagicMock()
        target_resp.status_code = 200
        target_resp.headers = {"Content-Type": "text/html"}
        target_resp.text = '<html><body><input type="password" name="pwd"> admin login panel ' + ('X' * 200) + '</body></html>'
        
        def mock_side_effect(method, url, **kwargs):
            if url.endswith("/admin"):
                return target_resp
            return hp_resp
        
        mock_req.side_effect = mock_side_effect
        
        from api.scanner.modules.discovery import ExposedFilesModule
        module = ExposedFilesModule()
        findings = module.run(self.url, self.hostname, self.session)
        
        admin_finding = next((f for f in findings if f["name"] == "Administrative Interface Exposed"), None)
        self.assertIsNotNone(admin_finding)
        self.assertEqual(admin_finding["confidence"], "Medium")
        self.assertEqual(admin_finding["severity"], "Low")

    def test_subdomains_discovered_evidence_limit(self):
        # Create a massive string > 180 chars
        large_evidence = "A" * 500
        finding = self.base.make_finding("Subdomains Discovered", "Informational", "Desc", large_evidence)
        self.assertEqual(len(finding["evidence"]["raw"]), 500)
        
        # Test a non-whitelisted finding
        normal_finding = self.base.make_finding("Random Issue", "Low", "Desc", large_evidence)
        self.assertEqual(len(normal_finding["evidence"]["raw"]), 180)

if __name__ == "__main__":
    unittest.main()
