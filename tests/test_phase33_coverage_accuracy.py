import unittest
from unittest.mock import patch, MagicMock
from api.scanner.modules.network_checks import SubdomainProbingModule
from api.scanner.modules.http_security import HTTPSRedirectModule, AdvancedSecurityHeadersModule
from api.scanner.modules.discovery import SitemapModule
import ssl

class TestPhase33CoverageAccuracy(unittest.TestCase):

    @patch('api.scanner.modules.network_checks.safe_request')
    def test_subdomain_probing_functional(self, mock_req):
        """Test SubdomainProbingModule functionality."""
        mod = SubdomainProbingModule()
        
        def side_effect(*args, **kwargs):
            url = args[1]
            if "api.example.com" in url:
                return MagicMock(status_code=200, __bool__=lambda self: True)
            else:
                return None # The module ignores if resp is None
            
        mock_req.side_effect = side_effect
        
        with patch('api.scanner.modules.network_checks.Config.COMMON_SUBDOMAINS', ['api', 'dev', 'stage']):
            findings = mod.run("https://example.com", "example.com", MagicMock())
        
        self.assertEqual(len(findings), 1)
        self.assertIn("Active Subdomain Found: api.example.com", findings[0]["name"])
        self.assertEqual(findings[0]["severity"], "Informational")

    def test_https_redirect_missing(self):
        """Test HTTPSRedirectModule when redirect is missing."""
        mod = HTTPSRedirectModule()
        session = MagicMock()
        
        # Mock the cleartext HTTP request returning 200 OK (no redirect)
        resp = MagicMock()
        resp.url = "http://example.com/"
        resp.status_code = 200
        session.get.return_value = resp
        
        with patch('api.scanner.modules.http_security.safe_request', return_value=resp):
            findings = mod.run("https://example.com", "example.com", session)
            
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "Missing HTTPS Redirection")
        self.assertEqual(findings[0]["severity"], "High")

    def test_sitemap_missing(self):
        """Test SitemapModule when sitemap is missing."""
        mod = SitemapModule()
        
        resp = MagicMock()
        resp.status_code = 404
        
        with patch('api.scanner.modules.discovery.safe_request', return_value=resp):
            findings = mod.run("https://example.com", "example.com", MagicMock())
            
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "sitemap.xml Missing")
        self.assertEqual(findings[0]["severity"], "Informational")

    def test_advanced_security_headers_missing(self):
        """Test AdvancedSecurityHeadersModule when headers are missing."""
        mod = AdvancedSecurityHeadersModule()
        
        resp = MagicMock()
        resp.headers = {}
        resp.url = "https://example.com"
        
        with patch('api.scanner.modules.http_security.safe_request', return_value=resp):
            findings = mod.run("https://example.com", "example.com", MagicMock())
            
        self.assertEqual(len(findings), 3)
        finding_names = [f["name"] for f in findings]
        self.assertIn("COOP Not Configured", finding_names)
        self.assertIn("COEP Not Configured", finding_names)
        self.assertIn("CORP Not Configured", finding_names)

if __name__ == '__main__':
    unittest.main()
