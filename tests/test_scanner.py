import unittest
from unittest.mock import patch, MagicMock
import requests
import datetime
import socket

from api.index import (
    TechFingerprintModule,
    InformationDisclosureModule,
    RobotsTxtModule,
    SitemapModule,
    SecurityTxtModule,
    CORSModule,
    AdvancedCookieModule,
    HTTPSRedirectModule,
    EnhancedTLSModule,
    SecurityHeadersModule,
    AdvancedSecurityHeadersModule,
    ScannerModule,
    scan_url,
    Config,
    is_public_hostname
)

class TestScannerModules(unittest.TestCase):
    def setUp(self):
        self.session = requests.Session()
        self.url = "https://example.com"
        self.hostname = "example.com"

    def mock_response(self, status_code=200, text="", headers=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.headers = headers or {}
        resp.is_redirect = False
        del resp.raw
        return resp

    @patch('requests.Session.request')
    def test_tech_fingerprint_module(self, mock_get):
        mock_get.return_value = self.mock_response(headers={"Server": "nginx", "X-Powered-By": "PHP"})
        module = TechFingerprintModule()
        findings = module.run(self.url, self.hostname, self.session)
        self.assertEqual(len(findings), 1)
        self.assertTrue(any(f['name'] == 'Server Header Exposed' for f in findings))

    @patch('requests.Session.request')
    def test_tech_fingerprint_module_empty(self, mock_get):
        mock_get.return_value = self.mock_response(headers={})
        module = TechFingerprintModule()
        findings = module.run(self.url, self.hostname, self.session)
        self.assertEqual(len(findings), 0)

    @patch('requests.Session.request')
    def test_information_disclosure_module(self, mock_get):
        mock_get.return_value = self.mock_response(headers={"Server": "nginx/1.18.0"})
        module = InformationDisclosureModule()
        findings = module.run(self.url, self.hostname, self.session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['name'], 'Verbose Server Banner')

    @patch('requests.Session.request')
    def test_information_disclosure_module_safe(self, mock_get):
        mock_get.return_value = self.mock_response(headers={"Server": "nginx"})
        module = InformationDisclosureModule()
        findings = module.run(self.url, self.hostname, self.session)
        self.assertEqual(len(findings), 0)

    @patch('requests.Session.request')
    def test_robots_txt_module(self, mock_get):
        mock_get.return_value = self.mock_response(status_code=200, text="User-agent: *\nDisallow: /admin")
        module = RobotsTxtModule()
        findings = module.run(self.url, self.hostname, self.session)
        self.assertEqual(len(findings), 1)

    @patch('requests.Session.request')
    def test_sitemap_module(self, mock_get):
        mock_get.return_value = self.mock_response(status_code=200, text="<urlset></urlset>")
        module = SitemapModule()
        findings = module.run(self.url, self.hostname, self.session)
        self.assertEqual(len(findings), 1)

    @patch('requests.Session.request')
    def test_security_txt_module(self, mock_get):
        hp_resp = self.mock_response(status_code=200, text="homepage" * 200)
        target_resp = self.mock_response(status_code=200, text="Contact: mailto:security@example.com", headers={"Content-Type": "text/plain"})
        mock_get.side_effect = [hp_resp, target_resp]
        module = SecurityTxtModule()
        findings = module.run(self.url, self.hostname, self.session)
        self.assertEqual(findings[0]['severity'], 'Passed')

    @patch('requests.Session.request')
    def test_cors_module(self, mock_get):
        mock_get.return_value = self.mock_response(headers={"Access-Control-Allow-Origin": "*"})
        module = CORSModule()
        findings = module.run(self.url, self.hostname, self.session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], 'Informational')

    @patch('requests.Session.request')
    def test_advanced_cookie_module(self, mock_get):
        mock_get.return_value = self.mock_response(headers={"Set-Cookie": "session=123; path=/"})
        module = AdvancedCookieModule()
        findings = module.run(self.url, self.hostname, self.session)
        self.assertEqual(len(findings), 3) # Missing HttpOnly, Secure, SameSite

    @patch('requests.Session.request')
    def test_https_redirect_module(self, mock_get):
        mock_get.return_value = self.mock_response(status_code=301, headers={"Location": "https://example.com"})
        module = HTTPSRedirectModule()
        findings = module.run(self.url, self.hostname, self.session)
        self.assertEqual(findings[0]['severity'], 'Passed')

    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_enhanced_tls_module(self, mock_ssl, mock_sock):
        mock_context = MagicMock()
        mock_ssock = MagicMock()
        
        # Valid future date
        future_date = (datetime.datetime.utcnow() + datetime.timedelta(days=40)).strftime("%b %d %H:%M:%S %Y GMT")
        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "*.example.com"),),),
            "notAfter": future_date
        }
        mock_ssock.version.return_value = "TLSv1.3"
        
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ssl.return_value = mock_context
        
        module = EnhancedTLSModule()
        findings = module.run(self.url, self.hostname, self.session)
        
        self.assertTrue(any(f['severity'] == 'Passed' for f in findings))
        self.assertTrue(any(f['name'] == 'Wildcard Certificate in Use' for f in findings))

    @patch('requests.Session.request')
    def test_security_headers_module(self, mock_get):
        mock_get.return_value = self.mock_response(headers={})
        module = SecurityHeadersModule()
        findings = module.run(self.url, self.hostname, self.session)
        self.assertEqual(len(findings), 8) # All missing headers

    @patch('requests.Session.request')
    def test_advanced_security_headers_module(self, mock_get):
        mock_get.return_value = self.mock_response(headers={})
        module = AdvancedSecurityHeadersModule()
        findings = module.run(self.url, self.hostname, self.session)
        self.assertEqual(len(findings), 3)

    # Edge Cases & Timeouts
    @patch('requests.Session.request')
    def test_timeout_handling(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")
        module = SecurityHeadersModule()
        findings = module.run(self.url, self.hostname, self.session)
        self.assertGreaterEqual(len(findings), 8)

    @patch('requests.Session.request')
    def test_redirect_loop_handling(self, mock_get):
        mock_get.side_effect = requests.exceptions.TooManyRedirects("Exceeded redirects")
        module = HTTPSRedirectModule()
        findings = module.run(self.url, self.hostname, self.session)
        self.assertEqual(len(findings), 0)

    def test_is_public_hostname(self):
        self.assertFalse(is_public_hostname("localhost"))
        self.assertFalse(is_public_hostname("127.0.0.1"))
        self.assertFalse(is_public_hostname("192.168.1.1"))
        self.assertFalse(is_public_hostname("10.0.0.1"))
        
        # Test a public IP directly since DNS can be flaky in tests
        with patch('socket.getaddrinfo') as mock_dns:
            mock_dns.return_value = [(2, 1, 6, '', ('8.8.8.8', 0))]
            self.assertTrue(is_public_hostname("example.com"))

    @patch('api.index.is_public_hostname')
    def test_scan_url_orchestration(self, mock_public):
        mock_public.return_value = True
        
        # Create a dummy module that always returns a known finding
        class DummyModule(ScannerModule):
            module_name = "Dummy"
            enabled = True
            timeout = 1.0
            def run(self, url, hostname, session):
                return [{"name": "Test Finding", "severity": "High", "description": "Test", "evidence": "None", "owasp": "A01"}]
        
        # Override the global REGISTERED_MODULES for this test
        with patch('api.index.REGISTERED_MODULES', [DummyModule()]), \
             patch('api.scanner.data.registry.REGISTERED_MODULES', [DummyModule()]), \
             patch('api.scanner.orchestrator.REGISTERED_MODULES', [DummyModule()]):
            result = scan_url("https://example.com")
            
            self.assertEqual(result['score'], 90) # 100 - 10 (High)
            self.assertEqual(result['severity_counts']['High'], 1)
            self.assertTrue("A01" in result['owasp_coverage'])

if __name__ == '__main__':
    unittest.main()
