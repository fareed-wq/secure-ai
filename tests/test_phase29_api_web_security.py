import unittest
from unittest.mock import patch, MagicMock
import requests
from api.scanner.modules.api_web_security import ApiWebSecurityModule
from api.scanner.modules.headers import TechFingerprintModule
import json

class TestPhase29ApiWebSecurity(unittest.TestCase):
    def setUp(self):
        self.session = requests.Session()
        self.hostname = "example.com"
        self.url = "https://example.com"

    @patch("api.scanner.modules.api_web_security.safe_request")
    def test_http_to_https_downgrade(self, mock_safe_request):
        mock_resp = MagicMock()
        
        hist1 = MagicMock()
        hist1.url = "https://example.com/login"
        
        mock_resp.history = [hist1]
        mock_resp.url = "http://example.com/login"
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.text = ""
        mock_safe_request.side_effect = [mock_resp, None]

        module = ApiWebSecurityModule()
        findings = module.run(self.url, self.hostname, self.session)
        
        downgrade = next((f for f in findings if f["name"] == "HTTP to HTTPS Redirect Security Issue"), None)
        self.assertIsNotNone(downgrade)
        self.assertEqual(downgrade["severity"], "Medium")

    @patch("api.scanner.modules.api_web_security.safe_request")
    def test_trace_advertised(self, mock_safe_request):
        mock_resp = MagicMock()
        mock_resp.history = []
        mock_resp.url = self.url
        mock_resp.status_code = 200
        mock_resp.headers = {"Allow": "GET, POST, TRACE, OPTIONS"}
        mock_resp.text = ""
        mock_safe_request.side_effect = [mock_resp, None]

        module = ApiWebSecurityModule()
        findings = module.run(self.url, self.hostname, self.session)
        
        trace = next((f for f in findings if f["name"] == "TRACE HTTP Method Advertised"), None)
        self.assertIsNotNone(trace)
        self.assertEqual(trace["severity"], "Low")

    @patch("api.scanner.modules.api_web_security.safe_request")
    def test_content_type_mismatch(self, mock_safe_request):
        mock_resp = MagicMock()
        mock_resp.history = []
        mock_resp.url = self.url
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.text = '{"status": "ok", "user": "admin"}'
        mock_safe_request.side_effect = [mock_resp, None]

        module = ApiWebSecurityModule()
        findings = module.run(self.url, self.hostname, self.session)
        
        mismatch = next((f for f in findings if f["name"] == "API Content-Type Mismatch Detected"), None)
        self.assertIsNotNone(mismatch)
        self.assertEqual(mismatch["severity"], "Low")

    @patch("api.scanner.modules.api_web_security.safe_request")
    def test_sensitive_cache(self, mock_safe_request):
        mock_resp = MagicMock()
        mock_resp.history = []
        mock_resp.url = "https://example.com/api/v1/user/profile"
        mock_resp.status_code = 200
        mock_resp.headers = {"Cache-Control": "public, max-age=3600"}
        mock_resp.text = '{"user": "admin"}'
        mock_safe_request.side_effect = [mock_resp, None]

        module = ApiWebSecurityModule()
        findings = module.run(self.url, self.hostname, self.session)
        
        cache = next((f for f in findings if f["name"] == "Publicly Cacheable JSON Response Observed"), None)
        self.assertIsNone(next((f for f in findings if f["name"] == "Sensitive API Response May Be Publicly Cacheable"), None), "Old Medium finding must be absent")
        self.assertIsNotNone(cache)
        self.assertEqual(cache["severity"], "Informational")

    @patch("api.scanner.modules.api_web_security.safe_request")
    def test_python_traceback(self, mock_safe_request):
        mock_resp = MagicMock()
        mock_resp.history = []
        mock_resp.url = self.url
        mock_resp.status_code = 500
        mock_resp.headers = {}
        mock_resp.text = 'Traceback (most recent call last):\n  File "app.py", line 10, in <module>'
        mock_safe_request.side_effect = [mock_resp, None]

        module = ApiWebSecurityModule()
        findings = module.run(self.url, self.hostname, self.session)
        
        err = next((f for f in findings if f["name"] == "API Error Information Disclosure"), None)
        self.assertIsNotNone(err)
        self.assertIn("Python Traceback", err["description"])
        
    @patch("api.scanner.modules.api_web_security.safe_request")
    def test_passive_recon(self, mock_safe_request):
        mock_resp = MagicMock()
        mock_resp.history = []
        mock_resp.url = self.url
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.text = '''
        <html>
        <script>
            let socket = new WebSocket("wss://api.example.com/stream");
            fetch("/api/v1/users");
        </script>
        <a href="/login">Login</a>
        <a href="/swagger-ui">Docs</a>
        </html>
        '''
        mock_safe_request.side_effect = [mock_resp, None]

        module = ApiWebSecurityModule()
        findings = module.run(self.url, self.hostname, self.session)
        
        ws = next((f for f in findings if f["name"] == "WebSocket Endpoint Discovered"), None)
        self.assertIsNotNone(ws)
        
        ver = next((f for f in findings if f["name"] == "API Version Disclosed"), None)
        self.assertIsNotNone(ver)
        
        auth = next((f for f in findings if f["name"] == "Authentication / Administrative Portal Discovered"), None)
        self.assertIsNotNone(auth)
        
        docs = next((f for f in findings if f["name"] == "API Documentation Reference Discovered"), None)
        self.assertIsNotNone(docs)

    @patch("api.scanner.modules.api_web_security.safe_request")
    def test_oidc_discovery(self, mock_safe_request):
        mock_oidc = MagicMock()
        mock_oidc.status_code = 200
        mock_oidc.text = ""
        mock_oidc.headers = {"Content-Type": "application/json"}
        mock_oidc.json.return_value = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/auth"
        }
        
        mock_safe_request.side_effect = [mock_oidc, mock_oidc]

        module = ApiWebSecurityModule()
        findings = module.run("https://example.com/.well-known/openid-configuration", self.hostname, self.session)
        
        oidc = next((f for f in findings if f["name"] == "OpenID Connect Configuration Discovered"), None)
        self.assertIsNotNone(oidc)
        self.assertEqual(oidc["severity"], "Informational")
        
    @patch("api.scanner.modules.headers.safe_request")
    def test_server_version_disclosure(self, mock_safe_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ""
        mock_resp.headers = {
            "Server": "nginx/1.24.0",
            "X-Powered-By": "PHP/8.2"
        }
        mock_safe_request.return_value = mock_resp

        module = TechFingerprintModule()
        findings = module.run(self.url, self.hostname, self.session)
        
        version_finding = next((f for f in findings if f["name"] == "Technology Fingerprint Identified" and "nginx" in str(f["evidence"])), None)
        self.assertIsNotNone(version_finding)
        self.assertEqual(version_finding["severity"], "Informational")

if __name__ == '__main__':
    unittest.main()
