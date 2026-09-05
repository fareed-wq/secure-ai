import unittest
from unittest.mock import MagicMock
import requests
from api.scanner.modules.headers import CORSModule
from api.scanner.modules.http_security import SecurityHeadersModule
from api.scanner.scoring import calculate_score

class TestPhase18Accuracy(unittest.TestCase):

    def setUp(self):
        self.session = requests.Session()
        self.url = "https://example.com"
        self.hostname = "example.com"

    def test_cors_module_passive_wildcard(self):
        module = CORSModule()
        resp = requests.Response()
        resp.status_code = 200
        resp.headers = {"Access-Control-Allow-Origin": "*"}
        
        # We need to mock safe_request so we return this response when url is requested
        import api.scanner.modules.headers
        old_safe_request = api.scanner.modules.headers.safe_request
        api.scanner.modules.headers.safe_request = MagicMock(return_value=resp)
        
        try:
            findings = module.run(self.url, self.hostname, self.session)
            # Find the CORS finding
            finding = next((f for f in findings if "CORS" in f["name"]), None)
            self.assertIsNotNone(finding)
            self.assertEqual(finding["name"], "CORS Enabled (Wildcard)")
            self.assertEqual(finding["severity"], "Informational")
        finally:
            api.scanner.modules.headers.safe_request = old_safe_request

    def test_security_headers_api_response(self):
        module = SecurityHeadersModule()
        resp = requests.Response()
        resp.status_code = 200
        resp.headers = {"Content-Type": "application/json"}
        
        import api.scanner.modules.http_security
        old_safe_request = api.scanner.modules.http_security.safe_request
        api.scanner.modules.http_security.safe_request = MagicMock(return_value=resp)
        
        try:
            findings = module.run(self.url, self.hostname, self.session)
            
            xfo_finding = next((f for f in findings if "X-Frame-Options" in f["name"]), None)
            csp_finding = next((f for f in findings if "Content-Security-Policy" in f["name"]), None)
            
            self.assertIsNone(xfo_finding, "API response should not flag X-Frame-Options")
            self.assertIsNone(csp_finding, "API response should not flag Content-Security-Policy")
        finally:
            api.scanner.modules.http_security.safe_request = old_safe_request

    def test_sensitive_paths_low_severity(self):
        from api.scanner.modules.discovery import ExposedFilesModule
        module = ExposedFilesModule()
        resp = requests.Response()
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/html"}
        resp._content = b'<html><body><form action="/login"><input type="password" name="pwd">login admin</form></body></html>'
        
        import api.scanner.modules.discovery
        old_safe_request = api.scanner.modules.discovery.safe_request
        def mock_request(method, url, *args, **kwargs):
            if "/admin" in url:
                return resp
            return None
        api.scanner.modules.discovery.safe_request = mock_request
        
        try:
            findings = module.run(self.url, self.hostname, self.session)
            finding = next((f for f in findings if "Administrative Interface Observed" in f["name"]), None)
            
            self.assertIsNotNone(finding)
            self.assertEqual(finding["severity"], "Informational", "Administrative interface should be Informational severity")
            self.assertIn("administrative use", finding["description"])
        finally:
            api.scanner.modules.discovery.safe_request = old_safe_request

    def test_scoring_deduplication_tls(self):
        finding1 = {
            "name": "Obsolete TLS Version Supported",
            "severity": "High",
            "category": "encryption_tls"
        }
        finding2 = {
            "name": "Weak TLS Cipher Negotiated",
            "severity": "Medium", # Medium weight is 10, High is 15. If deduped, we only subtract max
            "category": "encryption_tls"
        }
        
        metadata = {}
        score_data = calculate_score(self.url, [finding1, finding2], metadata, None)
        # High weight = 10, Medium weight = 5
        # With dedup: High is scored (penalty=10), Medium is deduped. Score = 90.
        self.assertEqual(score_data["score"], 90)

if __name__ == "__main__":
    unittest.main()
