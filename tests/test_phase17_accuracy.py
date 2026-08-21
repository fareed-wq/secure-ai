import unittest
from unittest.mock import patch, MagicMock
import requests

from api.scanner.modules.http_security import SecurityHeadersModule, AdvancedCookieModule
from api.scanner.modules.headers import CORSModule
from api.scanner.modules.content import MixedContentModule
from api.scanner.modules.network_checks import GraphQLIntrospectionModule, VerboseStackTraceModule

class MockResponse:
    def __init__(self, text, status_code, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
    
    def json(self):
        import json
        return json.loads(self.text)
        
    def iter_content(self, chunk_size):
        yield self.text.encode('utf-8')

class TestPhase17Accuracy(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock(spec=requests.Session)
        
    # 1 & 2: SecurityHeadersModule
    @patch('api.scanner.modules.http_security.safe_request')
    def test_security_headers_present(self, mock_safe):
        mock_safe.return_value = MockResponse("", 200, {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'"
        })
        mod = SecurityHeadersModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        # We expect a "Passed" finding if all 4 are present
        passed_findings = [f for f in findings if f["severity"] == "Passed"]
        self.assertGreaterEqual(len(passed_findings), 1)
        missing_findings = [f for f in findings if f["name"] == "Missing Security Headers"]
        self.assertEqual(len(missing_findings), 0)

    @patch('api.scanner.modules.http_security.safe_request')
    def test_security_headers_missing(self, mock_safe):
        mock_safe.return_value = MockResponse("", 200, {})
        mod = SecurityHeadersModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        missing_findings = [f for f in findings if "Missing" in f["name"]]
        self.assertGreaterEqual(len(missing_findings), 1)

    # 3 & 4: AdvancedCookieModule
    @patch('api.scanner.modules.http_security.safe_request')
    def test_secure_cookie(self, mock_safe):
        mock_safe.return_value = MockResponse("", 200, {
            "Set-Cookie": "session_id=12345; Secure; HttpOnly; SameSite=Strict"
        })
        mod = AdvancedCookieModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        insecure_cookie_findings = [f for f in findings if f["severity"] in ["High", "Medium"]]
        self.assertEqual(len(insecure_cookie_findings), 0)

    @patch('api.scanner.modules.http_security.safe_request')
    def test_insecure_cookie(self, mock_safe):
        mock_safe.return_value = MockResponse("", 200, {
            "Set-Cookie": "session_id=12345" # Missing Secure, HttpOnly
        })
        mod = AdvancedCookieModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        insecure_cookie_findings = [f for f in findings if f["severity"] in ["High", "Medium"] and "Cookie" in f["name"]]
        self.assertGreaterEqual(len(insecure_cookie_findings), 1)

    # 5 & 6: CORSModule
    @patch('api.scanner.modules.headers.safe_request')
    def test_safe_cors(self, mock_safe):
        mock_safe.return_value = MockResponse("", 200, {
            "Access-Control-Allow-Origin": "https://example.com"
        })
        mod = CORSModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        dangerous_cors = [f for f in findings if f["severity"] == "High" and "CORS" in f["name"]]
        self.assertEqual(len(dangerous_cors), 0)

    @patch('api.scanner.modules.headers.safe_request')
    def test_dangerous_cors(self, mock_safe):
        mock_safe.return_value = MockResponse("", 200, {
            "Access-Control-Allow-Origin": "*"
        })
        mod = CORSModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        dangerous_cors = [f for f in findings if f["severity"] in ["High", "Medium", "Informational"] and "CORS" in f["name"]]
        self.assertGreaterEqual(len(dangerous_cors), 1)

    # 7 & 8:  (Secrets)
    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_js_fake_secret(self, mock_safe):
        html_resp = MockResponse("<script src='/app.js'></script>", 200, {"Content-Type": "text/html"})
        js_resp = MockResponse("var k = 'AKIAIOSFODNN7EXAMPLE';", 200, {"Content-Type": "application/javascript"})
        mock_safe.side_effect = [html_resp, js_resp]
        from api.scanner.modules.javascript_security import JavaScriptSecurityModule
        mod = JavaScriptSecurityModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        exposed = [f for f in findings if f["name"] == "Hardcoded Third-Party Secret Key Exposed in JS Bundle"]
        self.assertEqual(len(exposed), 0)

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_js_real_secret(self, mock_safe):
        html_resp = MockResponse("<script src='/app.js'></script>", 200, {"Content-Type": "text/html"})
        js_resp = MockResponse("var aws_key = 'AKIA9876543210ABCDEF';", 200, {"Content-Type": "application/javascript"})
        mock_safe.side_effect = [html_resp, js_resp]
        from api.scanner.modules.javascript_security import JavaScriptSecurityModule
        mod = JavaScriptSecurityModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        exposed = [f for f in findings if "Secret Key Exposed" in f["name"]]
        self.assertEqual(len(exposed), 1)

    # 9 & 10:  (Source Maps)
    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_source_map_absent(self, mock_safe):
        def side_effect(*args, **kwargs):
            url = args[1]
            if url == "https://example.com":
                return MockResponse("<script src='/app.js'></script>", 200, {"Content-Type": "text/html"})
            if url.endswith(".map"):
                return MockResponse("Not Found", 404)
            return MockResponse("console.log('hi');", 200, {"Content-Type": "application/javascript"})
        mock_safe.side_effect = side_effect
        from api.scanner.modules.javascript_security import JavaScriptSecurityModule
        mod = JavaScriptSecurityModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        maps = [f for f in findings if f["name"] == "JavaScript Source Maps Exposed (.map)"]
        self.assertEqual(len(maps), 0)

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_source_map_present(self, mock_safe):
        def side_effect(*args, **kwargs):
            url = args[1]
            if url == "https://example.com":
                return MockResponse("<script src='/app.js'></script>", 200, {"Content-Type": "text/html"})
            if url.endswith(".map"):
                return MockResponse('{"version":3,"sources":["index.js"]}', 200)
            return MockResponse("console.log('hi'); //# sourceMappingURL=app.js.map", 200, {"Content-Type": "application/javascript"})
        mock_safe.side_effect = side_effect
        from api.scanner.modules.javascript_security import JavaScriptSecurityModule
        mod = JavaScriptSecurityModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        maps = [f for f in findings if f["name"] == "JavaScript Source Maps Exposed (.map)"]
        self.assertEqual(len(maps), 1)

    # 11 & 12: MixedContentModule
    @patch('api.scanner.modules.content.safe_request')
    def test_safe_mixed_content(self, mock_safe):
        # HEAD returns HTML, GET returns HTML
        mock_safe.return_value = MockResponse("<html><body><img src='https://secure.com/a.png'></body></html>", 200, {"Content-Type": "text/html"})
        mod = MixedContentModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        mixed = [f for f in findings if "Mixed Content" in f["name"] and f["severity"] in ["High", "Medium"]]
        self.assertEqual(len(mixed), 0)

    @patch('api.scanner.modules.content.safe_request')
    def test_mixed_content_resource(self, mock_safe):
        mock_safe.return_value = MockResponse("<html><body><img src='http://insecure.com/a.png'></body></html>", 200, {"Content-Type": "text/html"})
        mod = MixedContentModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        mixed = [f for f in findings if f["name"] == "Mixed Content Detected"]
        self.assertEqual(len(mixed), 1)

    # 13 & 14: GraphQLIntrospectionModule
    @patch('api.scanner.modules.network_checks.safe_request')
    def test_graphql_no_introspection(self, mock_safe):
        mock_safe.return_value = MockResponse('{"errors": [{"message": "Introspection disabled"}]}', 200, {"Content-Type": "application/json"})
        mod = GraphQLIntrospectionModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        introspection = [f for f in findings if "Introspection" in f["name"] and f["severity"] != "Passed"]
        self.assertEqual(len(introspection), 0)

    @patch('api.scanner.modules.network_checks.safe_request')
    def test_graphql_introspection(self, mock_safe):
        mock_safe.return_value = MockResponse('{"data": {"__schema": {"types": []}}}', 200, {"Content-Type": "application/json"})
        mod = GraphQLIntrospectionModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        introspection = [f for f in findings if "Introspection" in f["name"] and f["severity"] != "Passed"]
        self.assertEqual(len(introspection), 1)

    # 15 & 16: VerboseStackTraceModule
    @patch('api.scanner.modules.network_checks.safe_request')
    def test_debug_normal_response(self, mock_safe):
        mock_safe.return_value = MockResponse('{"error": "Not Found"}', 404, {"Content-Type": "application/json"})
        mod = VerboseStackTraceModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        verbose = [f for f in findings if "Verbose" in f["name"] and f["severity"] != "Passed"]
        self.assertEqual(len(verbose), 0)

    @patch('api.scanner.modules.network_checks.safe_request')
    def test_debug_verbose_response(self, mock_safe):
        mock_safe.return_value = MockResponse('Traceback (most recent call last): \n  File "main.py", line 1, in <module>', 500, {"Content-Type": "text/plain"})
        mod = VerboseStackTraceModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        verbose = [f for f in findings if "Verbose" in f["name"] and f["severity"] != "Passed"]
        self.assertEqual(len(verbose), 1)

if __name__ == '__main__':
    unittest.main()
