import unittest
from unittest.mock import patch, MagicMock
from api.scanner.modules.javascript_security import JavaScriptSecurityModule

class DummyResponse:
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    def iter_content(self, chunk_size=1024):
        # yields the string encoded, mimicking requests.Response.iter_content
        yield self.text.encode('utf-8')
        
    def close(self):
        pass

class TestJavaScriptSecurityModule(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock()
        self.module = JavaScriptSecurityModule()

    def create_side_effect(self, responses):
        """
        responses: dict mapping url -> DummyResponse
        """
        def side_effect(method, url, **kwargs):
            if url in responses:
                return responses[url]
            return DummyResponse(404, "Not Found")
        return side_effect

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_javascript_bundle_extraction_and_secret(self, mock_request):
        html_body = '''
        <html>
            <head>
                <script src="/static/js/main.js"></script>
                <script src="https://example.com/static/js/app.js"></script>
                <script src="https://external.com/analytics.js"></script> <!-- Should be ignored -->
            </head>
        </html>
        '''
        
        js_main = 'var key = "AKIAIOSFODNN7EXAMPLE"; var realKey = "AKIAABCDEFGHIJKLMNOP";'
        js_app = 'console.log("no secrets here");'
        
        responses = {
            "https://example.com/": DummyResponse(200, html_body, {"Content-Type": "text/html"}),
            "https://example.com/static/js/main.js": DummyResponse(200, js_main),
            "https://example.com/static/js/app.js": DummyResponse(200, js_app)
        }
        
        mock_request.side_effect = self.create_side_effect(responses)
        findings = self.module.run("https://example.com/", "example.com", self.session)
        
        secret_findings = [f for f in findings if f["name"] == "Hardcoded Third-Party Secret Key Exposed in JS Bundle"]
        self.assertEqual(len(secret_findings), 1)
        
        # Test masking and extraction
        evidence = str(secret_findings[0]["evidence"])
        self.assertIn("AKIA******MNOP", evidence)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", evidence)
        
        # The EXAMPLE key should be ignored
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", evidence)

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_source_map_detection_and_sensitive_content(self, mock_request):
        html_body = '<script src="/app.js"></script>'
        js_app = '//# sourceMappingURL=app.js.map'
        
        map_content = '{"version":3,"sources":["index.js"],"sourcesContent":["const db = \'postgresql://user:password@localhost/db\'; const stripe = \'sk_live_abcdef0987654321xyzxyz\';"]}'
        
        responses = {
            "https://example.com/": DummyResponse(200, html_body, {"Content-Type": "text/html"}),
            "https://example.com/app.js": DummyResponse(200, js_app),
            "https://example.com/app.js.map": DummyResponse(200, map_content)
        }
        
        mock_request.side_effect = self.create_side_effect(responses)
        findings = self.module.run("https://example.com/", "example.com", self.session)
        
        sm_findings = [f for f in findings if f["name"] == "JavaScript Source Maps Exposed (.map)"]
        self.assertEqual(len(sm_findings), 1)
        
        secret_findings = [f for f in findings if f["name"] == "Hardcoded Third-Party Secret Key Exposed in JS Bundle"]
        self.assertEqual(len(secret_findings), 1)
        self.assertIn("sk_l******zxyz", str(secret_findings[0]["evidence"]))

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_api_endpoints_and_idor(self, mock_request):
        html_body = '<script src="/app.js"></script>'
        js_app = 'fetch("/api/v1/users"); fetch("/api/v1/orders/{id}"); fetch("https://api.example.com/data");'
        
        responses = {
            "https://example.com/": DummyResponse(200, html_body, {"Content-Type": "text/html"}),
            "https://example.com/app.js": DummyResponse(200, js_app)
        }
        
        mock_request.side_effect = self.create_side_effect(responses)
        findings = self.module.run("https://example.com/", "example.com", self.session)
        
        api_findings = [f for f in findings if f["name"] == "Client-Side API Endpoints Discovered"]
        self.assertEqual(len(api_findings), 1)
        self.assertIn("/api/v1/users", str(api_findings[0]["evidence"]))
        self.assertIn("https://api.example.com/data", str(api_findings[0]["evidence"]))
        
        idor_findings = [f for f in findings if f["name"] == "Sequential Object Identifiers Detected in API Routes (IDOR Risk)"]
        self.assertEqual(len(idor_findings), 1)
        self.assertIn("/api/v1/orders/{id}", str(idor_findings[0]["evidence"]))

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_library_fingerprinting(self, mock_request):
        html_body = '<script src="/app.js"></script>'
        js_app = '/*! jQuery v3.4.1 */ Vue.component("app", {});'
        
        responses = {
            "https://example.com/": DummyResponse(200, html_body, {"Content-Type": "text/html"}),
            "https://example.com/app.js": DummyResponse(200, js_app)
        }
        
        mock_request.side_effect = self.create_side_effect(responses)
        findings = self.module.run("https://example.com/", "example.com", self.session)
        
        fw_findings = [f for f in findings if f["name"] == "Client-Side Framework Detected"]
        self.assertEqual(len(fw_findings), 0)
        
        lib_findings = [f for f in findings if f["name"] == "Outdated Client-Side JavaScript Library Detected"]
        self.assertEqual(len(lib_findings), 1)
        self.assertIn("jQuery v3.4.1", str(lib_findings[0]["evidence"]))

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_frontend_config(self, mock_request):
        html_body = '<script>window.__CONFIG__ = { debug: true, environment: "development", api: "https://staging.example.com" };</script>'
        
        responses = {
            "https://example.com/": DummyResponse(200, html_body, {"Content-Type": "text/html"}),
        }
        
        mock_request.side_effect = self.create_side_effect(responses)
        findings = self.module.run("https://example.com/", "example.com", self.session)
        
        config_findings = [f for f in findings if f["name"] == "Exposed Frontend Environment & Debug Configuration"]
        self.assertEqual(len(config_findings), 1)

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_internal_infrastructure_references(self, mock_request):
        html_body = '<script src="/app.js"></script>'
        js_app = 'const devApi = "http://localhost:5000/api"; const localDb = "http://192.168.1.10:8080"; const msg = "welcome to localhost"; const publicApi = "https://api.example.com";'
        
        responses = {
            "https://example.com/": DummyResponse(200, html_body, {"Content-Type": "text/html"}),
            "https://example.com/app.js": DummyResponse(200, js_app)
        }
        
        mock_request.side_effect = self.create_side_effect(responses)
        findings = self.module.run("https://example.com/", "example.com", self.session)
        
        infra_findings = [f for f in findings if f["name"] == "Internal Infrastructure References Disclosed in Client-Side Code"]
        self.assertEqual(len(infra_findings), 1)
        self.assertEqual(infra_findings[0]["severity"], "Low")
        evidence = str(infra_findings[0]["evidence"])
        self.assertIn("http://localhost:5000", evidence)
        self.assertIn("http://192.168.1.10:8080", evidence)
        self.assertNotIn("welcome to localhost", evidence)
        self.assertNotIn("https://api.example.com", evidence)

if __name__ == '__main__':
    unittest.main()
