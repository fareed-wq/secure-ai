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


    @patch('api.scanner.modules.content.safe_request')
    def test_3d_a_mixed_content_identities(self, mock_safe):
        mod = MixedContentModule()

        # Test 1: Insecure resources + Insecure forms
        html_with_mixed = '''
        <html>
            <body>
                <img src='http://insecure.com/a.png'>
                <script src='http://insecure.com/b.js'></script>
                <form action='http://insecure.com/login'></form>
                <form action='http://insecure.com/submit'></form>
            </body>
        </html>
        '''
        mock_safe.return_value = MockResponse(html_with_mixed, 200, {"Content-Type": "text/html"})
        findings_mixed = mod.run("https://example.com", "example.com", self.session)

        self.assertEqual(len(findings_mixed), 2)
        rids = {f.get("rule_id") for f in findings_mixed}
        self.assertEqual(rids, {"mixed_content_detected", "mixed_content_insecure_form"})
        for f in findings_mixed:
            self.assertNotIn("instance_key", f)

        # Test 2: Clean page
        html_clean = "<html><body><img src='https://secure.com/a.png'></body></html>"
        mock_safe.return_value = MockResponse(html_clean, 200, {"Content-Type": "text/html"})
        findings_clean = mod.run("https://example.com", "example.com", self.session)

        self.assertEqual(len(findings_clean), 1)
        self.assertEqual(findings_clean[0].get("rule_id"), "mixed_content_none")
        self.assertNotIn("instance_key", findings_clean[0])


    def test_3d_b_permissions_policy_identities(self):
        import ast
        with open("api/scanner/modules/headers.py", "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())

        found_rules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "PermissionsPolicyModule":
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and getattr(child.func, "attr", "") == "make_finding":
                        has_instance_key = False
                        for kw in child.keywords:
                            if kw.arg == "rule_id" and isinstance(kw.value, ast.Constant):
                                found_rules.add(kw.value.value)
                            if kw.arg == "instance_key":
                                has_instance_key = True
                        self.assertFalse(has_instance_key, "PermissionsPolicy finding has instance_key")

        expected = {"headers_permissions_policy_missing", "headers_permissions_policy_permissive", "headers_permissions_policy_configured"}
        self.assertEqual(found_rules, expected)

    def test_3d_b_csp_quality_identities(self):
        import ast
        with open("api/scanner/modules/headers.py", "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())

        found_rules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "CSPQualityModule":
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and getattr(child.func, "attr", "") == "make_finding":
                        has_instance_key = False
                        for kw in child.keywords:
                            if kw.arg == "rule_id" and isinstance(kw.value, ast.Constant):
                                found_rules.add(kw.value.value)
                            if kw.arg == "instance_key":
                                has_instance_key = True
                        self.assertFalse(has_instance_key, "CSPQuality finding has instance_key")

        expected = {"csp_quality_weak", "csp_quality_inline_styles", "csp_quality_missing_default_src", "csp_quality_object_src_unrestricted"}
        self.assertEqual(found_rules, expected)

    def test_3d_b_advanced_security_headers_identities(self):
        import ast
        with open("api/scanner/modules/http_security.py", "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())

        found_rules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "AdvancedSecurityHeadersModule":
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and getattr(child.func, "attr", "") == "make_finding":
                        has_instance_key = False
                        for kw in child.keywords:
                            if kw.arg == "rule_id" and isinstance(kw.value, ast.Constant):
                                found_rules.add(kw.value.value)
                            if kw.arg == "instance_key":
                                has_instance_key = True
                        self.assertFalse(has_instance_key, "AdvancedSecurityHeaders finding has instance_key")

        expected = {
            "headers_coop_missing", "headers_coep_missing", "headers_corp_missing",
            "headers_corp_invalid", "headers_corp_configured",
            "headers_cross_origin_isolation_configured", "headers_advanced_check_inconclusive"
        }
        self.assertEqual(found_rules, expected)

if __name__ == '__main__':
    unittest.main()


def test_3b3a_network_checks_identities(monkeypatch):
    import requests
    from api.scanner.modules.network_checks import GraphQLIntrospectionModule, VerboseStackTraceModule
    session = requests.Session()

    # GraphQL Introspection
    module_gql = GraphQLIntrospectionModule()
    def mock_safe_request_gql(*a, **kw):
        mock_resp = requests.Response()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp._content = b'{"__schema": {}}'
        return mock_resp
    monkeypatch.setattr("api.scanner.modules.network_checks.safe_request", mock_safe_request_gql)
    findings = module_gql.run("https://example.com/graphql", "example.com", session)
    assert findings[0].get("rule_id") == "api_graphql_introspection_enabled"

    # Verbose Stack Trace
    module_st = VerboseStackTraceModule()
    def mock_safe_request_st(*a, **kw):
        mock_resp = requests.Response()
        mock_resp.status_code = 200
        mock_resp._content = b'Traceback (most recent call last):'
        return mock_resp
    monkeypatch.setattr("api.scanner.modules.network_checks.safe_request", mock_safe_request_st)
    findings = module_st.run("https://example.com/error", "example.com", session)
    assert findings[0].get("rule_id") == "api_verbose_error_messages_disclosed"
