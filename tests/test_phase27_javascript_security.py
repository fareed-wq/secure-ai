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

        idor_findings = [f for f in findings if f["name"] == "Sequential Identifier Observed in API Route"]
        self.assertEqual(len(idor_findings), 1)
        self.assertIn("/api/v1/orders/{id}", str(idor_findings[0]["evidence"]))

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_library_fingerprinting(self, mock_request):
        html_body = '<script src="/app.js"></script>'
        js_app = '/*! jQuery v3.4.1 */ window.Vue = {};'

        responses = {
            "https://example.com/": DummyResponse(200, html_body, {"Content-Type": "text/html"}),
            "https://example.com/app.js": DummyResponse(200, js_app)
        }

        import re
        self.module.FRAMEWORKS = {"Vue.js": re.compile(r'window\.Vue')}

        mock_request.side_effect = self.create_side_effect(responses)
        findings = self.module.run("https://example.com/", "example.com", self.session)

        fw_findings = [f for f in findings if f["name"] == "Client-Side Framework Detected"]
        self.assertEqual(len(fw_findings), 1)
        self.assertEqual(fw_findings[0].get("rule_id"), "technology_js_frameworks_detected")
        self.assertNotIn("instance_key", fw_findings[0])

        lib_findings = [f for f in findings if f["name"] == "Outdated Client-Side JavaScript Library Detected"]
        self.assertEqual(len(lib_findings), 1)
        self.assertIn("jQuery v3.4.1", str(lib_findings[0]["evidence"]))
        self.assertEqual(lib_findings[0].get("rule_id"), "technology_outdated_library")
        self.assertNotIn("instance_key", lib_findings[0])
        self.assertNotEqual(lib_findings[0].get("rule_id"), "technology_detected")

        self.module.FRAMEWORKS = {}

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
        self.assertIn("http://192.168.1.10:8080", evidence)
        self.assertNotIn("http://localhost:5000", evidence)

        loopback_findings = [f for f in findings if f["name"] == "Development / Localhost References in Client-Side Code"]
        self.assertEqual(len(loopback_findings), 1)
        self.assertEqual(loopback_findings[0]["severity"], "Informational")
        lb_evidence = str(loopback_findings[0]["evidence"])
        self.assertIn("http://localhost:5000", lb_evidence)
        self.assertNotIn("welcome to localhost", lb_evidence)
        self.assertNotIn("https://api.example.com", lb_evidence)

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_loopback_supabase_exclusion(self, mock_request):
        html_body = '<script src="/supabase.js"></script><script src="/app.js"></script>'
        # Test 1 & 3: SUPABASE CONTEXT (should be ignored)
        js_supabase = 'Ba=`http://localhost:9999`,Va=`supabase.auth.token`,Ha={"X-Client-Info":`gotrue-js/2.112.0`}'
        # Test 4: SAME URL WITHOUT CONTEXT (should be detected) + 2: 127.0.0.1 + 5: MULTIPLE REFERENCES
        js_app = 'const fallback = "http://localhost:9999"; const api = "http://127.0.0.1:8000/api"; const localApi = "http://localhost:3000/api";'

        responses = {
            "https://example.com/": DummyResponse(200, html_body, {"Content-Type": "text/html"}),
            "https://example.com/supabase.js": DummyResponse(200, js_supabase),
            "https://example.com/app.js": DummyResponse(200, js_app)
        }

        mock_request.side_effect = self.create_side_effect(responses)
        findings = self.module.run("https://example.com/", "example.com", self.session)

        loopback_findings = [f for f in findings if f["name"] == "Development / Localhost References in Client-Side Code"]
        self.assertEqual(len(loopback_findings), 1)

        lb_evidence = str(loopback_findings[0]["evidence"])

        # Test 1: Real app reference detected
        self.assertIn("http://localhost:3000", lb_evidence)
        # Test 2: Real 127.0.0.1 reference detected
        self.assertIn("http://127.0.0.1:8000", lb_evidence)
        # Test 4: Same URL without library context detected
        self.assertIn("http://localhost:9999", lb_evidence)

        # The library context one doesn't appear as a separate or suppressing factor for the entire thing,
        # but if we run js_supabase ALONE, it should yield NO findings.

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_loopback_supabase_exclusion_alone(self, mock_request):
        html_body = '<script src="/supabase.js"></script>'
        js_supabase = 'Ba=`http://localhost:9999`,Va=`supabase.auth.token`,Ha={"X-Client-Info":`gotrue-js/2.112.0`}'
        responses = {
            "https://example.com/": DummyResponse(200, html_body, {"Content-Type": "text/html"}),
            "https://example.com/supabase.js": DummyResponse(200, js_supabase),
        }
        mock_request.side_effect = self.create_side_effect(responses)
        findings = self.module.run("https://example.com/", "example.com", self.session)
        loopback_findings = [f for f in findings if f["name"] == "Development / Localhost References in Client-Side Code"]
        self.assertEqual(len(loopback_findings), 0)

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_loopback_supabase_exclusion_port_edge_cases(self, mock_request):
        html_body = '<script src="/supabase.js"></script>'
        # Test 3 & 4: http://localhost:19999, http://localhost:99990, and https://localhost:9999 with Supabase context (should be detected)
        js_supabase = 'Ba=`http://localhost:19999`,Ca=`http://localhost:99990`,Da=`https://localhost:9999`,Va=`supabase.auth.token`,Ha={"X-Client-Info":`gotrue-js/2.112.0`}'
        responses = {
            "https://example.com/": DummyResponse(200, html_body, {"Content-Type": "text/html"}),
            "https://example.com/supabase.js": DummyResponse(200, js_supabase),
        }
        mock_request.side_effect = self.create_side_effect(responses)
        findings = self.module.run("https://example.com/", "example.com", self.session)
        loopback_findings = [f for f in findings if f["name"] == "Development / Localhost References in Client-Side Code"]
        self.assertEqual(len(loopback_findings), 1)
        lb_evidence = str(loopback_findings[0]["evidence"])
        self.assertIn("http://localhost:19999", lb_evidence)
        # Note: http://localhost:99990 won't be matched fully by the regex if it only matches \d+, wait, \d+ matches 99990 entirely.
        self.assertIn("http://localhost:99990", lb_evidence)
        self.assertIn("https://localhost:9999", lb_evidence)

if __name__ == '__main__':
    unittest.main()



def test_3b3b_js_identities(monkeypatch):
    from api.scanner.modules.javascript_security import JavaScriptSecurityModule
    import requests
    from unittest.mock import MagicMock
    module = JavaScriptSecurityModule()

    class DummyResp:
        def __init__(self, status_code, text, url="http://example.com/app.js"):
            self.status_code = status_code
            self.text = text
            self.url = url
            self.headers = {"Content-Type": "application/javascript"}
        def iter_content(self, chunk_size):
            yield self.text.encode('utf-8')
        def close(self):
            pass

    html_body = '''
        <html><script src="/app.js"></script>
        window.__INITIAL_STATE__ = { debug: true, api: 'http://localhost' };
        </html>
    '''
    js_body = '''
        const bearer_token = "Bearer AAAAAABBBBBBCCCCCCDDDDDDEEEEEEFFFFFF";
        const gmap_key = "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhI";
        const local = "http://localhost:3000/api";
        const internal = "http://10.0.0.5/api";
        // # sourceMappingURL=app.js.map
        fetch("/api/v1/users");
        fetch("/api/v1/posts");
        fetch("/api/users/1234"); debugger;foo
        const config = { "password": "supersecret" };
        const auth = { isAdmin === true, roles: ["admin", "user"] };
        fetch("/api/admin/users");
    '''

    responses = {
        "http://example.com": DummyResp(200, html_body, "http://example.com"),
        "http://example.com/app.js": DummyResp(200, js_body, "http://example.com/app.js"),
        "http://example.com/app.js.map": DummyResp(200, '{"version": 3}', "http://example.com/app.js.map")
    }

    def side_effect(method, url, **kw):
        return responses.get(url, DummyResp(404, ""))

    monkeypatch.setattr("api.scanner.modules.javascript_security.safe_request", side_effect)

    session = MagicMock()
    findings = module.run("http://example.com", "example.com", session)

    # 14 identities
    # Exposed Frontend Environment & Debug Config...
    assert next((f for f in findings if f["name"].startswith("Exposed Frontend Environment")), None).get("rule_id") == "js_exposed_frontend_env"

    # Hardcoded Third-Party Secret Key Exposed...
    secret_finding = next((f for f in findings if f["name"].startswith("Hardcoded Third-Party Secret")), None)
    assert secret_finding.get("rule_id") == "js_hardcoded_secret_key"
    assert "instance_key" not in secret_finding
    assert "AAAAAABBBBBBCCCCCCDDDDDDEEEEEEFFFFFF" not in secret_finding.get("instance_key", "")
    assert "AAAAAABBBBBBCCCCCCDDDDDDEEEEEEFFFFFF" not in secret_finding.get("rule_id", "")

    # Client-Side API Key Detected
    api_key_finding = next((f for f in findings if f["name"].startswith("Client-Side API Key Detected")), None)
    assert api_key_finding.get("rule_id") == "js_client_side_api_key"
    assert "instance_key" not in api_key_finding
    assert "AIzaSy" not in api_key_finding.get("rule_id", "")

    # Development / Localhost References
    assert next((f for f in findings if f["name"].startswith("Development / Localhost")), None).get("rule_id") == "js_localhost_references"

    # Internal Infrastructure References
    assert next((f for f in findings if f["name"].startswith("Internal Infrastructure")), None).get("rule_id") == "js_internal_infra_references"

    # Client-Side Development Artifacts
    assert next((f for f in findings if f["name"].startswith("Client-Side Development Artifacts")), None).get("rule_id") == "js_development_artifacts"

    # Client-Side API Endpoints Discovered
    endpoint_finding = next((f for f in findings if f["name"] == "Client-Side API Endpoints Discovered"), None)
    assert endpoint_finding.get("rule_id") == "js_api_endpoints_discovered"
    assert "instance_key" not in endpoint_finding
    assert "4 API endpoints discovered" in str(endpoint_finding["evidence"]) or "/api/v1/users" in str(endpoint_finding["evidence"])

    # Sequential Identifier
    assert next((f for f in findings if f["name"].startswith("Sequential Identifier")), None).get("rule_id") == "js_sequential_identifier_observed"

    # Sensitive Client-Side Configuration
    assert next((f for f in findings if f["name"].startswith("Sensitive Client-Side Configuration")), None).get("rule_id") == "js_sensitive_config_reference"

    # Source Maps Exposed
    assert next((f for f in findings if f["name"].startswith("JavaScript Source Maps")), None).get("rule_id") == "js_source_maps_exposed"

    # Privileged Auth Logic
    assert next((f for f in findings if f["name"].startswith("Privileged Client-Side Auth")), None).get("rule_id") == "js_privileged_auth_logic"

    # Auth Roles / Permissions Disclosed
    assert next((f for f in findings if f["name"].startswith("Authorization Roles / Permissions Disclosed")), None).get("rule_id") == "js_auth_roles_disclosed"

    # Privileged API Surface
    assert next((f for f in findings if f["name"].startswith("Privileged API Surface")), None).get("rule_id") == "js_privileged_api_surface"

    # Versioned API Surface
    assert next((f for f in findings if f["name"].startswith("Versioned API Surface")), None).get("rule_id") == "js_versioned_api_surface"

    # Check 3B-1 identities remained untouched and function properly (add to js_body if needed)
    # They should not be removed from the class
