import unittest
from unittest.mock import patch, MagicMock
from api.scanner.modules.discovery import (
    OpenApiModule,
    GraphqlIdeModule,
    ActuatorModule,
    XmlRpcModule,
    ExposedFilesModule,
    RobotsTxtModule
)

class DummyResponse:
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    def json(self):
        import json
        return json.loads(self.text)

    def iter_content(self, chunk_size=1024):
        yield self.text.encode('utf-8')

    def close(self):
        pass

class TestPhase26ApiWebExpansion(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock()

    def create_side_effect(self, target_path, target_response):
        def side_effect(method, url, **kwargs):
            from urllib.parse import urlparse
            path = urlparse(url).path
            if path == "" or path == "/":
                return DummyResponse(200, "<html>Homepage of length 1000... " + "x" * 900 + "</html>", {"Content-Type": "text/html"})
            if path == target_path:
                return target_response
            return DummyResponse(404, "Not Found", {"Content-Type": "text/html"})
        return side_effect

    @patch('api.scanner.modules.discovery.safe_request')
    def test_openapi_detection_valid(self, mock_request):
        mock_request.side_effect = self.create_side_effect("/openapi.json", DummyResponse(200, '{"openapi": "3.0.0"}', {"Content-Type": "application/json"}))
        mod = OpenApiModule()
        findings = mod.run("https://example.com/openapi.json", "example.com", self.session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "Public OpenAPI / Swagger Specification Exposed")
        self.assertEqual(findings[0]["severity"], "Informational")
        self.assertEqual(findings[0]["confidence"], "High")

    @patch('api.scanner.modules.discovery.safe_request')
    def test_openapi_detection_invalid(self, mock_request):
        mock_request.side_effect = self.create_side_effect("/openapi.json", DummyResponse(200, '{"error": "not found"}', {"Content-Type": "application/json"}))
        mod = OpenApiModule()
        findings = mod.run("https://example.com/graphiql", "example.com", self.session)
        self.assertEqual(len(findings), 0)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_graphql_ide_detection(self, mock_request):
        mock_request.side_effect = self.create_side_effect("/graphiql", DummyResponse(200, '<html><head><title>GraphiQL</title></head><body></body></html>', {"Content-Type": "text/html"}))
        mod = GraphqlIdeModule()
        findings = mod.run("https://example.com/graphiql", "example.com", self.session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "Interactive GraphQL Developer IDE Exposed")

    @patch('api.scanner.modules.discovery.safe_request')
    def test_actuator_health(self, mock_request):
        mock_request.side_effect = self.create_side_effect("/actuator/health", DummyResponse(200, '{"status": "UP"}', {"Content-Type": "application/json"}))
        mod = ActuatorModule()
        findings = mod.run("https://example.com/actuator/health", "example.com", self.session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Informational")
        self.assertEqual(findings[0]["name"], "Spring Boot Actuator Endpoint Exposed")

    @patch('api.scanner.modules.discovery.safe_request')
    def test_actuator_sensitive_env(self, mock_request):
        mock_request.side_effect = self.create_side_effect("/actuator/env", DummyResponse(200, '{"propertySources": []}', {"Content-Type": "application/json"}))
        mod = ActuatorModule()
        findings = mod.run("https://example.com/actuator/env", "example.com", self.session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "High")
        self.assertEqual(findings[0]["name"], "Sensitive Spring Boot Actuator Config Exposed")

    @patch('api.scanner.modules.discovery.safe_request')
    def test_git_head_valid(self, mock_request):
        mock_request.side_effect = self.create_side_effect("/.git/HEAD", DummyResponse(200, 'ref: refs/heads/main', {"Content-Type": "text/plain"}))
        mod = ExposedFilesModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        git_findings = [f for f in findings if f["name"] == "Exposed .git Repository"]
        self.assertEqual(len(git_findings), 1)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_git_head_invalid(self, mock_request):
        mock_request.side_effect = self.create_side_effect("/.git/HEAD", DummyResponse(200, '<html>generic page</html>', {"Content-Type": "text/html"}))
        mod = ExposedFilesModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        git_findings = [f for f in findings if f["name"] == "Exposed .git Repository"]
        self.assertEqual(len(git_findings), 0)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_env_detection_valid(self, mock_request):
        mock_request.side_effect = self.create_side_effect("/.env", DummyResponse(200, 'APP_ENV=production\nDATABASE_URL=mysql://...', {"Content-Type": "text/plain"}))
        mod = ExposedFilesModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        env_findings = [f for f in findings if f["name"] == "Exposed .env Configuration File"]
        self.assertEqual(len(env_findings), 1)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_phpinfo_valid(self, mock_request):
        mock_request.side_effect = self.create_side_effect("/phpinfo.php", DummyResponse(200, '<title>phpinfo()</title>', {"Content-Type": "text/html"}))
        mod = ExposedFilesModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        php_findings = [f for f in findings if f["name"] == "Exposed phpinfo() File"]
        self.assertEqual(len(php_findings), 1)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_robots_noise_filtering(self, mock_request):
        mock_request.side_effect = self.create_side_effect("/robots.txt", DummyResponse(200, 'User-agent: *\nDisallow: /wp-admin\nDisallow: /internal\nAllow: /dev/api', {"Content-Type": "text/plain"}))
        mod = RobotsTxtModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        robots_internal = [f for f in findings if f["name"] == "Internal Paths Disclosed in Robots.txt"]
        self.assertEqual(len(robots_internal), 1)
        self.assertIn("/internal", str(robots_internal[0]["evidence"]))
        self.assertIn("/dev", str(robots_internal[0]["evidence"]))

    @patch('api.scanner.modules.discovery.safe_request')
    def test_xmlrpc_detection(self, mock_request):
        mock_request.side_effect = self.create_side_effect("/xmlrpc.php", DummyResponse(405, 'XML-RPC server accepts POST requests only', {"Content-Type": "text/plain"}))
        mod = XmlRpcModule()
        findings = mod.run("https://example.com/xmlrpc.php", "example.com", self.session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "Legacy XML-RPC Endpoint Exposed")


    @patch('api.scanner.modules.discovery.safe_request')
    def test_actuator_generic_json_ignored(self, mock_request):
        mock_request.side_effect = self.create_side_effect("/api/public-json", DummyResponse(200, '{"status": "ok", "service": "public-demo"}', {"Content-Type": "application/json"}))
        mod = ActuatorModule()
        findings = mod.run("https://example.com/api/public-json", "example.com", self.session)
        self.assertEqual(len(findings), 0)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_openapi_global_security(self, mock_request):
        json_payload = '{"openapi": "3.0.0", "security": [{"ApiKeyAuth": []}], "paths": {"/admin": {"get": {}}}}'
        mock_request.side_effect = self.create_side_effect("/openapi.json", DummyResponse(200, json_payload, {"Content-Type": "application/json"}))
        mod = OpenApiModule()
        findings = mod.run("https://example.com/openapi.json", "example.com", self.session)
        names = [f["name"] for f in findings]
        self.assertNotIn("Privileged API Operation Documented Without Security Requirement", names)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_openapi_no_global_security(self, mock_request):
        json_payload = '{"openapi": "3.0.0", "paths": {"/admin": {"get": {}}}}'
        mock_request.side_effect = self.create_side_effect("/openapi.json", DummyResponse(200, json_payload, {"Content-Type": "application/json"}))
        mod = OpenApiModule()
        findings = mod.run("https://example.com/openapi.json", "example.com", self.session)
        names = [f["name"] for f in findings]
        self.assertIn("Privileged API Operation Documented Without Security Requirement", names)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_openapi_override_global_security(self, mock_request):
        json_payload = '{"openapi": "3.0.0", "security": [{"ApiKeyAuth": []}], "paths": {"/admin": {"get": {"security": []}}}}'
        mock_request.side_effect = self.create_side_effect("/openapi.json", DummyResponse(200, json_payload, {"Content-Type": "application/json"}))
        mod = OpenApiModule()
        findings = mod.run("https://example.com/openapi.json", "example.com", self.session)
        names = [f["name"] for f in findings]
        self.assertIn("Privileged API Operation Documented Without Security Requirement", names)


    @patch('api.scanner.modules.discovery.safe_request')
    def test_actuator_health_negative_paths(self, mock_request):
        # /api/health -> NO Actuator finding
        mock_request.side_effect = self.create_side_effect("/api/health", DummyResponse(200, '{"status": "UP"}', {"Content-Type": "application/json"}))
        mod = ActuatorModule()
        findings = mod.run("https://example.com/api/health", "example.com", self.session)
        self.assertEqual(len(findings), 0)

        # /health -> NO Actuator finding
        mock_request.side_effect = self.create_side_effect("/health", DummyResponse(200, '{"status": "ok"}', {"Content-Type": "application/json"}))
        findings = mod.run("https://example.com/health", "example.com", self.session)
        self.assertEqual(len(findings), 0)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_actuator_health_positive(self, mock_request):
        # /actuator/health -> Spring Boot Actuator Endpoint Exposed (Informational)
        mock_request.side_effect = self.create_side_effect("/actuator/health", DummyResponse(200, '{"status": "UP"}', {"Content-Type": "application/json"}))
        mod = ActuatorModule()
        findings = mod.run("https://example.com/actuator/health", "example.com", self.session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "Spring Boot Actuator Endpoint Exposed")
        self.assertEqual(findings[0]["severity"], "Informational")

    @patch('api.scanner.modules.discovery.safe_request')
    def test_actuator_env_high(self, mock_request):
        # /actuator/env with propertySources -> High
        mock_request.side_effect = self.create_side_effect("/actuator/env", DummyResponse(200, '{"propertySources": []}', {"Content-Type": "application/json"}))
        mod = ActuatorModule()
        findings = mod.run("https://example.com/actuator/env", "example.com", self.session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "Sensitive Spring Boot Actuator Config Exposed")
        self.assertEqual(findings[0]["severity"], "High")

    @patch('api.scanner.modules.discovery.safe_request')
    def test_actuator_env_info_only(self, mock_request):
        # /actuator/env with activeProfiles ONLY -> Informational
        mock_request.side_effect = self.create_side_effect("/actuator/env", DummyResponse(200, '{"activeProfiles": ["prod"]}', {"Content-Type": "application/json"}))
        mod = ActuatorModule()
        findings = mod.run("https://example.com/actuator/env", "example.com", self.session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "Spring Boot Actuator Endpoint Exposed")
        self.assertEqual(findings[0]["severity"], "Informational")

if __name__ == '__main__':
    unittest.main()


def test_3b3a_openapi_actuator_identities(monkeypatch):
    import requests
    from api.scanner.modules.discovery import OpenApiModule, GraphqlIdeModule, ActuatorModule, XmlRpcModule
    session = requests.Session()

    # 1. OpenAPI
    module = OpenApiModule()
    def mock_safe_request_openapi(*a, **kw):
        mock_resp = requests.Response()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp._content = b'{"openapi": "3.0.0", "info": {"version": "1.0"}, "components": {"securitySchemes": {"x": {}}}, "paths": {"/admin": {"get": {}}, "/v1/user": {"get": {"security": []}}}}'
        return mock_resp
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", mock_safe_request_openapi)
    findings = module.run("https://example.com", "example.com", session)

    assert next((f for f in findings if f["name"] == "Public OpenAPI / Swagger Specification Exposed"), None).get("rule_id") == "api_openapi_exposed"
    assert next((f for f in findings if f["name"] == "API Authorization Scheme Disclosed"), None).get("rule_id") == "api_openapi_auth_scheme_disclosed"
    assert next((f for f in findings if f["name"] == "Privileged API Routes Publicly Documented"), None).get("rule_id") == "api_openapi_privileged_routes"
    assert next((f for f in findings if f["name"] == "Privileged API Operation Documented Without Security Requirement"), None).get("rule_id") == "api_openapi_unprotected_privileged_routes"
    assert next((f for f in findings if f["name"] == "Versioned API Surface Discovered"), None).get("rule_id") == "api_openapi_versioned_surface"

    # 2. GraphQL IDE
    module_gql = GraphqlIdeModule()
    def mock_safe_request_gqlide(*a, **kw):
        mock_resp = requests.Response()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp._content = b'graphiql'
        return mock_resp
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", mock_safe_request_gqlide)
    findings = module_gql.run("https://example.com", "example.com", session)
    assert findings[0].get("rule_id") == "api_graphql_ide_exposed"

    # 3. Actuator Sensitive
    module_act = ActuatorModule()
    def mock_safe_request_act_sens(*a, **kw):
        mock_resp = requests.Response()
        mock_resp.status_code = 200
        mock_resp.url = "https://example.com/actuator/env"
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp._content = b'{"propertySources": []}'
        return mock_resp
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", mock_safe_request_act_sens)
    findings = module_act.run("https://example.com/actuator/env", "example.com", session)
    assert findings[0].get("rule_id") == "api_actuator_sensitive_exposed"

    # 4. Actuator Base
    def mock_safe_request_act_base(*a, **kw):
        mock_resp = requests.Response()
        mock_resp.status_code = 200
        mock_resp.url = "https://example.com/actuator"
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp._content = b'{"_links": {}}'
        return mock_resp
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", mock_safe_request_act_base)
    findings = module_act.run("https://example.com/actuator", "example.com", session)
    assert findings[0].get("rule_id") == "api_actuator_endpoint_exposed"

    # 5. XML-RPC
    module_xml = XmlRpcModule()
    def mock_safe_request_xml(*a, **kw):
        from unittest.mock import MagicMock
        mock_resp = MagicMock()
        mock_resp.status_code = 405
        mock_resp.text = 'XML-RPC server accepts POST requests only'
        return mock_resp
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", mock_safe_request_xml)
    findings = module_xml.run("https://example.com/xmlrpc.php", "example.com", session)
    assert findings[0].get("rule_id") == "api_xmlrpc_exposed"
