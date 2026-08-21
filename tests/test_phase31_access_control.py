import unittest
import requests
import json
import logging
from unittest.mock import MagicMock, patch
from api.scanner.modules.javascript_security import JavaScriptSecurityModule
from api.scanner.modules.discovery import OpenApiModule, RobotsTxtModule
from api.scanner.modules.auth_session_security import AuthenticationSessionSecurityModule
from api.scanner.orchestrator import scan_url

class TestPhase31AccessControl(unittest.TestCase):

    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)
        self.session = requests.Session()

    @patch('requests.Session.request')
    def test_javascript_auth_logic_and_roles(self, mock_request):
        module = JavaScriptSecurityModule()
        
        # Mock HTML containing JS link
        html_resp = MagicMock()
        html_resp.text = '<html><body><script src="/app.js"></script></body></html>'
        html_resp.status_code = 200
        html_resp.headers = {"Content-Type": "text/html"}
        
        js_resp = MagicMock()
        js_resp.status_code = 200
        js_resp.headers = {"Content-Type": "application/javascript"}
        js_resp.text = '''
            const userRole = "admin";
            if (isAdmin === true) { showDashboard(); }
            const config = { roles: ["admin", "editor", "viewer"] };
            fetch('/api/v2/admin/users');
            fetch('/api/admin/users');
        '''
        js_resp.iter_content.return_value = [js_resp.text.encode('utf-8')]
        
        def mock_req(*args, **kwargs):
            url = args[1] if len(args) > 1 else kwargs.get('url', '')
            if url.endswith(".js"): return js_resp
            return html_resp
            
        mock_request.side_effect = mock_req
        
        findings = module.run("https://example.com", "example.com", self.session)
        finding_names = [f["name"] for f in findings]
        print("JS FINDINGS:", finding_names)
        self.assertIn("Privileged Client-Side Authorization Logic Disclosed", finding_names)
        self.assertIn("Authorization Roles / Permissions Disclosed", finding_names)
        self.assertIn("Privileged API Surface Discovered in Client-Side Code", finding_names)
        self.assertIn("Versioned API Surface Discovered", finding_names)

    @patch('requests.Session.request')
    def test_openapi_auth_schemes_and_unprotected_ops(self, mock_request):
        module = OpenApiModule()
        
        swagger_data = {
            "openapi": "3.0.0",
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer"
                    }
                }
            },
            "paths": {
                "/api/v1/admin/users": {
                    "get": {
                        "security": []
                    }
                }
            }
        }
        
        json_resp = MagicMock()
        json_resp.status_code = 200
        json_resp.headers = {"Content-Type": "application/json"}
        json_resp.json.return_value = swagger_data
        
        def mock_req(*args, **kwargs):
            return json_resp
            
        mock_request.side_effect = mock_req
        
        findings = module.run("https://example.com", "example.com", self.session)
        
        finding_names = [f["name"] for f in findings]
        self.assertIn("Public OpenAPI / Swagger Specification Exposed", finding_names)
        self.assertIn("API Authorization Scheme Disclosed", finding_names)
        self.assertIn("Privileged API Routes Publicly Documented", finding_names)
        self.assertIn("Potentially Unprotected Privileged API Operation", finding_names)
        self.assertIn("Versioned API Surface Discovered", finding_names)

    @patch('requests.Session.request')
    def test_robotstxt_privileged_surface(self, mock_request):
        module = RobotsTxtModule()
        
        txt_resp = MagicMock()
        txt_resp.status_code = 200
        txt_resp.headers = {"Content-Type": "text/plain"}
        txt_resp.text = "User-agent: *\nDisallow: /admin\nDisallow: /dashboard"
        
        hp_resp = MagicMock()
        hp_resp.status_code = 200
        hp_resp.headers = {"Content-Type": "text/html"}
        hp_resp.text = "<html><body>Home</body></html>" * 10
        
        def mock_req(*args, **kwargs):
            url = args[1] if len(args) > 1 else kwargs.get('url', '')
            if url.endswith("robots.txt"):
                return txt_resp
            return hp_resp
            
        mock_request.side_effect = mock_req
        
        findings = module.run("https://example.com", "example.com", self.session)
        
        finding_names = [f["name"] for f in findings]
        self.assertIn("Privileged / Administrative Surface Discovered", finding_names)

    @patch('requests.Session.request')
    def test_html_privileged_surface(self, mock_request):
        module = AuthenticationSessionSecurityModule()
        
        html_resp = MagicMock()
        html_resp.status_code = 200
        html_resp.headers = {"Content-Type": "text/html"}
        html_resp.text = '<html><body><a href="/admin/login">Admin</a><form action="/dashboard/submit" method="POST"></form></body></html>'
        
        def mock_req(*args, **kwargs):
            return html_resp
            
        mock_request.side_effect = mock_req
        
        findings = module.run("https://example.com", "example.com", self.session)
        
        finding_names = [f["name"] for f in findings]
        self.assertIn("Privileged / Administrative Surface Discovered", finding_names)

if __name__ == '__main__':
    unittest.main()
