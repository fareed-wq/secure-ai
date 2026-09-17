import unittest
from unittest.mock import patch, MagicMock
import requests

from api.scanner.core import ModuleResult, AssessmentOutcome
from api.scanner.modules.dns import DNSEmailSecurityModule
from api.scanner.modules.auth_session_security import AuthenticationSessionSecurityModule
from api.scanner.modules.javascript_security import JavaScriptSecurityModule

class TestPhase1B6Outcomes(unittest.TestCase):
    def setUp(self):
        self.session = requests.Session()
        self.url = "https://example.com"
        self.hostname = "example.com"

    def mock_response(self, status_code=200, text="", headers=None, url="https://example.com", json_data=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.headers = headers or {}
        resp.url = url
        resp.history = []
        if json_data is not None:
            resp.json.return_value = json_data
        return resp

    # --- DNSEmailSecurityModule ---
    @patch('api.scanner.modules.dns.query_doh')
    def test_dns_email_completed(self, mock_doh):
        mock_doh.return_value = {"Status": 0, "Answer": [{"data": "v=spf1 -all"}]}
        module = DNSEmailSecurityModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.dns.query_doh')
    def test_dns_email_partial(self, mock_doh):
        # Fail the first call, succeed the others
        def side_effect(domain, type_str, session):
            if type_str == "MX":
                return None
            return {"Status": 0}
        mock_doh.side_effect = side_effect
        module = DNSEmailSecurityModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.PARTIAL)

    @patch('api.scanner.modules.dns.query_doh')
    def test_dns_email_failed(self, mock_doh):
        mock_doh.return_value = None
        module = DNSEmailSecurityModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    # --- AuthenticationSessionSecurityModule ---
    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_auth_completed(self, mock_req):
        mock_req.return_value = self.mock_response(text="<form></form>")
        module = AuthenticationSessionSecurityModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_auth_failed(self, mock_req):
        mock_req.return_value = None
        module = AuthenticationSessionSecurityModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    @patch.object(AuthenticationSessionSecurityModule, 'extract_forms')
    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_auth_parse_exception(self, mock_req, mock_extract):
        mock_req.return_value = self.mock_response(text="<form></form>")
        mock_extract.side_effect = Exception("Internal parse error")
        module = AuthenticationSessionSecurityModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    # --- JavaScriptSecurityModule ---
    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_js_completed(self, mock_req):
        mock_req.return_value = self.mock_response(text="<html></html>")
        module = JavaScriptSecurityModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_js_partial(self, mock_req):
        # 1 HTML + 1 JS
        def side_effect(*args, **kwargs):
            if args[1] == "https://example.com":
                return self.mock_response(text="<script src='test.js'></script>")
            return None # JS fails
        mock_req.side_effect = side_effect
        module = JavaScriptSecurityModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.PARTIAL)

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_js_failed(self, mock_req):
        mock_req.return_value = None
        module = JavaScriptSecurityModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)


if __name__ == '__main__':
    unittest.main()

    # --- PassiveSubdomainDiscoveryModule ---
    @patch('api.scanner.modules.network_checks.safe_request')
    def test_passive_subdomain_completed_non_empty(self, mock_req):
        mock_req.return_value = self.mock_response(status_code=200, json_data=[{"name_value": "api.example.com"}])
        from api.scanner.modules.network_checks import PassiveSubdomainDiscoveryModule
        module = PassiveSubdomainDiscoveryModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.network_checks.safe_request')
    def test_passive_subdomain_completed_empty(self, mock_req):
        mock_req.return_value = self.mock_response(status_code=200, json_data=[])
        from api.scanner.modules.network_checks import PassiveSubdomainDiscoveryModule
        module = PassiveSubdomainDiscoveryModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.network_checks.safe_request')
    def test_passive_subdomain_failed_none(self, mock_req):
        mock_req.return_value = None
        from api.scanner.modules.network_checks import PassiveSubdomainDiscoveryModule
        module = PassiveSubdomainDiscoveryModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    @patch('api.scanner.modules.network_checks.safe_request')
    def test_passive_subdomain_failed_http_error(self, mock_req):
        mock_req.return_value = self.mock_response(status_code=500, json_data={"error": "failed"})
        from api.scanner.modules.network_checks import PassiveSubdomainDiscoveryModule
        module = PassiveSubdomainDiscoveryModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    @patch('api.scanner.modules.network_checks.safe_request')
    def test_passive_subdomain_parse_failure(self, mock_req):
        mock_resp = self.mock_response(status_code=200)
        mock_resp.json.side_effect = Exception("JSON parse error")
        mock_req.return_value = mock_resp
        from api.scanner.modules.network_checks import PassiveSubdomainDiscoveryModule
        module = PassiveSubdomainDiscoveryModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)
