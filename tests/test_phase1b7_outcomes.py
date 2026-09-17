import unittest
from unittest.mock import patch, MagicMock
from api.scanner.core import ModuleResult, AssessmentOutcome
from api.scanner.modules.dns import DNSEmailSecurityModule
from api.scanner.modules.javascript_security import JavaScriptSecurityModule
from api.scanner.modules.auth_session_security import AuthenticationSessionSecurityModule
from api.scanner.modules.network_checks import PassiveSubdomainDiscoveryModule, SubdomainTakeoverModule, SubdomainProbingModule
from api.scanner.modules.content import MixedContentModule
import requests

class TestPhase1B7Outcomes(unittest.TestCase):
    def setUp(self):
        self.url = "https://example.com"
        self.hostname = "example.com"
        self.session = requests.Session()

    def mock_response(self, status_code=200, text="", json_data=None, headers=None):
        resp = MagicMock(spec=requests.Response)
        resp.status_code = status_code
        resp.text = text
        resp.headers = headers or {}
        if json_data is not None:
            resp.json.return_value = json_data
        resp.__bool__ = lambda self: status_code < 400
        return resp

    # DNSEmailSecurityModule
    @patch('api.scanner.modules.dns.query_doh')
    def test_dns_all_failed(self, mock_doh):
        mock_doh.return_value = None
        module = DNSEmailSecurityModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.FAILED)
        self.assertEqual(result.assessment_progress, {"attempted": 3, "completed": 0, "failed": 3})

    @patch('api.scanner.modules.dns.query_doh')
    def test_dns_mixed(self, mock_doh):
        def side_effect(name, type_str, session):
            if type_str == "MX": return {"Status": 0, "Answer": []}
            return None
        mock_doh.side_effect = side_effect
        module = DNSEmailSecurityModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.PARTIAL)
        self.assertEqual(result.assessment_progress, {"attempted": 3, "completed": 1, "failed": 2})

    # JavaScriptSecurityModule
    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_js_all_failed(self, mock_req):
        mock_req.return_value = None
        module = JavaScriptSecurityModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.FAILED)

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_js_mixed(self, mock_req):
        def side_effect(*args, **kwargs):
            if args[1] == "https://example.com":
                return self.mock_response(text="<script src='test.js'></script>")
            return None
        mock_req.side_effect = side_effect
        module = JavaScriptSecurityModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.PARTIAL)
        self.assertIn("attempted", result.assessment_progress)

    # AuthenticationSessionSecurityModule
    @patch.object(AuthenticationSessionSecurityModule, 'extract_forms')
    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_auth_internal_failure(self, mock_req, mock_extract):
        mock_req.return_value = self.mock_response(text="<form></form>")
        mock_extract.side_effect = Exception("Internal error")
        module = AuthenticationSessionSecurityModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.FAILED)

    # PassiveSubdomainDiscoveryModule
    @patch('api.scanner.modules.network_checks.safe_request')
    def test_passive_discovery_failure(self, mock_req):
        mock_req.return_value = None
        module = PassiveSubdomainDiscoveryModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.FAILED)

    # SubdomainTakeoverModule
    @patch('api.scanner.modules.network_checks.safe_request')
    def test_subdomain_takeover_failure(self, mock_req):
        mock_req.return_value = None
        module = SubdomainTakeoverModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.FAILED)

    # MixedContentModule
    @patch('api.scanner.modules.content.safe_request')
    def test_mixed_content_http(self, mock_req):
        module = MixedContentModule()
        result = module.run("http://example.com", self.hostname, self.session)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.NOT_APPLICABLE)

    @patch('api.scanner.modules.content.safe_request')
    def test_mixed_content_api(self, mock_req):
        mock_req.return_value = self.mock_response(text="{}", headers={"Content-Type": "application/json"})
        module = MixedContentModule()
        result = module.run("https://api.example.com", "api.example.com", self.session)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.NOT_APPLICABLE)

    @patch('api.scanner.modules.content.safe_request')
    def test_mixed_content_failure(self, mock_req):
        mock_req.return_value = None
        module = MixedContentModule()
        result = module.run("https://example.com", self.hostname, self.session)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.FAILED)

    # SubdomainProbingModule
    @patch('api.scanner.modules.network_checks.safe_request')
    def test_subdomain_probing_all_responses(self, mock_req):
        mock_req.return_value = self.mock_response(status_code=200)
        module = SubdomainProbingModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.network_checks.safe_request')
    def test_subdomain_probing_mixed(self, mock_req):
        def side_effect(*args, **kwargs):
            if "api." in args[1]:
                return self.mock_response(status_code=200)
            return None
        mock_req.side_effect = side_effect
        module = SubdomainProbingModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.PARTIAL)

    @patch('api.scanner.modules.network_checks.safe_request')
    def test_subdomain_probing_all_failures(self, mock_req):
        mock_req.return_value = None
        module = SubdomainProbingModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.FAILED)

if __name__ == '__main__':
    unittest.main()
