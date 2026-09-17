import unittest
from unittest.mock import patch, MagicMock
import requests

from api.scanner.core import ModuleResult, AssessmentOutcome
from api.scanner.modules.api_web_security import ApiWebSecurityModule
from api.scanner.modules.content import MixedContentModule
from api.scanner.modules.network_checks import GraphQLIntrospectionModule, SubdomainTakeoverModule
from api.scanner.modules.discovery import ActuatorModule, OpenApiModule, GraphqlIdeModule

class TestPhase1B5Outcomes(unittest.TestCase):
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

    # --- ApiWebSecurityModule ---
    @patch('api.scanner.modules.api_web_security.safe_request')
    def test_api_web_security_completed(self, mock_request):
        mock_request.return_value = self.mock_response(status_code=200)
        module = ApiWebSecurityModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.api_web_security.safe_request')
    def test_api_web_security_failed(self, mock_request):
        mock_request.return_value = None
        module = ApiWebSecurityModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    # --- MixedContentModule ---
    @patch('api.scanner.modules.content.safe_request')
    def test_mixed_content_completed(self, mock_request):
        mock_request.return_value = self.mock_response(status_code=200, text="<html></html>")
        module = MixedContentModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.content.safe_request')
    def test_mixed_content_failed(self, mock_request):
        mock_request.return_value = None
        module = MixedContentModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    @patch('api.scanner.modules.content.safe_request')
    def test_mixed_content_http_not_completed(self, mock_request):
        mock_request.return_value = self.mock_response(status_code=200, text="<html></html>")
        module = MixedContentModule()
        result = module.run("http://example.com", "example.com", self.session)
        self.assertIsInstance(result, list)

    @patch('api.scanner.modules.content.safe_request')
    def test_mixed_content_api_not_completed(self, mock_request):
        mock_request.return_value = self.mock_response(status_code=200, text="{}", headers={"Content-Type": "application/json"})
        module = MixedContentModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    # --- GraphQLIntrospectionModule ---
    @patch('api.scanner.modules.network_checks.safe_request')
    def test_graphql_introspection_completed(self, mock_request):
        mock_request.return_value = self.mock_response(status_code=200, text='{"__schema": {}}', headers={"Content-Type": "application/json"})
        module = GraphQLIntrospectionModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.network_checks.safe_request')
    def test_graphql_introspection_failed(self, mock_request):
        mock_request.return_value = None
        module = GraphQLIntrospectionModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    # --- SubdomainTakeoverModule ---
    @patch('api.scanner.modules.network_checks.safe_request')
    def test_subdomain_takeover_completed(self, mock_request):
        mock_request.return_value = self.mock_response(status_code=200, json_data={"Answer": []})
        module = SubdomainTakeoverModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.network_checks.safe_request')
    def test_subdomain_takeover_failed(self, mock_request):
        mock_request.return_value = None
        module = SubdomainTakeoverModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    @patch('api.scanner.modules.network_checks.safe_request')
    def test_subdomain_takeover_500_not_completed(self, mock_request):
        mock_request.return_value = self.mock_response(status_code=500)
        module = SubdomainTakeoverModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    # --- ActuatorModule ---
    @patch('api.scanner.modules.discovery.safe_request')
    def test_actuator_completed(self, mock_request):
        mock_request.return_value = self.mock_response(status_code=200, json_data={"status": "UP"}, headers={"Content-Type": "application/json"})
        module = ActuatorModule()
        result = module.run("https://example.com/actuator", self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_actuator_failed(self, mock_request):
        mock_request.return_value = None
        module = ActuatorModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    # --- OpenApiModule ---
    @patch('api.scanner.modules.discovery.safe_request')
    def test_openapi_completed(self, mock_request):
        mock_request.return_value = self.mock_response(status_code=200, json_data={"openapi": "3.0.0"}, headers={"Content-Type": "application/json"})
        module = OpenApiModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_openapi_failed(self, mock_request):
        mock_request.return_value = None
        module = OpenApiModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    # --- GraphqlIdeModule ---
    @patch('api.scanner.modules.discovery.safe_request')
    def test_graphql_ide_completed(self, mock_request):
        mock_request.return_value = self.mock_response(status_code=200, text="GraphiQL", headers={"Content-Type": "text/html"})
        module = GraphqlIdeModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_graphql_ide_failed(self, mock_request):
        mock_request.return_value = None
        module = GraphqlIdeModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)


if __name__ == '__main__':
    unittest.main()
