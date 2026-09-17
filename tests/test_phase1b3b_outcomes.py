import unittest
from unittest.mock import patch, MagicMock
from api.scanner.core import ModuleResult, AssessmentOutcome
from api.scanner.modules.headers import TechFingerprintModule, PermissionsPolicyModule
from api.scanner.modules.http_security import HTTPSRedirectModule
from api.scanner.modules.discovery import InformationDisclosureModule
import requests

class TestPhase1B3BOutcomes(unittest.TestCase):
    def setUp(self):
        self.url = 'https://example.com'
        self.hostname = 'example.com'
        self.session = MagicMock()

    def mock_response(self, status_code=200, text='', headers=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.headers = headers or {}
        resp.url = 'https://example.com' if status_code == 301 else 'http://example.com'
        return resp

    @patch('api.scanner.modules.headers.safe_request')
    def test_tech_fingerprint_clean(self, mock_req):
        mock_req.return_value = self.mock_response(200, headers={'Server': 'nginx'})
        mod = TechFingerprintModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.headers.safe_request')
    def test_tech_fingerprint_timeout(self, mock_req):
        mock_req.side_effect = requests.exceptions.Timeout()
        mod = TechFingerprintModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    @patch('api.scanner.modules.headers.safe_request')
    def test_permissions_policy_clean(self, mock_req):
        mock_req.return_value = self.mock_response(200, headers={'Permissions-Policy': 'geolocation=()'})
        mod = PermissionsPolicyModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.headers.safe_request')
    def test_permissions_policy_timeout(self, mock_req):
        mock_req.side_effect = requests.exceptions.Timeout()
        mod = PermissionsPolicyModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    @patch('api.scanner.modules.http_security.safe_request')
    def test_https_redirect_clean(self, mock_req):
        mock_req.return_value = self.mock_response(301, headers={'Location': 'https://example.com'})
        mod = HTTPSRedirectModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.http_security.safe_request')
    def test_https_redirect_timeout(self, mock_req):
        mock_req.side_effect = requests.exceptions.Timeout()
        mod = HTTPSRedirectModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_info_disclosure_clean(self, mock_req):
        mock_req.return_value = self.mock_response(200, text='Traceback (most recent call last):', headers={'Server': 'nginx'})
        mod = InformationDisclosureModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_info_disclosure_timeout(self, mock_req):
        mock_req.side_effect = requests.exceptions.Timeout()
        mod = InformationDisclosureModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

if __name__ == '__main__':
    unittest.main()
