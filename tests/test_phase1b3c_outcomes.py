import unittest
from unittest.mock import patch, MagicMock
from api.scanner.core import ModuleResult, AssessmentOutcome
from api.scanner.modules.network_checks import VerboseStackTraceModule
from api.scanner.modules.headers import CSPQualityModule
from api.scanner.modules.http_security import AdvancedSecurityHeadersModule
from api.scanner.modules.tls import EnhancedTLSModule
import requests
import ssl

class TestPhase1B3COutcomes(unittest.TestCase):
    def setUp(self):
        self.url = 'https://example.com'
        self.hostname = 'example.com'
        self.session = MagicMock()

    def mock_response(self, status_code=200, text='', headers=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.headers = headers or {}
        resp.url = 'https://example.com'
        return resp

    @patch('api.scanner.modules.network_checks.safe_request')
    def test_verbose_stack_trace_clean(self, mock_req):
        mock_req.return_value = self.mock_response(200, text='Traceback (most recent call last):')
        mod = VerboseStackTraceModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.network_checks.safe_request')
    def test_verbose_stack_trace_timeout(self, mock_req):
        mock_req.side_effect = requests.exceptions.Timeout()
        mod = VerboseStackTraceModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    @patch('api.scanner.modules.headers.safe_request')
    def test_csp_quality_clean(self, mock_req):
        mock_req.return_value = self.mock_response(200, headers={'Content-Security-Policy': 'default-src *'})
        mod = CSPQualityModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.headers.safe_request')
    def test_csp_quality_timeout(self, mock_req):
        mock_req.side_effect = requests.exceptions.Timeout()
        mod = CSPQualityModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    @patch('api.scanner.modules.http_security.safe_request')
    def test_advanced_sec_headers_clean(self, mock_req):
        mock_req.return_value = self.mock_response(200, headers={'Strict-Transport-Security': 'max-age=31536000'})
        mod = AdvancedSecurityHeadersModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.http_security.safe_request')
    def test_advanced_sec_headers_timeout(self, mock_req):
        mock_req.side_effect = requests.exceptions.Timeout()
        mod = AdvancedSecurityHeadersModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    @patch('api.scanner.modules.tls.ssl.create_default_context')
    @patch('api.scanner.modules.tls.safe_create_connection')
    def test_enhanced_tls_clean(self, mock_conn, mock_ssl):
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        mock_context = MagicMock()
        mock_ssock = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ssl.return_value = mock_context
        mod = EnhancedTLSModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.tls.safe_create_connection')
    def test_enhanced_tls_timeout(self, mock_conn):
        mock_conn.side_effect = Exception("Connection Refused")
        mod = EnhancedTLSModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

if __name__ == '__main__':
    unittest.main()
