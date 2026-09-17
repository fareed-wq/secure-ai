import unittest
from unittest.mock import patch, MagicMock
import requests
import socket

from api.scanner.core import ModuleResult, AssessmentOutcome
from api.scanner.modules.discovery import ExposedFilesModule
from api.scanner.modules.infrastructure import InfrastructureIntelligenceModule
from api.scanner.modules.network_services import NetworkServiceExposureModule

class TestPhase1B4Outcomes(unittest.TestCase):
    def setUp(self):
        self.session = requests.Session()
        self.url = "https://example.com"
        self.hostname = "example.com"

    def mock_response(self, status_code=200, text="", headers=None, url="https://example.com"):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.headers = headers or {}
        resp.url = url
        resp.history = []
        return resp

    # --- ExposedFilesModule ---
    @patch('api.scanner.modules.discovery.safe_request')
    def test_exposed_files_completed(self, mock_request):
        # All 6 requests return clean 404s
        mock_request.return_value = self.mock_response(status_code=404)
        module = ExposedFilesModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)
        self.assertEqual(len(result.findings), 0)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_exposed_files_partial(self, mock_request):
        # First request succeeds, next 5 throw timeout
        def side_effect(*args, **kwargs):
            if "/.env" in args[1]:
                return self.mock_response(status_code=200, text="API_KEY=123")
            raise requests.exceptions.Timeout("Timeout")
        mock_request.side_effect = side_effect

        module = ExposedFilesModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.PARTIAL)
        self.assertEqual(len(result.findings), 2)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_exposed_files_legacy_all_fail(self, mock_request):
        # All requests fail
        mock_request.side_effect = requests.exceptions.Timeout("Timeout")
        module = ExposedFilesModule()
        result = module.run(self.url, self.hostname, self.session)
        # Should return raw list (legacy/null outcome)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_exposed_files_safe_request_returns_none(self, mock_request):
        # Return None explicitly instead of raising
        mock_request.return_value = None
        module = ExposedFilesModule()
        result = module.run(self.url, self.hostname, self.session)
        # Should count as all failed -> legacy list
        self.assertIsInstance(result, list)

    # --- InfrastructureIntelligenceModule ---
    @patch('api.scanner.modules.infrastructure.safe_create_connection')
    @patch('api.scanner.modules.infrastructure.safe_request')
    @patch('ssl.create_default_context')
    def test_infrastructure_completed(self, mock_ssl, mock_request, mock_sock):
        # Mock everything to return clean, empty responses
        mock_request.return_value = self.mock_response(status_code=404)
        mock_sock.return_value.__enter__.return_value = MagicMock()
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = {}
        mock_ssl.return_value = mock_context

        module = InfrastructureIntelligenceModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.infrastructure.safe_create_connection')
    @patch('api.scanner.modules.infrastructure.safe_request')
    @patch('ssl.create_default_context')
    def test_infrastructure_partial(self, mock_ssl, mock_request, mock_sock):
        # SAN fails, but NS record succeeds
        mock_sock.side_effect = Exception("SAN fail")
        def req_side_effect(*args, **kwargs):
            if "type=NS" in args[1]:
                return self.mock_response(status_code=200, text='{"Answer": [{"data": "ns1.cloudflare.com"}]}')
            raise requests.exceptions.Timeout("Timeout")
        mock_request.side_effect = req_side_effect

        module = InfrastructureIntelligenceModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.PARTIAL)

    @patch('api.scanner.modules.infrastructure.safe_create_connection')
    @patch('api.scanner.modules.infrastructure.safe_request')
    def test_infrastructure_all_fail(self, mock_request, mock_sock):
        mock_request.side_effect = requests.exceptions.Timeout("Timeout")
        mock_sock.side_effect = Exception("Sock fail")
        module = InfrastructureIntelligenceModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    # --- NetworkServiceExposureModule ---
    @patch('api.scanner.modules.network_services.socket.getaddrinfo')
    @patch('api.scanner.modules.network_services.safe_create_connection')
    def test_network_services_completed(self, mock_conn, mock_getaddr):
        # All ports get connection refused (negative result, but completes successfully)
        mock_getaddr.return_value = [[None, None, None, None, ["127.0.0.1"]]]
        mock_conn.side_effect = ConnectionRefusedError("Closed")

        module = NetworkServiceExposureModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)
        self.assertEqual(len(result.findings), 0)

    @patch('api.scanner.modules.network_services.socket.getaddrinfo')
    @patch('api.scanner.modules.network_services.safe_create_connection')
    def test_network_services_partial(self, mock_conn, mock_getaddr):
        # First port fails to resolve DNS, others succeed
        def side_effect(*args, **kwargs):
            if args[1] == 21:
                raise socket.gaierror("DNS failed")
            return [[None, None, None, None, ["127.0.0.1"]]]
        mock_getaddr.side_effect = side_effect
        mock_conn.side_effect = ConnectionRefusedError("Closed")

        module = NetworkServiceExposureModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.PARTIAL)

    @patch('api.scanner.modules.network_services.socket.getaddrinfo')
    def test_network_services_all_fail(self, mock_getaddr):
        # DNS totally fails for all ports
        mock_getaddr.side_effect = socket.gaierror("DNS failed")

        module = NetworkServiceExposureModule()
        result = module.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)

    @patch('api.scanner.modules.network_services.socket.getaddrinfo')
    @patch('api.scanner.modules.network_services.safe_create_connection')
    def test_network_services_timeout(self, mock_conn, mock_getaddr):
        mock_getaddr.return_value = [[None, None, None, None, ["127.0.0.1"]]]
        # Timeout should count as failed
        mock_conn.side_effect = socket.timeout("Timeout")
        module = NetworkServiceExposureModule()
        result = module.run(self.url, self.hostname, self.session)
        # Should count as all failed -> legacy list
        self.assertIsInstance(result, list)

if __name__ == '__main__':
    unittest.main()
