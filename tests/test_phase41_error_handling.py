import unittest
from unittest.mock import patch, MagicMock
from api.scanner.orchestrator import scan_url
import requests
import socket

class TestPhase41ErrorHandling(unittest.TestCase):

    @patch('api.scanner.orchestrator.is_public_hostname')
    @patch('api.scanner.orchestrator.check_liveness')
    def test_liveness_failure(self, mock_check_liveness, mock_is_public):
        mock_is_public.return_value = True
        # When check_liveness fails, the scan should return status="failed"
        mock_check_liveness.return_value = False
        
        result = scan_url("https://dead-target.example.com")
        
        self.assertEqual(result.get("status"), "failed")
        self.assertIn("could not be reached", result.get("error", ""))
        self.assertNotIn("findings", result)
        self.assertNotIn("score", result)

    @patch('api.scanner.orchestrator.is_public_hostname')
    @patch('api.scanner.orchestrator.check_liveness')
    @patch('api.scanner.orchestrator.safe_request')
    def test_initial_request_timeout(self, mock_safe_request, mock_check_liveness, mock_is_public):
        mock_is_public.return_value = True
        mock_check_liveness.return_value = True
        
        # When safe_request raises requests.exceptions.Timeout, it should return status="timeout"
        mock_safe_request.side_effect = requests.exceptions.Timeout("Read timeout")
        
        result = scan_url("https://timeout.example.com")
        
        self.assertEqual(result.get("status"), "timeout")
        self.assertIn("Connection timed out", result.get("error", ""))
        self.assertNotIn("findings", result)

    @patch('api.scanner.orchestrator.is_public_hostname')
    @patch('api.scanner.orchestrator.check_liveness')
    @patch('api.scanner.orchestrator.safe_request')
    def test_initial_request_connection_error(self, mock_safe_request, mock_check_liveness, mock_is_public):
        mock_is_public.return_value = True
        mock_check_liveness.return_value = True
        
        # When safe_request raises requests.exceptions.ConnectionError, it should return status="failed"
        mock_safe_request.side_effect = requests.exceptions.ConnectionError("Connection refused")
        
        result = scan_url("https://refused.example.com")
        
        self.assertEqual(result.get("status"), "failed")
        self.assertIn("Failed to establish connection", result.get("error", ""))
        self.assertNotIn("findings", result)
        
    @patch('api.scanner.orchestrator.is_public_hostname')
    @patch('api.scanner.orchestrator.check_liveness')
    @patch('api.scanner.orchestrator.safe_request')
    @patch('api.scanner.orchestrator.get_metadata')
    @patch('api.scanner.orchestrator.REGISTERED_MODULES')
    @patch('api.scanner.orchestrator.calculate_score')
    def test_successful_scan_preserved(self, mock_calc_score, mock_modules, mock_meta, mock_req, mock_liveness, mock_is_public):
        mock_is_public.return_value = True
        # A successful scan should not return status=failed
        mock_liveness.return_value = True
        mock_req.return_value = MagicMock()
        mock_meta.return_value = {}
        # mock modules
        mock_modules.return_value = []
        
        mock_calc_score.return_value = {"score": 100, "findings": []}
        
        result = scan_url("https://success.example.com")
        
        self.assertNotEqual(result.get("status"), "failed")
        self.assertNotEqual(result.get("status"), "timeout")
        self.assertEqual(result.get("score"), 100)

if __name__ == '__main__':
    unittest.main()
