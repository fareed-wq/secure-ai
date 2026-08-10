import unittest
from unittest.mock import patch, MagicMock
import requests
import socket

from api.scanner.transport import is_public_hostname, safe_request, get_http_session
from api.scanner.validation import canonicalize_url
from api.scanner.orchestrator import scan_url

class TestPhase35SecurityHardening(unittest.TestCase):

    def setUp(self):
        self.session = get_http_session()

    def tearDown(self):
        self.session.close()

    # --- SSRF IP Validation Tests ---

    @patch('socket.getaddrinfo')
    def test_ssrf_cgnat_blocked(self, mock_getaddrinfo):
        # 100.64.0.1 (CGNAT space)
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('100.64.0.1', 80))
        ]
        self.assertFalse(is_public_hostname("cgnat.test", self.session))

    @patch('socket.getaddrinfo')
    def test_ssrf_zero_network_blocked(self, mock_getaddrinfo):
        # 0.0.0.0
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('0.0.0.0', 80))
        ]
        self.assertFalse(is_public_hostname("zero.test", self.session))

    @patch('socket.getaddrinfo')
    def test_ssrf_ipv4_mapped_ipv6_blocked(self, mock_getaddrinfo):
        # ::ffff:192.168.1.1 mapped private IP
        mock_getaddrinfo.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::ffff:192.168.1.1', 80))
        ]
        self.assertFalse(is_public_hostname("mapped.test", self.session))

    @patch('socket.getaddrinfo')
    def test_ssrf_public_ip_allowed(self, mock_getaddrinfo):
        # 93.184.216.34 (example.com)
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))
        ]
        self.assertTrue(is_public_hostname("example.com", self.session))

    # --- Redirect and Scheme Safety Tests ---

    def test_unsupported_scheme_rejected(self):
        resp = safe_request("GET", "file:///etc/passwd", session=self.session)
        self.assertIsNone(resp)
        
        resp = safe_request("GET", "gopher://127.0.0.1:11211", session=self.session)
        self.assertIsNone(resp)

    @patch('requests.Session.request')
    @patch('socket.getaddrinfo')
    def test_redirect_to_private_ip_blocked(self, mock_getaddrinfo, mock_request):
        # First hop is public, second hop is 127.0.0.1
        def side_effect(host, *args, **kwargs):
            if host == "public.test":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 80))]
        mock_getaddrinfo.side_effect = side_effect

        mock_resp = MagicMock()
        mock_resp.is_redirect = True
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "http://private.test/admin"}
        mock_request.return_value = mock_resp

        # safe_request catches the exception during redirect and returns the last valid response (the 302)
        resp = safe_request("GET", "http://public.test", session=self.session)
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 302)

    @patch('requests.Session.request')
    @patch('socket.getaddrinfo')
    def test_redirect_to_unsupported_scheme_blocked(self, mock_getaddrinfo, mock_request):
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))]
        
        mock_resp = MagicMock()
        mock_resp.is_redirect = True
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "file:///etc/passwd"}
        mock_request.return_value = mock_resp

        # safe_request catches the exception during redirect and returns the last valid response
        resp = safe_request("GET", "http://public.test", session=self.session)
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 302)

    # --- Response Size Limitation Tests ---

    @patch('requests.Session.request')
    @patch('api.scanner.transport.is_public_hostname')
    def test_5mb_global_response_limit(self, mock_is_public, mock_request):
        mock_is_public.return_value = True
        
        mock_resp = MagicMock()
        mock_resp.is_redirect = False
        mock_resp.status_code = 200
        mock_resp.headers = {}
        
        # Simulate a 10MB response generated in 1MB chunks
        chunk = b"A" * (1024 * 1024)
        def iter_content(chunk_size=1, decode_unicode=False):
            for _ in range(10):
                yield chunk
        mock_resp.iter_content = iter_content
        
        mock_request.return_value = mock_resp

        # Without stream=True, safe_request should internally bound to 5MB
        resp = safe_request("GET", "http://example.com", session=self.session)
        
        self.assertIsNotNone(resp)
        self.assertTrue(getattr(resp, '_content_consumed', False))
        # Bounded read should be exactly 5MB
        self.assertEqual(len(resp._content), 5 * 1024 * 1024)
        
    @patch('requests.Session.request')
    @patch('api.scanner.transport.is_public_hostname')
    def test_stream_response_limit(self, mock_is_public, mock_request):
        mock_is_public.return_value = True
        
        mock_resp = MagicMock()
        mock_resp.is_redirect = False
        mock_resp.status_code = 200
        mock_resp.headers = {}
        
        # Simulate a 10MB response
        chunk = b"B" * (1024 * 1024)
        def iter_content(chunk_size=1, decode_unicode=False):
            for _ in range(10):
                yield chunk
        mock_resp.iter_content = iter_content
        mock_request.return_value = mock_resp

        # When explicitly requested stream=True,iter_content should be replaced by a bounded generator
        resp = safe_request("GET", "http://example.com", session=self.session, stream=True)
        
        self.assertIsNotNone(resp)
        
        bytes_read = 0
        for chunk in resp.iter_content(chunk_size=8192):
            bytes_read += len(chunk)
            
        self.assertEqual(bytes_read, 5 * 1024 * 1024)
        mock_resp.close.assert_called_once()

    # --- Input Validation Tests ---

    def test_url_length_limit(self):
        # Build a URL that exceeds 2048 chars
        long_url = "http://example.com/" + ("A" * 2050)
        with self.assertRaises(ValueError) as context:
            canonicalize_url(long_url)
        self.assertIn("URL exceeds maximum allowed length of 2048 characters", str(context.exception))
        
        # A valid URL should pass
        valid_url = "http://example.com/" + ("A" * 10)
        self.assertEqual(canonicalize_url(valid_url), valid_url)

    # --- Exception Safety Tests ---

    @patch('api.scanner.orchestrator.is_public_hostname')
    @patch('api.scanner.orchestrator.check_liveness')
    @patch('api.scanner.orchestrator.get_metadata')
    @patch('api.scanner.orchestrator.safe_request')
    @patch('api.scanner.modules.network_checks.SubdomainProbingModule.run')
    def test_exception_path_masking(self, mock_mod_run, mock_safe_request, mock_get_meta, mock_liveness, mock_public):
        mock_public.return_value = True
        mock_liveness.return_value = True
        mock_get_meta.return_value = {}
        mock_safe_request.return_value = MagicMock(status_code=200, text="OK", headers={})
        
        # Simulate a module raising an exception with a local path
        mock_mod_run.side_effect = Exception("Failed at /usr/src/app/api/scanner/modules/network_checks.py line 42")
        
        report = scan_url("http://example.com", probe_subdomains=True)
        
        # Check that the finding for the failed module masks the path
        found = False
        for finding in report.get("findings", []):
            if finding["name"].startswith("Module Timeout / Error"):
                evidence = finding["evidence"]["raw"]
                self.assertIn("<path_masked>", evidence)
                self.assertNotIn("/usr/src/app", evidence)
                found = True
        self.assertTrue(found, "Did not find expected exception masking finding in report.")

if __name__ == '__main__':
    unittest.main()
