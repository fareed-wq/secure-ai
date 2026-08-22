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
        with self.assertRaises(requests.exceptions.RequestException):
            safe_request("GET", "file:///etc/passwd", session=self.session)

        with self.assertRaises(requests.exceptions.RequestException):
            safe_request("GET", "gopher://127.0.0.1:11211", session=self.session)

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

        # safe_request raises exception on redirect to private IP
        with self.assertRaises(requests.exceptions.RequestException):
            safe_request("GET", "http://public.test", session=self.session)

    @patch('requests.Session.request')
    @patch('socket.getaddrinfo')
    def test_redirect_to_unsupported_scheme_blocked(self, mock_getaddrinfo, mock_request):
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))]

        mock_resp = MagicMock()
        mock_resp.is_redirect = True
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "file:///etc/passwd"}
        mock_request.return_value = mock_resp

        # safe_request raises exception on redirect to unsupported scheme
        with self.assertRaises(requests.exceptions.RequestException):
            safe_request("GET", "http://public.test", session=self.session)

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

        report = scan_url("http://example.com", probe_subdomains=True, scan_mode="active")

        # Check that the finding for the failed module masks the path
        found = False
        for finding in report.get("findings", []):
            if finding["name"].startswith("Module Timeout / Error"):
                evidence = finding["evidence"]["raw"]
                self.assertIn("<path_masked>", evidence)
                self.assertNotIn("/usr/src/app", evidence)
                found = True
        self.assertTrue(found, "Did not find expected exception masking finding in report.")

class TestGlobalScanAdmissionAndIP(unittest.TestCase):

    # --- Client IP Tests ---
    def test_get_client_ip_vercel_header(self):
        from api.scanner.core import get_client_ip
        mock_req = MagicMock()
        mock_req.headers.get.side_effect = lambda k, d=None: "9.9.9.9" if k.lower() == "x-vercel-forwarded-for" else ("1.2.3.4, 9.9.9.9" if k.lower() == "x-forwarded-for" else d)
        self.assertEqual(get_client_ip(mock_req), "9.9.9.9")

    def test_get_client_ip_spoofed_xff_ignored(self):
        from api.scanner.core import get_client_ip
        mock_req = MagicMock()
        mock_req.headers.get.side_effect = lambda k, d=None: "1.2.3.4" if k.lower() == "x-forwarded-for" else d
        mock_req.client.host = "127.0.0.1"
        self.assertEqual(get_client_ip(mock_req), "127.0.0.1")

    def test_get_client_ip_local_fallback(self):
        from api.scanner.core import get_client_ip
        mock_req = MagicMock()
        mock_req.headers.get.return_value = None
        mock_req.client.host = "192.168.1.100"
        self.assertEqual(get_client_ip(mock_req), "192.168.1.100")

    def test_get_client_ip_malformed_vercel_header(self):
        from api.scanner.core import get_client_ip
        mock_req = MagicMock()
        mock_req.headers.get.side_effect = lambda k, d=None: " 10.0.0.1 , 1.2.3.4 " if k.lower() == "x-vercel-forwarded-for" else d
        self.assertEqual(get_client_ip(mock_req), "10.0.0.1")

    # --- Lease Acquisition Tests ---
    @patch('api.scanner.core.requests.post')
    @patch.dict('os.environ', {'UPSTASH_REDIS_REST_URL': 'http://mock', 'UPSTASH_REDIS_REST_TOKEN': 'token'})
    def test_acquire_scan_lease_success(self, mock_post):
        from api.scanner.core import acquire_scan_lease
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": 1}
        mock_post.return_value = mock_resp

        lease_id = acquire_scan_lease()
        self.assertIsNotNone(lease_id)
        mock_post.assert_called_once()
        called_json = mock_post.call_args[1]['json']
        self.assertEqual(called_json[0], "EVAL")

    @patch('api.scanner.core.requests.post')
    @patch.dict('os.environ', {'UPSTASH_REDIS_REST_URL': 'http://mock', 'UPSTASH_REDIS_REST_TOKEN': 'token'})
    def test_acquire_scan_lease_full(self, mock_post):
        from api.scanner.core import acquire_scan_lease
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": 0}
        mock_post.return_value = mock_resp

        lease_id = acquire_scan_lease()
        self.assertIsNone(lease_id)

    @patch('api.scanner.core.requests.post')
    @patch.dict('os.environ', {'UPSTASH_REDIS_REST_URL': 'http://mock', 'UPSTASH_REDIS_REST_TOKEN': 'token'})
    def test_acquire_scan_lease_redis_error_fails_closed(self, mock_post):
        from api.scanner.core import acquire_scan_lease
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        mock_post.return_value = mock_resp

        with self.assertRaises(RuntimeError) as context:
            acquire_scan_lease()
        self.assertIn("Failed to acquire global active-scan lease", str(context.exception))

    @patch.dict('os.environ', clear=True)
    def test_acquire_scan_lease_missing_env_fails_closed(self):
        from api.scanner.core import acquire_scan_lease
        with self.assertRaises(RuntimeError) as context:
            acquire_scan_lease()
        self.assertIn("Redis configuration missing", str(context.exception))

    # --- Lease Release Tests ---
    @patch('api.scanner.core.requests.post')
    @patch.dict('os.environ', {'UPSTASH_REDIS_REST_URL': 'http://mock', 'UPSTASH_REDIS_REST_TOKEN': 'token'})
    def test_release_scan_lease(self, mock_post):
        from api.scanner.core import release_scan_lease
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        release_scan_lease("test-uuid")
        mock_post.assert_called_once()
        called_json = mock_post.call_args[1]['json']
        self.assertEqual(called_json[0], "EVAL")
        self.assertEqual(called_json[5], "test-uuid")

    @patch('api.scanner.core.requests.post')
    @patch.dict('os.environ', {'UPSTASH_REDIS_REST_URL': 'http://mock', 'UPSTASH_REDIS_REST_TOKEN': 'token'})
    def test_release_scan_lease_idempotent_on_error(self, mock_post):
        from api.scanner.core import release_scan_lease
        mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")

        try:
            release_scan_lease("test-uuid")
        except Exception as e:
            self.fail(f"release_scan_lease raised an exception unexpectedly: {e}")

class TestBatchConcurrency(unittest.TestCase):

    @patch("api.index.acquire_scan_lease")
    @patch("api.index.release_scan_lease")
    @patch("api.index.scan_url")
    @patch("api.index.Entitlements")
    def test_single_scan_acquires_one_lease(self, mock_entitlements, mock_scan_url, mock_release, mock_acquire):
        mock_ent_instance = mock_entitlements.return_value
        mock_ent_instance.plan = "free"
        mock_ent_instance.can_advanced_scan = True
        from fastapi.testclient import TestClient
        from api.index import app
    
        client = TestClient(app)
        mock_acquire.return_value = "lease-1"
        mock_scan_url.return_value = {"url": "https://example.com", "findings": []}
    
        with patch("api.index.check_free_quota", return_value={"quota_remaining": 5}):
            with patch("api.index.consume_free_quota", return_value=True):
                res = client.post("/api/scan", json={"url": "https://example.com"})
    
        self.assertEqual(res.status_code, 200)
        mock_acquire.assert_called_once()
        mock_release.assert_called_once_with("lease-1", is_admin=unittest.mock.ANY)

    @patch("api.index.acquire_scan_lease")
    @patch("api.index.release_scan_lease")
    @patch("api.index.scan_url")
    @patch("api.index.Entitlements")
    def test_batch_scan_acquires_n_leases(self, mock_entitlements, mock_scan_url, mock_release, mock_acquire):
        mock_ent_instance = mock_entitlements.return_value
        mock_ent_instance.plan = "free"
        mock_ent_instance.can_advanced_scan = True
        from fastapi.testclient import TestClient
        from api.index import app
    
        client = TestClient(app)
        # Mock side_effect to return unique leases
        mock_acquire.side_effect = ["lease-1", "lease-2"]
        mock_scan_url.return_value = {"url": "https://example.com", "findings": []}
    
        res = client.post("/api/scan/batch", json={"urls": ["https://ex1.com", "https://ex2.com"]})
    
        self.assertEqual(res.status_code, 200)
        self.assertEqual(mock_acquire.call_count, 2)
        # Release should be called for both
        mock_release.assert_any_call("lease-1", is_admin=unittest.mock.ANY)
        mock_release.assert_any_call("lease-2", is_admin=unittest.mock.ANY)

    @patch("api.index.acquire_scan_lease")
    @patch("api.index.release_scan_lease")
    @patch("api.index.scan_url")
    @patch("api.index.Entitlements")
    def test_batch_scan_handles_mixed_capacity(self, mock_entitlements, mock_scan_url, mock_release, mock_acquire):
        mock_ent_instance = mock_entitlements.return_value
        mock_ent_instance.plan = "free"
        mock_ent_instance.can_advanced_scan = True
        from fastapi.testclient import TestClient
        from api.index import app
    
        client = TestClient(app)
        # First acquires successfully, second hits capacity full (None), third fails entirely (RuntimeError)
        mock_acquire.side_effect = ["lease-1", None, RuntimeError("Redis ded")]
        mock_scan_url.return_value = {"url": "https://ex1.com", "findings": []}
    
        res = client.post("/api/scan/batch", json={"urls": ["https://ex1.com", "https://ex2.com", "https://ex3.com"]})
    
        self.assertEqual(res.status_code, 200)
        data = res.json()
        results = data["results"]
        self.assertEqual(len(results), 3)

        success = [r for r in results if r.get("status") == "success" or r.get("findings") is not None]
        full = [r for r in results if r.get("status") == 429 or (r.get("status") == "failed" and "capacity is full" in r.get("error", ""))]
        err = [r for r in results if r.get("status") == 503 or (r.get("status") == "failed" and "unknown" in r.get("error", ""))]

        self.assertEqual(len(success), 1)
        self.assertEqual(len(full), 1)
        self.assertEqual(len(err), 1)

        # Release ONLY called for lease-1
        mock_release.assert_called_once_with("lease-1", is_admin=unittest.mock.ANY)

    @patch("api.index.acquire_scan_lease")
    @patch("api.index.release_scan_lease")
    @patch("api.index.scan_url")
    @patch("api.index.Entitlements")
    def test_release_on_scan_exception(self, mock_entitlements, mock_scan_url, mock_release, mock_acquire):
        mock_ent_instance = mock_entitlements.return_value
        mock_ent_instance.plan = "free"
        mock_ent_instance.can_advanced_scan = True
        from fastapi.testclient import TestClient
        from api.index import app
    
        client = TestClient(app)
        mock_acquire.return_value = "lease-fail"
        mock_scan_url.side_effect = Exception("Boom")
    
        with patch("api.index.check_free_quota", return_value={"quota_remaining": 5}):
            with patch("api.index.consume_free_quota", return_value=True):
                res = client.post("/api/scan", json={"url": "https://example.com"})
    
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "INCOMPLETE")
        mock_release.assert_called_once_with("lease-fail", is_admin=unittest.mock.ANY)

if __name__ == '__main__':
    unittest.main()
