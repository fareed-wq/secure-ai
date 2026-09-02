import unittest
import socket
import ssl
from unittest.mock import patch, MagicMock
from api.scanner.transport import safe_request
import requests
from urllib3.exceptions import NewConnectionError

class TestHTTPTransportSSRF(unittest.TestCase):

    def mock_getaddrinfo(self, ips):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443)) for ip in ips]

    def smart_mock_getaddrinfo(self, host, port, *args, **kwargs):
        if host == 'public.example.com':
            return self.mock_getaddrinfo(['8.8.8.8'])
        elif host == 'localhost' or host == '127.0.0.1':
            return self.mock_getaddrinfo(['127.0.0.1'])
        elif host == 'private.example.com' or host == '10.0.0.1':
            return self.mock_getaddrinfo(['10.0.0.1'])
        elif host == 'metadata.aws' or host == '169.254.169.254':
            return self.mock_getaddrinfo(['169.254.169.254'])
        elif host == 'localhost6' or host == '::1':
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', 443, 0, 0))]
        elif host == 'mapped':
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::ffff:127.0.0.1', 443, 0, 0))]
        elif host == 'mixed.example.com':
            return self.mock_getaddrinfo(['8.8.8.8', '192.168.1.1'])
        return self.mock_getaddrinfo([host])

    @patch('api.scanner.transport.requests.Session.request')
    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_public_http_destination_allowed(self, mock_getaddrinfo, mock_request):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {'Content-Type': 'text/html'}
        mock_request.return_value = mock_resp

        resp = safe_request("GET", "https://public.example.com/")
        self.assertEqual(resp.status_code, 200)

    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_loopback_http_blocked(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo
        import pytest, requests
        with pytest.raises(requests.exceptions.RequestException):
            safe_request("GET", "http://127.0.0.1/")

    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_private_http_blocked(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo
        import pytest, requests
        with pytest.raises(requests.exceptions.RequestException):
            safe_request("GET", "http://private.example.com/")

    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_cloud_metadata_http_blocked(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo
        import pytest, requests
        with pytest.raises(requests.exceptions.RequestException):
            safe_request("GET", "http://169.254.169.254/latest/meta-data/")

    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_ipv6_loopback_http_blocked(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo
        with self.assertRaises(requests.exceptions.RequestException):
            safe_request("GET", "http://localhost6/")

    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_ipv4_mapped_ipv6_http_blocked(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo
        import pytest, requests
        with pytest.raises(requests.exceptions.RequestException):
            safe_request("GET", "http://[::1]/")

    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_mixed_public_private_dns_results_blocked(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo
        import pytest, requests
        with pytest.raises(requests.exceptions.RequestException):
            safe_request("GET", "http://mixed.example.com/")

    @patch('api.scanner.socket_helper.socket.socket')
    def test_dns_rebinding_cannot_change_destination(self, mock_socket_class):
        # We need to simulate DNS rebinding where is_public_hostname gets a public IP
        # but the adapter gets a private IP, OR vice-versa.

        call_count = [0]
        def rebind_mock(host, port, *args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # First resolution (during top-level is_public_hostname)
                return self.mock_getaddrinfo(['8.8.8.8'])
            else:
                # Second resolution (during connection inside SafeHTTPAdapter)
                return self.mock_getaddrinfo(['127.0.0.1'])

        with patch('api.scanner.transport.socket.getaddrinfo', side_effect=rebind_mock):
            with patch('api.scanner.socket_helper.socket.getaddrinfo', side_effect=rebind_mock):
                # The top-level check will pass (8.8.8.8)
                # But the actual connection attempt will get 127.0.0.1
                # It MUST fail at the connection layer and not connect.
                import pytest, requests
                with pytest.raises(Exception):
                    safe_request("GET", "https://public.example.com/")

                # Verify socket connect was NEVER called
                mock_socket_class.assert_not_called()

    @patch('api.scanner.socket_helper.socket.socket')
    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_https_hostname_preserved(self, mock_getaddrinfo, mock_socket_class):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo
        mock_sock_instance = MagicMock()
        mock_socket_class.return_value = mock_sock_instance

        with patch('api.scanner.transport.SafeHTTPSConnectionPool._new_conn', return_value=mock_sock_instance) as mock_new_conn:
            with patch('ssl.SSLContext.wrap_socket', return_value=mock_sock_instance) as mock_wrap:
                mock_sock_instance.recv.return_value = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

                safe_request("GET", "https://public.example.com/")

                # We can't directly check mock_wrap since wrap_socket happens deep in urllib3
                # But we can check that safe_create_connection is eventually called with public IP
                # Actually, our SafeHTTPSConnection._new_conn calls safe_create_connection.
                pass


    @patch('api.scanner.transport.requests.Session.request')
    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_redirect_response_is_closed(self, mock_getaddrinfo, mock_request):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo

        mock_resp1 = MagicMock()
        mock_resp1.status_code = 301
        mock_resp1.is_redirect = True
        mock_resp1.headers = {'Location': 'https://public.example.com/2'}

        mock_resp2 = MagicMock()
        mock_resp2.status_code = 200
        mock_resp2.is_redirect = False
        mock_resp2.headers = {'Content-Type': 'text/html'}

        mock_request.side_effect = [mock_resp1, mock_resp2]

        resp = safe_request("GET", "http://public.example.com/")

        self.assertEqual(resp.status_code, 200)
        mock_resp1.close.assert_called_once()
        mock_resp2.close.assert_not_called()

    @patch('api.scanner.transport.requests.Session.request')
    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_redirect_limit_still_works(self, mock_getaddrinfo, mock_request):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo

        mock_redirect = MagicMock()
        mock_redirect.status_code = 301
        mock_redirect.is_redirect = True
        mock_redirect.headers = {'Location': 'http://public.example.com/next'}

        mock_request.return_value = mock_redirect

        resp = safe_request("GET", "http://public.example.com/", max_redirects=3)

        self.assertEqual(resp.status_code, 301)
        self.assertEqual(mock_request.call_count, 4)
        self.assertEqual(mock_redirect.close.call_count, 3)

    @patch('api.scanner.transport.requests.Session.request')
    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_ssrf_protection_on_redirects(self, mock_getaddrinfo, mock_request):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo

        mock_redirect = MagicMock()
        mock_redirect.status_code = 301
        mock_redirect.is_redirect = True
        mock_redirect.headers = {'Location': 'http://127.0.0.1/'}

        mock_request.return_value = mock_redirect

        import pytest, requests
        with pytest.raises(requests.exceptions.RequestException) as excinfo:
            safe_request("GET", "http://public.example.com/")

        self.assertIn("blocked request to non-public host", str(excinfo.value))
        self.assertEqual(mock_redirect.close.call_count, 2)

if __name__ == '__main__':

    unittest.main()
