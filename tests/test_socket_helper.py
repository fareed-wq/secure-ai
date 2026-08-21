import unittest
import socket
from unittest.mock import patch, MagicMock
from api.scanner.socket_helper import safe_create_connection

class TestSocketHelper(unittest.TestCase):

    def mock_getaddrinfo(self, ips):
        # returns [(family, type, proto, canonname, (ip, port))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443)) for ip in ips]
    def smart_mock_getaddrinfo(self, host, port, *args, **kwargs):
        if host == 'mixed.example.com':
            return self.mock_getaddrinfo(['8.8.8.8', '192.168.1.1'])
        elif host == 'example.com':
            return self.mock_getaddrinfo(['8.8.8.8'])
        elif host == 'localhost':
            return self.mock_getaddrinfo(['127.0.0.1'])
        elif host == 'internal.company.com':
            return self.mock_getaddrinfo(['10.0.0.1'])
        elif host == 'metadata.aws':
            return self.mock_getaddrinfo(['169.254.169.254'])
        elif host == 'localhost6':
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', 443, 0, 0))]
        elif host == 'mapped':
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::ffff:127.0.0.1', 443, 0, 0))]
        else:
            # When queried for an IP string like '8.8.8.8', just return it
            return self.mock_getaddrinfo([host])
    @patch('api.scanner.socket_helper.socket.socket')
    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_public_ip_permitted(self, mock_getaddrinfo, mock_socket_class):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo
        mock_sock_instance = MagicMock()
        mock_socket_class.return_value = mock_sock_instance
        
        sock = safe_create_connection(('example.com', 443))
        mock_sock_instance.connect.assert_called_with(('8.8.8.8', 443))
        self.assertEqual(sock, mock_sock_instance)

    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_loopback_blocked(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo
        with self.assertRaisesRegex(ValueError, "SSRF Protection blocked"):
            safe_create_connection(('localhost', 443))

    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_private_blocked(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo
        with self.assertRaisesRegex(ValueError, "SSRF Protection blocked"):
            safe_create_connection(('internal.company.com', 443))

    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_cloud_metadata_blocked(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo
        with self.assertRaisesRegex(ValueError, "SSRF Protection blocked"):
            safe_create_connection(('metadata.aws', 443))

    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_ipv6_loopback_blocked(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo
        with self.assertRaisesRegex(ValueError, "SSRF Protection blocked"):
            safe_create_connection(('localhost6', 443))

    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_ipv4_mapped_ipv6_blocked(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo
        with self.assertRaisesRegex(ValueError, "SSRF Protection blocked"):
            safe_create_connection(('mapped', 443))

    @patch('api.scanner.socket_helper.socket.socket')
    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_multiple_dns_results(self, mock_getaddrinfo, mock_socket_class):
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo
        
        # Should raise ValueError because ALL results must be valid
        with self.assertRaisesRegex(ValueError, "SSRF Protection blocked raw socket connection to non-public IP: 192.168.1.1"):
            safe_create_connection(('mixed.example.com', 443))
            
        mock_socket_class.assert_not_called()

    @patch('api.scanner.socket_helper.socket.socket')
    @patch('api.scanner.socket_helper.socket.getaddrinfo')
    def test_tls_sni_preserved(self, mock_getaddrinfo, mock_socket_class):
        import ssl
        mock_getaddrinfo.side_effect = self.smart_mock_getaddrinfo
        mock_sock_instance = MagicMock()
        mock_socket_class.return_value = mock_sock_instance
        
        sock = safe_create_connection(('example.com', 443))
        
        ctx = ssl.create_default_context()
        with patch.object(ctx, 'wrap_socket') as mock_wrap:
            ctx.wrap_socket(sock, server_hostname='example.com')
            mock_wrap.assert_called_with(mock_sock_instance, server_hostname='example.com')

if __name__ == '__main__':
    unittest.main()
