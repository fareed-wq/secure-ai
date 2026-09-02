import unittest
import ssl
import datetime
from unittest.mock import patch, MagicMock
from api.scanner.modules.tls import EnhancedTLSModule

class TestTLSUpgrade(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock()
        self.module = EnhancedTLSModule()

    @patch('api.scanner.modules.tls.safe_create_connection')
    @patch('ssl.create_default_context')
    def test_cert_validation_successful(self, mock_ctx, mock_conn):
        mock_context = MagicMock()
        mock_ctx.return_value = mock_context

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {}
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock

        findings = self.module.run("https://example.com", "example.com", self.session)
        names = [f["name"] for f in findings]

        self.assertIn("Valid SSL/TLS Certificate", names)
        self.assertIn("Modern TLS 1.3 Supported", names)
        self.assertIn("Negotiated TLS Cipher Identified", names)

    @patch('api.scanner.modules.tls.safe_create_connection')
    @patch('ssl.create_default_context')
    def test_cert_validation_expired(self, mock_ctx, mock_conn):
        mock_context = MagicMock()
        mock_ctx.return_value = mock_context

        def side_effect(*args, **kwargs):
            raise ssl.SSLCertVerificationError("certificate has expired")

        mock_context.wrap_socket.side_effect = side_effect

        findings = self.module.run("https://example.com", "example.com", self.session)
        expired = [f for f in findings if f["name"] == "Expired Certificate"]

        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["severity"], "Medium")
        self.assertNotIn("Valid SSL/TLS Certificate", [f["name"] for f in findings])

    @patch('api.scanner.modules.tls.safe_create_connection')
    @patch('ssl.create_default_context')
    def test_cert_validation_hostname_mismatch(self, mock_ctx, mock_conn):
        mock_context = MagicMock()
        mock_ctx.return_value = mock_context

        def side_effect(*args, **kwargs):
            raise ssl.SSLCertVerificationError("hostname 'example.com' doesn't match")

        mock_context.wrap_socket.side_effect = side_effect

        findings = self.module.run("https://example.com", "example.com", self.session)
        mismatch = [f for f in findings if f["name"] == "Hostname Mismatch"]

        self.assertEqual(len(mismatch), 1)
        self.assertEqual(mismatch[0]["severity"], "Medium")

    @patch('api.scanner.modules.tls.safe_create_connection')
    @patch('ssl.create_default_context')
    def test_cert_validation_self_signed(self, mock_ctx, mock_conn):
        mock_context = MagicMock()
        mock_ctx.return_value = mock_context

        def side_effect(*args, **kwargs):
            raise ssl.SSLCertVerificationError("self signed certificate")

        mock_context.wrap_socket.side_effect = side_effect

        findings = self.module.run("https://example.com", "example.com", self.session)
        selfsigned = [f for f in findings if f["name"] == "Self-Signed or Untrusted Certificate"]

        self.assertEqual(len(selfsigned), 1)
        self.assertEqual(selfsigned[0]["severity"], "Medium")

    @patch('api.scanner.modules.tls.safe_create_connection')
    @patch('ssl.create_default_context')
    def test_network_timeout_no_false_passed(self, mock_ctx, mock_conn):
        mock_conn.side_effect = TimeoutError("Connection timed out")
        findings = self.module.run("https://example.com", "example.com", self.session)

        names = [f["name"] for f in findings]
        self.assertNotIn("Valid SSL/TLS Certificate", names)
        self.assertNotIn("Legacy TLS Protocols Disabled", names)

    @patch('api.scanner.modules.tls.safe_create_connection')
    @patch('ssl.create_default_context')
    def test_expiration_3_days(self, mock_ctx, mock_conn):
        mock_context = MagicMock()
        mock_ctx.return_value = mock_context
        mock_ssock = MagicMock()

        now = datetime.datetime.now(datetime.timezone.utc)
        future = now + datetime.timedelta(days=3)
        mock_ssock.getpeercert.return_value = {"notAfter": future.strftime("%b %d %H:%M:%S %Y GMT")}
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock

        findings = self.module.run("https://example.com", "example.com", self.session)
        soon = [f for f in findings if f["name"] == "Certificate Expiring Very Soon"]

        self.assertEqual(len(soon), 1)
        self.assertEqual(soon[0]["severity"], "Medium")

    @patch('api.scanner.modules.tls.safe_create_connection')
    @patch('ssl.create_default_context')
    def test_expiration_15_days(self, mock_ctx, mock_conn):
        mock_context = MagicMock()
        mock_ctx.return_value = mock_context
        mock_ssock = MagicMock()

        now = datetime.datetime.now(datetime.timezone.utc)
        future = now + datetime.timedelta(days=15)
        mock_ssock.getpeercert.return_value = {"notAfter": future.strftime("%b %d %H:%M:%S %Y GMT")}
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock

        findings = self.module.run("https://example.com", "example.com", self.session)
        soon = [f for f in findings if f["name"] == "Certificate Expiring Soon"]

        self.assertEqual(len(soon), 1)
        self.assertEqual(soon[0]["severity"], "Low")

    @patch('api.scanner.modules.tls.safe_create_connection')
    @patch('ssl.create_default_context')
    def test_expiration_60_days(self, mock_ctx, mock_conn):
        mock_context = MagicMock()
        mock_ctx.return_value = mock_context
        mock_ssock = MagicMock()

        now = datetime.datetime.now(datetime.timezone.utc)
        future = now + datetime.timedelta(days=60)
        mock_ssock.getpeercert.return_value = {"notAfter": future.strftime("%b %d %H:%M:%S %Y GMT")}
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock

        findings = self.module.run("https://example.com", "example.com", self.session)

        self.assertNotIn("Certificate Expiring Soon", [f["name"] for f in findings])
        self.assertNotIn("Certificate Expiring Very Soon", [f["name"] for f in findings])

    @patch('api.scanner.modules.tls.safe_create_connection')
    @patch('ssl.create_default_context')
    def test_legacy_tls(self, mock_ctx, mock_conn):
        mock_context = MagicMock()
        mock_ctx.return_value = mock_context
        mock_ssock = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock

        findings = self.module.run("https://example.com", "example.com", self.session)
        legacy = [f for f in findings if f["name"] == "Deprecated TLS 1.0/1.1 Supported"]

        self.assertEqual(len(legacy), 1)
        self.assertEqual(legacy[0]["severity"], "Medium")
        self.assertEqual(mock_context.minimum_version, ssl.TLSVersion.TLSv1)
        self.assertEqual(mock_context.maximum_version, ssl.TLSVersion.TLSv1_1)

    @patch('api.scanner.modules.tls.safe_create_connection')
    @patch('ssl.create_default_context')
    def test_legacy_tls_client_rejection(self, mock_ctx, mock_conn):
        mock_context = MagicMock()
        mock_ctx.return_value = mock_context

        # Simulate the client runtime rejecting the legacy protocol
        def side_effect(*args, **kwargs):
            raise ssl.SSLError("UNSUPPORTED_PROTOCOL")

        mock_context.wrap_socket.side_effect = side_effect

        findings = self.module.run("https://example.com", "example.com", self.session)

        names = [f["name"] for f in findings]
        self.assertNotIn("Deprecated TLS 1.0/1.1 Supported", names)
        self.assertNotIn("Legacy TLS Protocols Disabled", names)

    @patch('api.scanner.modules.tls.safe_create_connection')
    @patch('ssl.create_default_context')
    def test_cipher_weak(self, mock_ctx, mock_conn):
        mock_context = MagicMock()
        mock_ctx.return_value = mock_context
        mock_ssock = MagicMock()
        mock_ssock.cipher.return_value = ("RC4-SHA", "TLSv1.2", 128)
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock

        findings = self.module.run("https://example.com", "example.com", self.session)
        weak = [f for f in findings if f["name"] == "Weak TLS Cipher Negotiated"]

        self.assertEqual(len(weak), 1)
        self.assertEqual(weak[0]["severity"], "Medium")
        self.assertNotIn("Strong Cipher Enforced", [f["name"] for f in findings])

if __name__ == '__main__':
    unittest.main()
