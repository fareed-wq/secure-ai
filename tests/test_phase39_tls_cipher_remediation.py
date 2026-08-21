import unittest
import ssl
from unittest.mock import patch, MagicMock
from api.scanner.modules.network_checks import TLSCipherStrengthModule

class TestPhase39TLSCipherRemediation(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock()
        self.module = TLSCipherStrengthModule()

    @patch('api.scanner.modules.network_checks.safe_create_connection')
    @patch('ssl.create_default_context')
    def test_modern_tls13_server_does_not_trigger_legacy_finding(self, mock_create_context, mock_create_conn):
        mock_ctx = MagicMock()
        mock_create_context.return_value = mock_ctx
        
        # Simulate TLS 1.3 strong cipher
        mock_ssock = MagicMock()
        mock_ssock.cipher.return_value = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
        
        # The first pass succeeds with a strong cipher
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock
        
        # The second pass (legacy weak cipher) should FAIL on a modern server because it rejects weak ciphers
        def mock_wrap_socket(*args, **kwargs):
            if mock_ctx.maximum_version == ssl.TLSVersion.TLSv1_2:
                raise ssl.SSLError("Handshake failed, no shared cipher")
            return MagicMock(__enter__=MagicMock(return_value=mock_ssock), __exit__=MagicMock())
        
        mock_ctx.wrap_socket.side_effect = mock_wrap_socket
        
        findings = self.module.run("https://example.com", "example.com", self.session)
        names = [f["name"] for f in findings]
        
        self.assertNotIn("Legacy Weak TLS Ciphers Supported", names)
        
        # Verify that the test context had TLSv1.2 maximum version set
        self.assertEqual(mock_ctx.maximum_version, ssl.TLSVersion.TLSv1_2)

    @patch('api.scanner.modules.network_checks.safe_create_connection')
    @patch('ssl.create_default_context')
    def test_legacy_weak_cipher_properly_detected(self, mock_create_context, mock_create_conn):
        mock_ctx = MagicMock()
        mock_create_context.return_value = mock_ctx
        
        # Simulate successful fallback to a weak cipher (e.g. 3DES)
        mock_ssock = MagicMock()
        mock_ssock.cipher.return_value = ("DES-CBC3-SHA", "TLSv1.2", 112)
        
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock
        
        findings = self.module.run("https://example.com", "example.com", self.session)
        
        weak_findings = [f for f in findings if f["name"] == "Legacy Weak TLS Ciphers Supported"]
        self.assertEqual(len(weak_findings), 1)
        
        # Verify evidence accuracy
        evidence = str(weak_findings[0]["evidence"])
        self.assertIn("DES-CBC3-SHA", evidence)
        self.assertIn("TLSv1.2", evidence)
        
        # Ensure it does not say TLS 1.3
        self.assertNotIn("TLSv1.3", evidence)

if __name__ == '__main__':
    unittest.main()
