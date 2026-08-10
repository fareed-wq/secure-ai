import unittest
from unittest.mock import patch, MagicMock
from api.scanner.modules.network_checks import TLSCipherStrengthModule, SubdomainProbingModule
from api.scanner.modules.http_security import HTTPSRedirectModule, AdvancedSecurityHeadersModule
from api.scanner.modules.discovery import SitemapModule
import ssl

class TestPhase33CoverageAccuracy(unittest.TestCase):

    @patch('api.scanner.modules.network_checks.safe_create_connection')
    @patch('ssl.create_default_context')
    def test_tls_cipher_strength_weak(self, mock_ctx, mock_conn):
        """Test TLSCipherStrengthModule detects weak ciphers."""
        mod = TLSCipherStrengthModule()
        
        # Mock connection 1: Initial check
        mock_sock1 = MagicMock()
        mock_sock1.cipher.return_value = ("TLS_RSA_WITH_AES_128_CBC_SHA", "TLSv1.2", 112)
        
        # Mock connection 2: Downgrade check (succeeds with weak cipher)
        mock_sock2 = MagicMock()
        mock_sock2.cipher.return_value = ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLSv1.0", 112)
        
        # Make safe_create_connection return a context manager that yields our mock sock
        mock_conn_cm1 = MagicMock()
        mock_conn_cm1.__enter__.return_value = mock_sock1
        
        mock_conn_cm2 = MagicMock()
        mock_conn_cm2.__enter__.return_value = mock_sock2
        
        mock_conn.side_effect = [mock_conn_cm1, mock_conn_cm2]
        
        # Mock context.wrap_socket
        mock_ctx_instance = MagicMock()
        mock_ctx_instance.wrap_socket.return_value.__enter__.return_value = mock_sock1
        
        mock_ctx_instance_2 = MagicMock()
        mock_ctx_instance_2.wrap_socket.return_value.__enter__.return_value = mock_sock2
        mock_ctx.side_effect = [mock_ctx_instance, mock_ctx_instance_2]
        
        findings = mod.run("https://example.com", "example.com", MagicMock())
        
        self.assertTrue(any("Legacy Weak TLS Ciphers Supported" in f["name"] for f in findings))
        self.assertTrue(any("Weak TLS Cipher Negotiated" in f["name"] for f in findings))

    @patch('api.scanner.modules.network_checks.safe_create_connection')
    @patch('ssl.create_default_context')
    def test_tls_cipher_strength_strong(self, mock_ctx, mock_conn):
        """Test TLSCipherStrengthModule detects strong ciphers and no downgrade."""
        mod = TLSCipherStrengthModule()
        
        mock_sock1 = MagicMock()
        mock_sock1.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        
        mock_conn_cm1 = MagicMock()
        mock_conn_cm1.__enter__.return_value = mock_sock1
        
        # Make the second connection fail with SSLError
        mock_conn_cm2 = MagicMock()
        mock_conn_cm2.__enter__.side_effect = ssl.SSLError("HANDSHAKE_FAILURE")
        
        mock_conn.side_effect = [mock_conn_cm1, mock_conn_cm2]
        
        mock_ctx_instance = MagicMock()
        mock_ctx_instance.wrap_socket.return_value.__enter__.return_value = mock_sock1
        mock_ctx.return_value = mock_ctx_instance
        
        findings = mod.run("https://example.com", "example.com", MagicMock())
        
        self.assertTrue(any("Strong TLS Cipher Suite Enforced" in f["name"] for f in findings))
        self.assertFalse(any("Weak" in f["name"] for f in findings))

    @patch('api.scanner.modules.network_checks.safe_request')
    def test_subdomain_probing_functional(self, mock_req):
        """Test SubdomainProbingModule functionality."""
        mod = SubdomainProbingModule()
        
        def side_effect(*args, **kwargs):
            url = args[1]
            if "api.example.com" in url:
                return MagicMock(status_code=200, __bool__=lambda self: True)
            else:
                return None # The module ignores if resp is None
            
        mock_req.side_effect = side_effect
        
        with patch('api.scanner.modules.network_checks.Config.COMMON_SUBDOMAINS', ['api', 'dev', 'stage']):
            findings = mod.run("https://example.com", "example.com", MagicMock())
        
        self.assertEqual(len(findings), 1)
        self.assertIn("Active Subdomain Found: api.example.com", findings[0]["name"])
        self.assertEqual(findings[0]["severity"], "Informational")

    def test_https_redirect_missing(self):
        """Test HTTPSRedirectModule when redirect is missing."""
        mod = HTTPSRedirectModule()
        session = MagicMock()
        
        # Mock the cleartext HTTP request returning 200 OK (no redirect)
        resp = MagicMock()
        resp.url = "http://example.com/"
        resp.status_code = 200
        session.get.return_value = resp
        
        with patch('api.scanner.modules.http_security.safe_request', return_value=resp):
            findings = mod.run("https://example.com", "example.com", session)
            
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "Missing HTTPS Redirection")
        self.assertEqual(findings[0]["severity"], "High")

    def test_sitemap_missing(self):
        """Test SitemapModule when sitemap is missing."""
        mod = SitemapModule()
        
        resp = MagicMock()
        resp.status_code = 404
        
        with patch('api.scanner.modules.discovery.safe_request', return_value=resp):
            findings = mod.run("https://example.com", "example.com", MagicMock())
            
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "sitemap.xml Missing")
        self.assertEqual(findings[0]["severity"], "Informational")

    def test_advanced_security_headers_missing(self):
        """Test AdvancedSecurityHeadersModule when headers are missing."""
        mod = AdvancedSecurityHeadersModule()
        
        resp = MagicMock()
        resp.headers = {}
        resp.url = "https://example.com"
        
        # We need a proper get_header_safe mock, or just rely on the base class one
        findings = mod.run("https://example.com", "example.com", MagicMock())
        
        # In reality the run() method takes resp from a self.safe_request or passed in?
        # Actually it calls get_header_safe on the passed in response? Wait, no, it makes a safe_request itself.
        
        with patch('api.scanner.modules.http_security.safe_request', return_value=resp):
            findings = mod.run("https://example.com", "example.com", MagicMock())
            
        self.assertEqual(len(findings), 3)
        finding_names = [f["name"] for f in findings]
        self.assertIn("Missing COOP Header", finding_names)
        self.assertIn("Missing COEP Header", finding_names)
        self.assertIn("Missing CORP Header", finding_names)

if __name__ == '__main__':
    unittest.main()
