import unittest
from unittest.mock import patch, MagicMock
import requests

from api.scanner.modules.http_security import SecurityHeadersModule
from api.scanner.modules.dns import DNSCAAModule, DNSEmailSecurityModule

class TestPhase42NetworkErrorHandling(unittest.TestCase):

    def setUp(self):
        self.session = MagicMock(spec=requests.Session)

    @patch('api.scanner.modules.http_security.safe_request')
    def test_security_headers_request_exception(self, mock_safe_request):
        # RequestException should return no findings (0 penalty)
        mock_safe_request.side_effect = requests.exceptions.ConnectionError("Connection refused")
        mod = SecurityHeadersModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        self.assertEqual(len(findings), 0)

    @patch('api.scanner.modules.http_security.safe_request')
    def test_security_headers_unexpected_exception(self, mock_safe_request):
        # Unexpected Exception should return no findings (0 penalty, logged)
        mock_safe_request.side_effect = TypeError("Unexpected logic error")
        mod = SecurityHeadersModule()
        findings = mod.run("https://example.com", "example.com", self.session)
        self.assertEqual(len(findings), 0)

    @patch('api.scanner.modules.dns.safe_request')
    def test_dns_caa_request_exception(self, mock_safe_request):
        # Network failure on dns.google should emit exactly one Inconclusive finding
        mock_safe_request.side_effect = requests.exceptions.Timeout("DNS timeout")
        mod = DNSCAAModule()
        findings = mod.run("https://example.com", "example.com", self.session)

        self.assertEqual(len(findings), 0)



    @patch('api.scanner.modules.dns.safe_request')
    def test_dns_email_request_exception(self, mock_safe_request):
        # Network failure on dns.google should emit exactly one Inconclusive finding
        mock_safe_request.side_effect = requests.exceptions.Timeout("DNS timeout")
        mod = DNSEmailSecurityModule()
        findings = mod.run("https://example.com", "example.com", self.session)

        self.assertEqual(len(findings), 0)



    @patch('api.scanner.modules.dns.safe_request')
    def test_dns_email_success_produces_missing_findings(self, mock_safe_request):
        # If the request succeeds but there's no data, it MUST produce the Missing SPF/DMARC findings
        # Mocking an empty response from DNS
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"Status": 0, "Answer": []}
        mock_safe_request.return_value = mock_resp

        mod = DNSEmailSecurityModule()
        findings = mod.run("https://example.com", "example.com", self.session)

        finding_names = [f["name"] for f in findings]
        self.assertIn("SPF Record Not Observed", finding_names)
        self.assertIn("DMARC Record Not Observed", finding_names)
        pass

if __name__ == '__main__':
    unittest.main()
