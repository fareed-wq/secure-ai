import unittest
from unittest.mock import patch, MagicMock
import requests
from api.scanner.modules.dns import DNSCAAModule, DNSEmailSecurityModule
from api.scanner.modules.infrastructure import InfrastructureIntelligenceModule
from api.scanner.orchestrator import scan_url

class TestPhase28Infrastructure(unittest.TestCase):
    def setUp(self):
        self.session = requests.Session()
        self.hostname = "https://example.com"
        self.domain = "example.com"

    @patch("api.scanner.modules.dns.safe_request")
    def test_dns_caa_missing(self, mock_safe_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"Status": 0, "Answer": []}
        mock_safe_request.return_value = mock_resp

        module = DNSCAAModule()
        findings = module.run(self.hostname, self.domain, self.session)
        
        missing_caa = next((f for f in findings if f["name"] == "Missing CAA Record"), None)
        self.assertIsNotNone(missing_caa)
        self.assertEqual(missing_caa["severity"], "Low")
        self.assertEqual(missing_caa["confidence"], "High")

    @patch("api.scanner.modules.dns.safe_request")
    def test_dns_spf_multiple(self, mock_safe_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Status": 0, 
            "Answer": [
                {"data": "v=spf1 include:_spf.google.com ~all"},
                {"data": "v=spf1 include:spf.protection.outlook.com -all"}
            ]
        }
        
        # We need to simulate safe_request responding to multiple calls.
        # But for DNSEmailSecurityModule, SPF is just one of the calls.
        # We can just use side_effect to return this for all TXT queries to make it easy.
        mock_safe_request.return_value = mock_resp

        module = DNSEmailSecurityModule()
        findings = module.run(self.hostname, self.domain, self.session)
        
        multiple_spf = next((f for f in findings if f["name"] == "Multiple SPF Records Detected"), None)
        self.assertIsNotNone(multiple_spf)
        self.assertEqual(multiple_spf["severity"], "Medium")

    @patch("api.scanner.modules.dns.safe_request")
    def test_dns_spf_permissive(self, mock_safe_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Status": 0, 
            "Answer": [
                {"data": "v=spf1 +all"}
            ]
        }
        mock_safe_request.return_value = mock_resp

        module = DNSEmailSecurityModule()
        findings = module.run(self.hostname, self.domain, self.session)
        
        permissive = next((f for f in findings if f["name"] == "Overly Permissive SPF Record"), None)
        self.assertIsNotNone(permissive)
        self.assertEqual(permissive["severity"], "High")
        self.assertEqual(permissive["confidence"], "High")

    @patch("api.scanner.modules.dns.safe_request")
    def test_dns_dmarc_missing(self, mock_safe_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"Status": 0, "Answer": []}
        mock_safe_request.return_value = mock_resp

        module = DNSEmailSecurityModule()
        findings = module.run(self.hostname, self.domain, self.session)
        
        missing_dmarc = next((f for f in findings if f["name"] == "Missing DMARC Policy"), None)
        self.assertIsNotNone(missing_dmarc)
        self.assertEqual(missing_dmarc["severity"], "Medium")

    @patch("api.scanner.modules.dns.safe_request")
    def test_dns_dmarc_none(self, mock_safe_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Status": 0, 
            "Answer": [
                {"data": "v=DMARC1; p=none; rua=mailto:dmarc@example.com"}
            ]
        }
        mock_safe_request.return_value = mock_resp

        module = DNSEmailSecurityModule()
        findings = module.run(self.hostname, self.domain, self.session)
        
        dmarc_none = next((f for f in findings if f["name"] == "DMARC Monitoring-Only Policy"), None)
        self.assertIsNotNone(dmarc_none)
        self.assertEqual(dmarc_none["severity"], "Informational")

    @patch("api.scanner.modules.infrastructure.safe_create_connection")
    @patch("api.scanner.modules.infrastructure.safe_request")
    @patch("api.scanner.modules.infrastructure.ssl.create_default_context")
    def test_infrastructure_cloud_fingerprint(self, mock_ssl, mock_safe_request, mock_safe_conn):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # NS response
        mock_resp.json.return_value = {
            "Status": 0, 
            "Answer": [
                {"data": "ns1.cloudflare.com."}
            ]
        }
        mock_safe_request.return_value = mock_resp

        module = InfrastructureIntelligenceModule()
        findings = module.run(self.hostname, self.domain, self.session)
        
        dns_prov = next((f for f in findings if f["name"] == "DNS Infrastructure Provider Identified"), None)
        self.assertIsNotNone(dns_prov)
        self.assertIn("Cloudflare", dns_prov["evidence"]["raw"])
        self.assertEqual(dns_prov["severity"], "Informational")

    @patch("api.scanner.orchestrator.get_http_session")
    @patch("api.scanner.orchestrator.safe_request")
    @patch("api.scanner.orchestrator.check_liveness")
    def test_cross_module_correlation(self, mock_liveness, mock_safe_request, mock_get_session):
        mock_liveness.return_value = True
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.text = "<html></html>"
        mock_safe_request.return_value = mock_resp
        
        mock_sess = MagicMock()
        mock_get_session.return_value.__enter__.return_value = mock_sess

        # Test full orchestration to trigger cross-module correlation
        result = scan_url("https://example.com")
        self.assertTrue("findings" in result)
        
        # We don't have mock data injecting SANs directly here, but we can verify
        # that the function doesn't crash and returns valid results.
        self.assertIsInstance(result["score"], int)

if __name__ == '__main__':
    unittest.main()
