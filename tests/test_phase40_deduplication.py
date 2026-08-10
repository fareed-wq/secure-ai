import unittest
from unittest.mock import patch, MagicMock
from api.scanner.modules.infrastructure import InfrastructureIntelligenceModule
from api.scanner.base import ScannerModule

class TestPhase40Deduplication(unittest.TestCase):

    def setUp(self):
        self.module = InfrastructureIntelligenceModule()
        self.session = MagicMock()

    @patch('api.scanner.modules.infrastructure.safe_request')
    def test_dns_infrastructure_deduplication(self, mock_safe_request):
        # Mock DNS response with 4 identical Cloudflare NS records
        ns_response = MagicMock()
        ns_response.status_code = 200
        ns_response.json.return_value = {
            "Answer": [
                {"data": "ns1.cloudflare.com"},
                {"data": "ns2.cloudflare.com"},
                {"data": "ns3.cloudflare.com"},
                {"data": "ns4.cloudflare.com"},
            ]
        }
        
        # We only care about the NS mock for this specific test
        # Let's make safe_request return the ns_response when called for NS
        # and a dummy 404 for other queries (MX)
        def side_effect(method, url, **kwargs):
            if "type=NS" in url:
                return ns_response
            resp = MagicMock()
            resp.status_code = 404
            return resp
            
        mock_safe_request.side_effect = side_effect
        
        findings = self.module.run("https://example.com", "example.com", self.session)
        
        # Check that we only got ONE Cloudflare finding
        dns_findings = [f for f in findings if f["name"] == "DNS Infrastructure Provider Identified"]
        self.assertEqual(len(dns_findings), 1)
        self.assertIn("Cloudflare", dns_findings[0]["evidence"]["raw"])

    @patch('api.scanner.modules.infrastructure.safe_request')
    def test_dns_infrastructure_distinct_providers(self, mock_safe_request):
        # Mock DNS response with 2 different providers
        ns_response = MagicMock()
        ns_response.status_code = 200
        ns_response.json.return_value = {
            "Answer": [
                {"data": "ns1.cloudflare.com"},
                {"data": "ns1.awsdns-12.com"},
            ]
        }
        
        def side_effect(method, url, **kwargs):
            if "type=NS" in url:
                return ns_response
            resp = MagicMock()
            resp.status_code = 404
            return resp
            
        mock_safe_request.side_effect = side_effect
        
        findings = self.module.run("https://example.com", "example.com", self.session)
        
        dns_findings = [f for f in findings if f["name"] == "DNS Infrastructure Provider Identified"]
        self.assertEqual(len(dns_findings), 2)
        evidences = [f["evidence"]["raw"] for f in dns_findings]
        self.assertTrue(any("Cloudflare" in e for e in evidences))
        self.assertTrue(any("AWS" in e for e in evidences))

    @patch('api.scanner.modules.infrastructure.safe_request')
    def test_mail_infrastructure_deduplication(self, mock_safe_request):
        mx_response = MagicMock()
        mx_response.status_code = 200
        mx_response.json.return_value = {
            "Answer": [
                {"data": "aspmx.l.google.com"},
                {"data": "alt1.aspmx.l.google.com"},
                {"data": "alt2.aspmx.l.google.com"},
            ]
        }
        
        def side_effect(method, url, **kwargs):
            if "type=MX" in url:
                return mx_response
            resp = MagicMock()
            resp.status_code = 404
            return resp
            
        mock_safe_request.side_effect = side_effect
        
        findings = self.module.run("https://example.com", "example.com", self.session)
        
        mx_findings = [f for f in findings if f["name"] == "Mail Infrastructure Identified"]
        self.assertEqual(len(mx_findings), 1)
        self.assertIn("Google", mx_findings[0]["evidence"]["raw"])

if __name__ == '__main__':
    unittest.main()
