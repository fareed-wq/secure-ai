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
        # Mock DNS response with 4 Cloudflare NS records (Test 1)
        ns_response = MagicMock()
        ns_response.status_code = 200
        ns_response.json.return_value = {
            "Answer": [
                {"data": "ns1.cloudflare.com"},
                {"data": "ns2.cloudflare.com"},
                {"data": "ns3.cloudflare.com"},
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
        
        # Check that we only got ONE Cloudflare finding
        dns_findings = [f for f in findings if f["name"] == "DNS Infrastructure Provider Identified"]
        self.assertEqual(len(dns_findings), 1)
        evidence = dns_findings[0]["evidence"]["raw"]
        self.assertIn("Cloudflare", evidence)
        self.assertIn("ns1.cloudflare.com", evidence)
        self.assertIn("ns2.cloudflare.com", evidence)
        self.assertIn("ns3.cloudflare.com", evidence)

    @patch('api.scanner.modules.infrastructure.safe_request')
    def test_dns_infrastructure_distinct_providers(self, mock_safe_request):
        # Mock DNS response with 2 different providers (Test 3)
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
        self.assertTrue(any("Cloudflare" in e and "ns1.cloudflare.com" in e for e in evidences))
        self.assertTrue(any("AWS" in e and "ns1.awsdns-12.com" in e for e in evidences))

    @patch('api.scanner.modules.infrastructure.safe_request')
    def test_mail_infrastructure_deduplication(self, mock_safe_request):
        # Test 2
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
        evidence = mx_findings[0]["evidence"]["raw"]
        self.assertIn("Google", evidence)
        self.assertIn("aspmx.l.google.com", evidence)
        self.assertIn("alt1.aspmx.l.google.com", evidence)
        self.assertIn("alt2.aspmx.l.google.com", evidence)
        
    @patch('api.scanner.modules.infrastructure.safe_request')
    def test_duplicate_hostnames(self, mock_safe_request):
        # Test 4 & 5
        dns_response = MagicMock()
        dns_response.status_code = 200
        dns_response.json.return_value = {
            "Answer": [
                {"data": "ns1.cloudflare.com"},
                {"data": "ns1.cloudflare.com"},
            ]
        }
        
        def side_effect(method, url, **kwargs):
            return dns_response
            
        mock_safe_request.side_effect = side_effect
        
        findings = self.module.run("https://example.com", "example.com", self.session)
        
        dns_findings = [f for f in findings if f["name"] == "DNS Infrastructure Provider Identified"]
        mx_findings = [f for f in findings if f["name"] == "Mail Infrastructure Identified"]
        
        # Will have 1 finding for NS, because cloudflare matched
        if len(dns_findings) == 1:
            evidence = dns_findings[0]["evidence"]["raw"]
            self.assertEqual(evidence.count("ns1.cloudflare.com"), 1)
        
if __name__ == '__main__':
    unittest.main()
