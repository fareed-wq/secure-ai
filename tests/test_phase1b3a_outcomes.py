import unittest
from unittest.mock import patch, MagicMock
import requests

from api.scanner.core import AssessmentOutcome, ModuleResult
from api.scanner.modules.discovery import SecurityTxtModule, XmlRpcModule
from api.scanner.modules.headers import CORSModule
from api.scanner.modules.dns import DNSCAAModule

class TestPhase1B3AOutcomes(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock()
        self.url = "https://example.com/"
        self.hostname = "example.com"

    def mock_response(self, status_code=200, text="", headers=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.headers = headers or {}
        return resp

    # SecurityTxtModule Tests
    @patch('api.scanner.modules.discovery.safe_request')
    def test_security_txt_clean_success(self, mock_req):
        long_homepage = "<html><body>" + "x" * 500 + "</body></html>"
        def side_effect(method, url, **kwargs):
            if "well-known" in url:
                return self.mock_response(200, "Contact: mailto:test@example.com\nExpires: 2030-01-01T00:00:00Z", headers={"Content-Type": "text/plain"})
            return self.mock_response(200, long_homepage)
        mock_req.side_effect = side_effect
        mod = SecurityTxtModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)
        self.assertTrue(any("Valid" in f["name"] for f in result.findings))

    @patch('api.scanner.modules.discovery.safe_request')
    def test_security_txt_clean_absence(self, mock_req):
        long_homepage = "<html><body>" + "x" * 500 + "</body></html>"
        def side_effect(method, url, **kwargs):
            if "well-known" in url or "security.txt" in url:
                return self.mock_response(404)
            return self.mock_response(200, long_homepage)
        mock_req.side_effect = side_effect
        mod = SecurityTxtModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)
        self.assertTrue(any("Not Found" in f["name"] for f in result.findings))

    @patch('api.scanner.modules.discovery.safe_request')
    def test_security_txt_timeout(self, mock_req):
        mock_req.side_effect = requests.exceptions.Timeout("Timeout")
        mod = SecurityTxtModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    # XmlRpcModule Tests
    @patch('api.scanner.modules.discovery.safe_request')
    def test_xmlrpc_clean_success(self, mock_req):
        mock_req.return_value = self.mock_response(405, "XML-RPC server accepts POST requests only")
        mod = XmlRpcModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)
        self.assertTrue(any("XML-RPC" in f["name"] for f in result.findings))

    @patch('api.scanner.modules.discovery.safe_request')
    def test_xmlrpc_clean_absence(self, mock_req):
        mock_req.return_value = self.mock_response(404)
        mod = XmlRpcModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)
        self.assertEqual(len(result.findings), 0)

    @patch('api.scanner.modules.discovery.safe_request')
    def test_xmlrpc_timeout(self, mock_req):
        mock_req.side_effect = requests.exceptions.Timeout("Timeout")
        mod = XmlRpcModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    # CORSModule Tests
    @patch('api.scanner.modules.headers.safe_request')
    def test_cors_clean_success(self, mock_req):
        mock_req.return_value = self.mock_response(200, "", {"Access-Control-Allow-Origin": "*"})
        mod = CORSModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)
        self.assertTrue(any("Wildcard" in f["name"] for f in result.findings))

    @patch('api.scanner.modules.headers.safe_request')
    def test_cors_waf_block(self, mock_req):
        mock_req.return_value = self.mock_response(403)
        mod = CORSModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list) # Null outcome
        # Might return 0 findings, but it shouldn't be COMPLETED

    @patch('api.scanner.modules.headers.safe_request')
    def test_cors_timeout(self, mock_req):
        mock_req.side_effect = requests.exceptions.Timeout("Timeout")
        mod = CORSModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    # DNSCAAModule Tests
    @patch('api.scanner.modules.dns.query_doh')
    def test_dns_clean_success(self, mock_doh):
        mock_doh.return_value = {"Status": 0, "Answer": []}
        mod = DNSCAAModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, ModuleResult)
        self.assertEqual(result.assessment_outcome, AssessmentOutcome.COMPLETED)

    @patch('api.scanner.modules.dns.query_doh')
    def test_dns_timeout(self, mock_doh):
        mock_doh.return_value = None # query_doh returns None on timeout
        mod = DNSCAAModule()
        result = mod.run(self.url, self.hostname, self.session)
        self.assertIsInstance(result, list)
