import unittest
from unittest.mock import MagicMock
import requests
import json

from api.scanner.base import ScannerModule
from api.scanner.modules.discovery import ExposedFilesModule, OpenApiModule
from api.scanner.modules.headers import CORSModule

class TestPhase32CoverageAudit(unittest.TestCase):
    
    def setUp(self):
        self.session = MagicMock(spec=requests.Session)
        
    def test_openapi_swagger_ui(self):
        """Verify OpenApiModule checks /swagger-ui.html"""
        module = OpenApiModule()
        
        called_urls = []
        def mock_req(*args, **kwargs):
            called_urls.append(args[1] if len(args) > 1 else kwargs.get("url", ""))
            resp = MagicMock()
            resp.status_code = 404
            return resp
            
        self.session.request = mock_req
        module.run("http://example.com", "example.com", self.session)
        
        self.assertIn("http://example.com/swagger-ui.html", called_urls)

    def test_exposed_files_env(self):
        """Verify ExposedFilesModule checks /.env"""
        module = ExposedFilesModule()
        
        called_urls = []
        def mock_req(*args, **kwargs):
            called_urls.append(args[1] if len(args) > 1 else kwargs.get("url", ""))
            resp = MagicMock()
            resp.status_code = 404
            return resp
            
        self.session.request = mock_req
        module.run("http://example.com", "example.com", self.session)
        
        self.assertTrue(any("/.env" in url for url in called_urls))
        
    def test_cors_reflection(self):
        """Verify CORSModule detects reflection"""
        module = CORSModule()
        
        def mock_req(*args, **kwargs):
            self.assertEqual(kwargs.get("headers", {}).get("Origin"), "https://cors-test.invalid")
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {
                "Access-Control-Allow-Origin": "https://cors-test.invalid",
                "Access-Control-Allow-Credentials": "true"
            }
            return resp
            
        self.session.request = mock_req
        findings = module.run("http://example.com", "example.com", self.session)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "High")
        self.assertEqual(findings[0]["name"], "Insecure CORS Policy (Arbitrary Origin Reflection with Credentials)")

    def test_cvss_vector_generation(self):
        """Verify CVSS vector is generated from severity"""
        class DummyModule(ScannerModule):
            def run(self, url, hostname, session):
                return [self.make_finding("Test Critical", "Critical", "Desc", "Ev")]
                
        module = DummyModule()
        findings = module.run("http://test", "test", None)
        self.assertEqual(findings[0]["cvss"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")

if __name__ == '__main__':
    unittest.main()
