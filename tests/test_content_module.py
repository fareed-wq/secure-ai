import unittest
from unittest.mock import patch, MagicMock
import requests
from api.scanner.transport import safe_request, get_http_session
from api.scanner.core import Config

class Test(unittest.TestCase):
    def setUp(self):
        self.url = "https://example.com"
        self.hostname = "example.com"
        self.session = get_http_session()

    def mock_response(self, status_code=200, text="", headers=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.headers = headers or {}
        # mock iter_content for streaming
        resp.iter_content = lambda chunk_size: [text.encode('utf-8')]
        return resp

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_public_js_url(self, mock_safe_request):
        # Initial HTML response containing a public JS URL
        html_resp = self.mock_response(text='<script src="https://example.com/app.js"></script>')
        # JS response containing a fake secret to trigger a finding
        js_resp = self.mock_response(text='var AWS_ACCESS_KEY_ID = "AKIAQWERTYUIOPASDFGH";')
        
        mock_safe_request.side_effect = [html_resp, js_resp]
        
        from api.scanner.modules.javascript_security import JavaScriptSecurityModule
        module = JavaScriptSecurityModule()
        findings = module.run(self.url, self.hostname, self.session)
        
        # Verify safe_request was called for the JS bundle
        js_calls = [c for c in mock_safe_request.call_args_list if len(c[0]) >= 2 and c[0][1] == "https://example.com/app.js"]
        self.assertTrue(len(js_calls) > 0, "safe_request should have been called for app.js")
        
        # Verify finding was generated
        if not any("Secret Key Exposed" in f['name'] for f in findings):
            print("FAILED FINDINGS:", findings)
        self.assertTrue(any("Secret Key Exposed" in f['name'] for f in findings))

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_public_map_url(self, mock_safe_request):
        # Initial HTML response containing a public JS URL
        html_resp = self.mock_response(text='<script src="https://example.com/app.js"></script>')
        # JS response containing a source map comment
        js_resp = self.mock_response(text='console.log("hello");\n//# sourceMappingURL=app.js.map')
        # Map response
        map_resp = self.mock_response(text='{"version":3,"file":"app.js","sources":["app.ts"]}')
        
        mock_safe_request.side_effect = [html_resp, js_resp, map_resp]
        
        from api.scanner.modules.javascript_security import JavaScriptSecurityModule
        module = JavaScriptSecurityModule()
        findings = module.run(self.url, self.hostname, self.session)
        
        # Verify safe_request was called for the map URL
        map_calls = [c for c in mock_safe_request.call_args_list if len(c[0]) >= 2 and "app.js.map" in c[0][1]]
        self.assertTrue(len(map_calls) > 0, "safe_request should have been called for app.js.map")
        
        # Verify finding was generated
        self.assertTrue(any("Source Map" in f['name'] for f in findings))

    @patch('api.scanner.transport.requests.Session.request')
    def test_internal_js_url(self, mock_request):
        # We patch session.request so safe_request runs normally but the actual HTTP request is mocked
        # First, mock the request for the initial URL (example.com is public)
        html_resp = self.mock_response(text='<script src="http://169.254.169.254/latest/meta-data/"></script>')
        html_resp.is_redirect = False
        mock_request.return_value = html_resp
        
        from api.scanner.modules.javascript_security import JavaScriptSecurityModule
        module = JavaScriptSecurityModule()
        with patch.object(self.session, 'get') as mock_session_get:
            findings = module.run(self.url, self.hostname, self.session)
            
            # The second safe_request call for the internal IP should throw RequestException inside safe_request and return None
            # So session.request should ONLY have been called for example.com
            self.assertEqual(mock_request.call_count, 1)
            self.assertEqual(mock_request.call_args[0][1], "https://example.com")
            
            # Direct session.get must NEVER be called
            mock_session_get.assert_not_called()

    @patch('api.scanner.transport.requests.Session.request')
    def test_internal_map_url(self, mock_request):
        # Initial URL is public, returns JS with an internal source map
        html_resp = self.mock_response(text='<script src="https://example.com/app.js"></script>')
        html_resp.is_redirect = False
        
        js_resp = self.mock_response(text='console.log("hello");\n//# sourceMappingURL=http://169.254.169.254/map')
        js_resp.is_redirect = False
        
        mock_request.side_effect = [html_resp, js_resp]
        
        from api.scanner.modules.javascript_security import JavaScriptSecurityModule
        module = JavaScriptSecurityModule()
        with patch.object(self.session, 'get') as mock_session_get:
            findings = module.run(self.url, self.hostname, self.session)
            
            # session.request called for example.com and example.com/app.js
            self.assertEqual(mock_request.call_count, 2)
            
            # Direct session.get must NEVER be called
            mock_session_get.assert_not_called()

if __name__ == '__main__':
    unittest.main()
