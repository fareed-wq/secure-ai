import unittest
from unittest.mock import patch, MagicMock
import requests
import json
from api.scanner.modules.api_web_security import ApiWebSecurityModule

class TestJsonCacheFix(unittest.TestCase):
    def setUp(self):
        self.session = requests.Session()
        self.hostname = "example.com"
        self.module = ApiWebSecurityModule()

    def make_mock(self, path, ct, cache, body, is_json_valid=True):
        mock_resp = MagicMock()
        mock_resp.history = []
        mock_resp.url = "https://example.com" + path
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": ct, "Cache-Control": cache}
        mock_resp.text = body
        if is_json_valid:
            mock_resp.json.return_value = json.loads(body) if body.startswith("{") else {}
        else:
            mock_resp.json.side_effect = ValueError("Invalid JSON")
        return mock_resp

    @patch("api.scanner.modules.api_web_security.safe_request")
    def test_html_negative(self, mock_safe_request):
        # HTML Negative test
        mock_resp = self.make_mock(
            "/api/app-page",
            "text/html; charset=utf-8",
            "public, max-age=0, must-revalidate",
            "<html>...</html>",
            is_json_valid=False
        )
        mock_safe_request.side_effect = [mock_resp, None]
        findings = self.module.run(mock_resp.url, self.hostname, self.session)
        names = [f["name"] for f in findings]
        self.assertNotIn("Publicly Cacheable JSON Response Observed", names)

    @patch("api.scanner.modules.api_web_security.safe_request")
    def test_json_positive(self, mock_safe_request):
        mock_resp = self.make_mock(
            "/api/public-json",
            "application/json",
            "public, max-age=300",
            '{"status":"ok","service":"public-demo"}'
        )
        mock_safe_request.side_effect = [mock_resp, None]
        findings = self.module.run(mock_resp.url, self.hostname, self.session)
        names = [f["name"] for f in findings]
        self.assertIn("Publicly Cacheable JSON Response Observed", names)

    @patch("api.scanner.modules.api_web_security.safe_request")
    def test_additional_negatives(self, mock_safe_request):
        # application/json, Cache-Control: private
        mock1 = self.make_mock("/api/priv", "application/json", "private, max-age=300", '{"data":1}')
        mock_safe_request.side_effect = [mock1, None]
        findings1 = self.module.run(mock1.url, self.hostname, self.session)
        self.assertNotIn("Publicly Cacheable JSON Response Observed", [f["name"] for f in findings1])

        # application/json, Cache-Control: no-store
        mock2 = self.make_mock("/api/nostore", "application/json", "no-store", '{"data":1}')
        mock_safe_request.side_effect = [mock2, None]
        findings2 = self.module.run(mock2.url, self.hostname, self.session)
        self.assertNotIn("Publicly Cacheable JSON Response Observed", [f["name"] for f in findings2])

        # application/json, invalid JSON body
        mock3 = self.make_mock("/api/invalid", "application/json", "public, max-age=300", 'Not a JSON', is_json_valid=False)
        mock_safe_request.side_effect = [mock3, None]
        findings3 = self.module.run(mock3.url, self.hostname, self.session)
        self.assertNotIn("Publicly Cacheable JSON Response Observed", [f["name"] for f in findings3])

        # text/html, valid JSON-looking text, Cache-Control: public
        mock4 = self.make_mock("/api/htmljson", "text/html", "public, max-age=300", '{"status":"ok"}', is_json_valid=True)
        mock_safe_request.side_effect = [mock4, None]
        findings4 = self.module.run(mock4.url, self.hostname, self.session)
        self.assertNotIn("Publicly Cacheable JSON Response Observed", [f["name"] for f in findings4])

        # application/problem+json, valid JSON, Cache-Control: public
        mock5 = self.make_mock("/api/problem", "application/problem+json", "public, max-age=300", '{"status":"ok"}', is_json_valid=True)
        mock_safe_request.side_effect = [mock5, None]
        findings5 = self.module.run(mock5.url, self.hostname, self.session)
        self.assertIn("Publicly Cacheable JSON Response Observed", [f["name"] for f in findings5])

if __name__ == '__main__':
    unittest.main()
