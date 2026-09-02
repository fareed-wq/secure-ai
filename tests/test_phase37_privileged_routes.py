import unittest
from unittest.mock import MagicMock, patch
from api.scanner.modules.javascript_security import JavaScriptSecurityModule
from api.scanner.orchestrator import scan_url

class DummyResponse:
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

class MockModule:
    def run(self, url, hostname, session):
        return [
            {"name": "Privileged API Routes Publicly Documented", "evidence": {"raw": "/api/admin"}, "severity": "Informational", "confidence": "High", "category": "api_surface", "owasp": "Not Mapped"},
            {"name": "Privileged API Surface Discovered in Client-Side Code", "evidence": {"raw": "/admin/dashboard"}, "severity": "Informational", "confidence": "High", "category": "api_surface", "owasp": "Not Mapped"}
        ]

class TestPrivilegedRoutes(unittest.TestCase):
    def setUp(self):
        self.mod = JavaScriptSecurityModule()

    @patch('api.scanner.modules.javascript_security.safe_request')
    def test_privileged_and_sequential_separation(self, mock_request):
        html_body = '<script src="/bundle.js"></script>'
        js_bundle = """
        const userRoute = "/api/users/123";
        const accountRoute = "/api/accounts/99";
        const paymentRoute = "/api/payments/42";
        const adminRoute = "/admin/dashboard";
        const apiAdminRoute = "/api/admin/users";
        """
        def mock_safe_request(method, url, **kwargs):
            if url.endswith("bundle.js"):
                return DummyResponse(200, js_bundle, {"Content-Type": "application/javascript"})
            return DummyResponse(200, html_body, {"Content-Type": "text/html"})

        mock_request.side_effect = mock_safe_request
        findings = self.mod.run("https://example.com/", "example.com", MagicMock())

        seq_findings = [f for f in findings if f["name"] == "Sequential Identifier Observed in API Route"]
        self.assertEqual(len(seq_findings), 1)
        evidence = str(seq_findings[0]["evidence"])
        self.assertIn("/api/users/123", evidence)
        self.assertIn("/api/accounts/99", evidence)

        priv_findings = [f for f in findings if f["name"] == "Privileged API Surface Discovered in Client-Side Code"]
        self.assertEqual(len(priv_findings), 1)
        priv_evidence = str(priv_findings[0]["evidence"])
        self.assertIn("/admin/dashboard", priv_evidence)
        self.assertIn("/api/admin/users", priv_evidence)
        self.assertNotIn("/api/users/123", priv_evidence)

    @patch('api.scanner.orchestrator.PASSIVE_MODULES', [MockModule()])
    @patch('api.scanner.orchestrator.validate_scan_target')
    @patch('api.scanner.orchestrator.get_metadata')
    @patch('api.scanner.orchestrator.check_liveness')
    @patch('api.scanner.transport.safe_request')
    def test_orchestrator_correlation(self, mock_safe, mock_live, mock_meta, mock_val):
        mock_safe.return_value = DummyResponse(200, '<html></html>', {'Content-Type': 'text/html'})
        mock_val.return_value = None
        mock_live.return_value = True
        mock_meta.return_value = {}

        result = scan_url("https://example.com")
        correlated = [f for f in result.get("findings", []) if f["name"] == "Privileged Application Surface Correlated"]
        self.assertEqual(len(correlated), 1)
        corr = correlated[0]
        self.assertEqual(corr["severity"], "Informational")
        self.assertEqual(corr["owasp"], "Not Mapped")
        self.assertNotIn("Broken Access Control", corr.get("description", ""))

if __name__ == "__main__":
    unittest.main()
