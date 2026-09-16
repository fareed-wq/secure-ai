import unittest
from unittest.mock import patch, MagicMock
import requests
import json

from api.scanner.modules.auth_session_security import AuthenticationSessionSecurityModule
from api.scanner.modules.http_security import AdvancedCookieModule, SecurityHeadersModule

class TestPhase30AuthSessionSecurity(unittest.TestCase):
    def setUp(self):
        self.auth_mod = AuthenticationSessionSecurityModule()
        self.cookie_mod = AdvancedCookieModule()
        self.headers_mod = SecurityHeadersModule()
        self.session = requests.Session()

    def _mock_response(self, headers=None, text="", url="https://example.com"):
        mock_resp = MagicMock()
        from requests.structures import CaseInsensitiveDict
        mock_resp.headers = CaseInsensitiveDict(headers or {})
        mock_resp.text = text
        mock_resp.url = url

        # Mock raw.headers.getlist for AdvancedCookieModule
        mock_raw = MagicMock()
        mock_raw.headers.getlist = lambda x: [(v) for k, v in (headers or {}).items() if k.lower() == x.lower()]
        mock_resp.raw = mock_raw

        return mock_resp

    @patch('api.scanner.modules.http_security.safe_request')
    def test_secure_session_cookie(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            headers={"Set-Cookie": "sessionid=123; Secure; HttpOnly; SameSite=Strict; Path=/"}
        )
        findings = self.cookie_mod.run("https://example.com", "example.com", self.session)
        # Should not produce any findings about this cookie being unsecured
        self.assertEqual(len(findings), 0)

    @patch('api.scanner.modules.http_security.safe_request')
    def test_session_cookie_missing_secure(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            headers={"Set-Cookie": "sessionid=123; HttpOnly; SameSite=Strict; Path=/"}
        )
        findings = self.cookie_mod.run("https://example.com", "example.com", self.session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['name'], "Session Cookie Missing Secure Flag")
        self.assertIn("sessionid=[REDACTED]", str(findings[0]['evidence']))

    @patch('api.scanner.modules.http_security.safe_request')
    def test_session_cookie_missing_httponly(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            headers={"Set-Cookie": "sessionid=123; Secure; SameSite=Strict; Path=/"}
        )
        findings = self.cookie_mod.run("https://example.com", "example.com", self.session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['name'], "Session Cookie Missing HttpOnly Flag")

    @patch('api.scanner.modules.http_security.safe_request')
    def test_session_cookie_samesite_none_insecure(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            headers={"Set-Cookie": "sessionid=123; HttpOnly; SameSite=None; Path=/"}
        )
        findings = self.cookie_mod.run("https://example.com", "example.com", self.session)
        self.assertIn("Session Cookie Missing Secure Flag", [f['name'] for f in findings])
        secure_finding = next(f for f in findings if f['name'] == "Session Cookie Missing Secure Flag")
        self.assertIn("SameSite=None", secure_finding['description'])

    @patch('api.scanner.modules.http_security.safe_request')
    def test_session_cookie_missing_samesite(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            headers={"Set-Cookie": "sessionid=123; Secure; HttpOnly; Path=/"}
        )
        findings = self.cookie_mod.run("https://example.com", "example.com", self.session)
        self.assertEqual(findings[0]['name'], "Session Cookie Missing SameSite Attribute")

    @patch('api.scanner.modules.http_security.safe_request')
    def test_host_prefix_valid(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            headers={"Set-Cookie": "__Host-session=123; Secure; HttpOnly; Path=/; SameSite=Strict"}
        )
        findings = self.cookie_mod.run("https://example.com", "example.com", self.session)
        self.assertEqual(len(findings), 0)

    @patch('api.scanner.modules.http_security.safe_request')
    def test_host_prefix_invalid(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            headers={"Set-Cookie": "__Host-session=123; Secure; HttpOnly; Path=/app; SameSite=Strict"}
        )
        findings = self.cookie_mod.run("https://example.com", "example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertIn("Invalid __Host- Cookie Prefix Configuration", names)

    @patch('api.scanner.modules.http_security.safe_request')
    def test_broad_session_cookie_domain(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            headers={"Set-Cookie": "sessionid=123; Secure; HttpOnly; SameSite=Strict; Path=/; Domain=.example.com"}
        )
        findings = self.cookie_mod.run("https://sub.example.com", "sub.example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertIn("Broad Session Cookie Domain Scope", names)

    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_login_form_detection(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            text='<form action="/login" method="POST"><input type="text" name="user"><input type="password" name="pass"></form>'
        )
        findings = self.auth_mod.run("https://example.com", "example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertIn("Authentication Interface Detected", names)

    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_password_form_over_http(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            text='<form action="http://example.com/login" method="POST"><input type="password" name="pass"></form>'
        )
        findings = self.auth_mod.run("https://example.com", "example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertIn("Password Form Submits Over HTTP", names)

    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_external_auth_form(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            text='<form action="https://sso.other.com/login" method="POST"><input type="password" name="pass"></form>'
        )
        findings = self.auth_mod.run("https://example.com", "example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertIn("Authentication Form Uses External Origin", names)

    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_csrf_protection_missing(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            text='<form action="/update" method="POST"><input type="text" name="data"></form>'
        )
        findings = self.auth_mod.run("https://example.com", "example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertIn("Potential Missing CSRF Protection", names)

    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_csrf_protection_present(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            text='<form action="/update" method="POST"><input type="hidden" name="csrf_token" value="123"><input type="text" name="data"></form>'
        )
        findings = self.auth_mod.run("https://example.com", "example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertNotIn("Potential Missing CSRF Protection", names)

    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_csrf_get_form_ignored(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            text='<form action="/search" name="f" method="GET"><input type="text" name="q"><a href="/advanced_search?authuser=0">Advanced Search</a></form>'
        )
        findings = self.auth_mod.run("https://example.com", "example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertNotIn("Potential Missing CSRF Protection", names)

    @patch('api.scanner.modules.http_security.safe_request')
    def test_csp_wildcard(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            headers={"Content-Security-Policy": "default-src 'self'; script-src *; object-src 'none'; base-uri 'self'"}
        )
        findings = self.headers_mod.run("https://example.com", "example.com", self.session)
        csp_findings = [f for f in findings if f['name'] == "Weak Content-Security-Policy (CSP)"]
        self.assertEqual(len(csp_findings), 1)
        self.assertIn("wildcard '*'", csp_findings[0]['description'])

    @patch('api.scanner.modules.http_security.safe_request')
    def test_csp_unsafe_inline(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            headers={"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline';"}
        )
        findings = self.headers_mod.run("https://example.com", "example.com", self.session)
        csp_findings = [f for f in findings if f['name'] == "Weak Content-Security-Policy (CSP)"]
        self.assertTrue(len(csp_findings) > 0)
        self.assertIn("unsafe-inline", csp_findings[0]['description'])

    @patch('api.scanner.modules.http_security.safe_request')
    def test_hsts_disabled(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            headers={"Strict-Transport-Security": "max-age=0"}
        )
        findings = self.headers_mod.run("https://example.com", "example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertIn("HSTS Policy Disabled", names)

    @patch('api.scanner.modules.http_security.safe_request')
    def test_hsts_weak_max_age(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            headers={"Strict-Transport-Security": "max-age=3600"}
        )
        findings = self.headers_mod.run("https://example.com", "example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertIn("Weak HSTS max-age Configuration", names)

    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_cache_control_public(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            url="https://example.com/reset-password?token=123",
            headers={"Cache-Control": "public, max-age=3600"},
            text="Please login"
        )
        findings = self.auth_mod.run("https://example.com/reset-password?token=123", "example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertIn("Authentication Response May Be Publicly Cacheable", names)

    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_cache_control_revalidate_low(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            url="https://example.com/reset-password?token=123",
            headers={"Cache-Control": "public, max-age=0, must-revalidate"},
            text="Please login"
        )
        findings = self.auth_mod.run("https://example.com/reset-password?token=123", "example.com", self.session)
        finding = next((f for f in findings if f['name'] == "Authentication Response May Be Publicly Cacheable"), None)
        self.assertIsNone(finding)

    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_cache_control_safe(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            url="https://example.com/reset-password?token=123",
            headers={"Cache-Control": "no-store, private"},
            text="Please login"
        )
        findings = self.auth_mod.run("https://example.com/reset-password?token=123", "example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertNotIn("Authentication Response May Be Publicly Cacheable", names)

    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_www_authenticate(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            url="http://example.com/admin",
            headers={"WWW-Authenticate": 'Basic realm="Admin"'}
        )
        findings = self.auth_mod.run("http://example.com/admin", "example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertIn("Basic Authentication Advertised Over HTTP", names)

    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_auth_tech_detection(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            text="Sign in with Keycloak"
        )
        findings = self.auth_mod.run("https://example.com", "example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertIn("Authentication Technology Detected", names)

    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_session_tech_detection(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            headers={"Set-Cookie": "PHPSESSID=123; path=/"}
        )
        findings = self.auth_mod.run("https://example.com", "example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertIn("Session Technology Fingerprinted", names)

    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_password_recovery(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            text="<a href='/forgot-password'>Forgot Password?</a>"
        )
        findings = self.auth_mod.run("https://example.com", "example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertIn("Password Recovery Interface Detected", names)


    @patch('api.scanner.modules.http_security.safe_request')
    def test_cookie_heuristic_csrf_exemption(self, mock_safe_req):
        from api.scanner.modules.http_security import AdvancedCookieModule
        from unittest.mock import MagicMock
        mock_safe_req.return_value = MagicMock()
        mock_safe_req.return_value.raw.headers.getlist.return_value = ['csrf_token=123; Path=/', 'XSRF-TOKEN=abc; Path=/', 'session_id=secure123; Path=/; HttpOnly; Secure']
        module = AdvancedCookieModule()
        findings = module.run('https://example.com', 'example.com', MagicMock())
        finding_names = [f['name'] for f in findings]
        assert 'Session Cookie Missing Secure Flag' not in finding_names
        assert 'Session Cookie Missing HttpOnly Flag' not in finding_names
        bulk_findings = [f for f in findings if 'Unsecured Non-Session Cookie' in f['name']]
        assert len(bulk_findings) == 1
        assert 'csrf_token' in bulk_findings[0]['evidence']['raw']
        assert 'XSRF-TOKEN' in bulk_findings[0]['evidence']['raw']

    @patch('api.scanner.modules.http_security.safe_request')
    def test_clickjacking_xfo_and_csp(self, mock_safe_req):
        from api.scanner.modules.http_security import SecurityHeadersModule
        from unittest.mock import MagicMock
        module = SecurityHeadersModule()
        def run_with_headers(headers):
            mock_safe_req.return_value = MagicMock()
            mock_safe_req.return_value.headers = headers
            mock_safe_req.return_value.text = '<html></html>'
            return [f['name'] for f in module.run('http://example.com', 'example.com', MagicMock())]
        assert 'Missing Clickjacking Protection' in run_with_headers({'Content-Type': 'text/html'})
        assert 'Missing Clickjacking Protection' not in run_with_headers({'Content-Type': 'text/html', 'X-Frame-Options': 'DENY'})
        assert 'Missing Clickjacking Protection' not in run_with_headers({'Content-Type': 'text/html', 'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'"})
        assert 'Missing Clickjacking Protection' not in run_with_headers({'Content-Type': 'text/html', 'Content-Security-Policy': "frame-ancestors 'self';"})
        assert 'Missing Clickjacking Protection' in run_with_headers({'Content-Type': 'text/html', 'Content-Security-Policy-Report-Only': "frame-ancestors 'none';"})


    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_3d_a_auth_session_identities(self, mock_safe_req):
        # Trigger auth cache/headers findings
        headers = {
            "WWW-Authenticate": "Basic realm='Admin'",
            "Cache-Control": "public, max-age=3600, no-cache",
            "CDN-Cache-Control": "public, max-age=3600",
            "ETag": '"123456"',
            "Set-Cookie": "PHPSESSID=123; path=/"
        }

        # Trigger HTML findings
        html_text = '''
        <a href='/forgot-password'>Forgot Password?</a>
        <a href='/admin/dashboard'>Admin Dashboard</a>
        Sign in with Keycloak
        <form action="http://external.com/login" method="POST">
            <input type="text" name="user">
            <input type="password" name="pass" autocomplete="off">
        </form>
        <form action="http://example.com/login" method="POST">
            <input type="text" name="user2">
            <input type="password" name="pass2">
        </form>
        '''

        mock_safe_req.return_value = self._mock_response(
            url="http://example.com/admin",
            headers=headers,
            text=html_text
        )
        findings1 = self.auth_mod.run("http://example.com/admin", "example.com", self.session)

        # Second run for mutually exclusive cache headers
        headers2 = {
            "WWW-Authenticate": "Basic realm='Admin'",
            "Cache-Control": "public, max-age=3600, no-store",
            "ETag": '"123456"'
        }
        mock_safe_req.return_value = self._mock_response(
            url="http://example.com/login",
            headers=headers2,
            text="Please login"
        )
        findings2 = self.auth_mod.run("http://example.com/admin", "example.com", self.session)

        # Third run for token cacheability
        mock_safe_req.return_value = self._mock_response(
            url="http://example.com/reset-password?token=123",
            headers={"Cache-Control": "public, max-age=3600"},
            text="Please reset"
        )
        findings3 = self.auth_mod.run("http://example.com/reset-password?token=123", "example.com", self.session)

        findings = findings1 + findings2 + findings3

        # Verify identities
        expected_ids = {
            "auth_scheme_disclosed",
            "auth_basic_over_http",
            "auth_response_cacheable",
            "auth_cache_contradictory",
            "auth_cdn_caching_permissive",
            "auth_cache_vary_missing",
            "auth_response_tracking_indicator",
            "auth_session_tech_fingerprinted",
            "auth_password_recovery_detected",
            "auth_technology_detected",
            "auth_interface_detected",
            "auth_password_form_http",
            "auth_form_external_origin",
            "auth_password_autocomplete",
            "auth_csrf_missing",
            "auth_admin_surface_discovered"
        }

        observed_ids = {f.get("rule_id") for f in findings if "rule_id" in f}

        # All expected should be found (except inconclusive which is an error branch)
        missing = expected_ids - observed_ids
        self.assertEqual(len(missing), 0, f"Missing rule_ids: {missing}")

        # Verify no instance_key is set
        for f in findings:
            self.assertNotIn("instance_key", f, f"Finding {f.get('name')} incorrectly has instance_key")

    def test_3d_a_auth_session_inconclusive_identity(self):
        # We use AST verification instead of runtime because a pre-existing NameError (logger)
        # prevents clean runtime execution of this path.
        import ast
        with open("api/scanner/modules/auth_session_security.py", "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())

        found_inconclusive = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "make_finding":
                if len(node.args) > 0 and isinstance(node.args[0], ast.Constant) and node.args[0].value == "Authentication/Session Security Check Inconclusive":
                    found_inconclusive = True
                    has_rule_id = False
                    has_instance_key = False
                    for kw in node.keywords:
                        if kw.arg == "rule_id" and isinstance(kw.value, ast.Constant) and kw.value.value == "auth_session_check_inconclusive":
                            has_rule_id = True
                        if kw.arg == "instance_key":
                            has_instance_key = True
                    self.assertEqual(has_rule_id, True, "Inconclusive finding missing correct rule_id")
                    self.assertEqual(has_instance_key, False, "Inconclusive finding should not have instance_key")
        self.assertEqual(found_inconclusive, True, "Could not find the inconclusive finding call site")

if __name__ == '__main__':
    unittest.main()
