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
        names = [f['name'] for f in findings]
        self.assertIn("Session Cookie Uses SameSite=None Without Secure", names)

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
            url="https://example.com/login",
            headers={"Cache-Control": "public, max-age=3600"},
            text="Please login"
        )
        findings = self.auth_mod.run("https://example.com/login", "example.com", self.session)
        names = [f['name'] for f in findings]
        self.assertIn("Authentication Response May Be Publicly Cacheable", names)

    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_cache_control_revalidate_low(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            url="https://example.com/login",
            headers={"Cache-Control": "public, max-age=0, must-revalidate"},
            text="Please login"
        )
        findings = self.auth_mod.run("https://example.com/login", "example.com", self.session)
        finding = next((f for f in findings if f['name'] == "Authentication Response May Be Publicly Cacheable"), None)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], "Low")

    @patch('api.scanner.modules.auth_session_security.safe_request')
    def test_cache_control_safe(self, mock_safe_req):
        mock_safe_req.return_value = self._mock_response(
            url="https://example.com/login",
            headers={"Cache-Control": "no-store, private"},
            text="Please login"
        )
        findings = self.auth_mod.run("https://example.com/login", "example.com", self.session)
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

if __name__ == '__main__':
    unittest.main()
