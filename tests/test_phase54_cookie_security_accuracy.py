import unittest
from unittest.mock import patch, MagicMock
from requests.structures import CaseInsensitiveDict
from urllib3.response import HTTPHeaderDict
from api.scanner.modules.http_security import AdvancedCookieModule

class TestPhase54CookieSecurityAccuracy(unittest.TestCase):
    def setUp(self):
        self.module = AdvancedCookieModule()

    def _run_with_cookies(self, cookies_list, url="https://example.com"):
        with patch("api.scanner.modules.http_security.safe_request") as mock_req:
            resp = MagicMock()
            h = HTTPHeaderDict()
            for c in cookies_list:
                h.add("Set-Cookie", c)
            resp.raw = MagicMock()
            resp.raw.headers = h
            resp.url = url
            mock_req.return_value = resp

            return self.module.run(url, url.split("//")[1], MagicMock())

    def test_session_all_flags(self):
        f = self._run_with_cookies(["session=abc; Secure; HttpOnly; SameSite=Lax"])
        self.assertEqual(len(f), 0)

    def test_missing_secure(self):
        f = self._run_with_cookies(["session=abc; HttpOnly; SameSite=Lax"])
        self.assertTrue(any(x["rule_id"] == "cookies_session_missing_secure" for x in f))

    def test_missing_httponly(self):
        f = self._run_with_cookies(["session=abc; Secure; SameSite=Lax"])
        self.assertTrue(any(x["rule_id"] == "cookies_session_missing_httponly" for x in f))

    def test_missing_samesite(self):
        f = self._run_with_cookies(["session=abc; Secure; HttpOnly"])
        self.assertTrue(any(x["rule_id"] == "cookies_session_missing_samesite" for x in f))

    def test_missing_all_flags(self):
        f = self._run_with_cookies(["session=abc"])
        rules = {x["rule_id"] for x in f}
        self.assertIn("cookies_session_missing_secure", rules)
        self.assertIn("cookies_session_missing_httponly", rules)
        self.assertIn("cookies_session_missing_samesite", rules)

    def test_preference_cookie(self):
        f = self._run_with_cookies(["theme=dark"])
        self.assertTrue(any(x["rule_id"] == "cookies_non_session_unsecured" for x in f))
        self.assertFalse(any(x["rule_id"] == "cookies_session_missing_secure" for x in f))

    def test_samesite_none_secure_session(self):
        f = self._run_with_cookies(["session=abc; Secure; HttpOnly; SameSite=None"])
        self.assertEqual(len(f), 0)

    def test_session_samesite_none_without_secure(self):
        f = self._run_with_cookies(["session=abc; HttpOnly; SameSite=None"])
        rules = {x["rule_id"] for x in f}
        self.assertIn("cookies_session_missing_secure", rules)
        self.assertNotIn("cookies_samesite_none_without_secure", rules)

    def test_non_session_samesite_none_without_secure(self):
        f = self._run_with_cookies(["theme=dark; SameSite=None"])
        rules = {x["rule_id"] for x in f}
        self.assertIn("cookies_samesite_none_without_secure", rules)

    def test_multiple_distinct_set_cookie(self):
        f = self._run_with_cookies(["session=abc; HttpOnly", "theme=dark"])
        rules = {x["rule_id"] for x in f}
        self.assertIn("cookies_session_missing_secure", rules)
        self.assertIn("cookies_non_session_unsecured", rules)

    def test_expires_attribute_comma(self):
        f = self._run_with_cookies(["session=abc; Expires=Wed, 21 Oct 2030 07:28:00 GMT"])
        rules = {x["rule_id"] for x in f}
        self.assertIn("cookies_session_missing_secure", rules)

    def test_same_name_safe_first_unsafe_second(self):
        f = self._run_with_cookies([
            "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
            "session=bbb; Path=/admin"
        ])
        rules = {x["rule_id"] for x in f}
        self.assertIn("cookies_session_missing_secure", rules)

    def test_same_name_unsafe_first_safe_second(self):
        f = self._run_with_cookies([
            "session=abc; Path=/admin",
            "session=bbb; Path=/; Secure; HttpOnly; SameSite=Lax"
        ])
        rules = {x["rule_id"] for x in f}
        self.assertIn("cookies_session_missing_secure", rules)

    def test_same_name_different_paths(self):
        f = self._run_with_cookies([
            "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
            "session=bbb; Path=/admin"
        ])
        rules = {x["rule_id"] for x in f}
        self.assertIn("cookies_session_missing_secure", rules)

    def test_same_name_different_domains(self):
        f = self._run_with_cookies([
            "session=abc; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax",
            "session=bbb; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=Lax"
        ], url="https://sub.example.com")
        rules = {x["rule_id"] for x in f}
        self.assertIn("cookies_session_broad_domain", rules)

    def test_two_safe_same_name(self):
        f = self._run_with_cookies([
            "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
            "session=bbb; Path=/admin; Secure; HttpOnly; SameSite=Lax"
        ])
        self.assertEqual(len(f), 0)

    def test_two_unsafe_same_name_aggregate_once(self):
        f = self._run_with_cookies([
            "session=abc; Path=/",
            "session=bbb; Path=/admin"
        ])
        count = sum(1 for x in f if x["rule_id"] == "cookies_session_missing_secure")
        self.assertEqual(count, 1)

    def test_host_prefix_valid(self):
        f = self._run_with_cookies(["__Host-session=abc; Secure; Path=/; HttpOnly; SameSite=Lax"])
        self.assertEqual(len(f), 0)

    def test_host_prefix_missing_secure(self):
        f = self._run_with_cookies(["__Host-session=abc; Path=/; HttpOnly; SameSite=Lax"])
        rules = {x["rule_id"] for x in f}
        self.assertIn("cookies_invalid_host_prefix", rules)

    def test_host_prefix_wrong_path(self):
        f = self._run_with_cookies(["__Host-session=abc; Secure; Path=/app; HttpOnly; SameSite=Lax"])
        rules = {x["rule_id"] for x in f}
        self.assertIn("cookies_invalid_host_prefix", rules)

    def test_host_prefix_with_domain(self):
        f = self._run_with_cookies(["__Host-session=abc; Secure; Path=/; Domain=example.com; HttpOnly; SameSite=Lax"])
        rules = {x["rule_id"] for x in f}
        self.assertIn("cookies_invalid_host_prefix", rules)

    def test_secure_prefix_valid(self):
        f = self._run_with_cookies(["__Secure-session=abc; Secure; HttpOnly; SameSite=Lax"])
        self.assertEqual(len(f), 0)

    def test_secure_prefix_invalid(self):
        f = self._run_with_cookies(["__Secure-session=abc; HttpOnly; SameSite=Lax"])
        rules = {x["rule_id"] for x in f}
        self.assertIn("cookies_invalid_secure_prefix", rules)

    def test_malformed_cookie(self):
        f = self._run_with_cookies(["session"])
        self.assertEqual(len(f), 0)

    def test_cookie_value_redaction(self):
        f = self._run_with_cookies(["session=SUPER_SECRET_ALPHA"])
        text = str(f)
        self.assertNotIn("SUPER_SECRET_ALPHA", text)
        self.assertNotIn("SUPER_SECRET_BETA", text)

    def test_session_theme_classified_non_session(self):
        self.assertFalse(self.module.is_session_cookie("session_theme"))

    def test_marketing_session_id_classified_non_session(self):
        self.assertFalse(self.module.is_session_cookie("marketing_session_id"))

    def test_canonical_session_auth_sensitive(self):
        self.assertTrue(self.module.is_session_cookie("sessionid"))
        self.assertTrue(self.module.is_session_cookie("auth_token"))

    def test_csrf_cookie_excluded(self):
        self.assertFalse(self.module.is_session_cookie("csrf_token"))

    def test_instance_key_remains_cookie_name(self):
        f = self._run_with_cookies(["session=abc"])
        self.assertEqual(f[0]["instance_key"], "session")
