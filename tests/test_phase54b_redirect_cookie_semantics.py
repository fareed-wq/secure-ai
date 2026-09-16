import unittest
from unittest.mock import patch, MagicMock
from urllib3.response import HTTPHeaderDict
from api.scanner.modules.http_security import AdvancedCookieModule


class TestPhase54bRedirectCookieSemantics(unittest.TestCase):
    def setUp(self):
        self.module = AdvancedCookieModule()

    def _make_resp(self, url, cookies, history=None):
        resp = MagicMock()
        h = HTTPHeaderDict()
        for c in cookies:
            h.add("Set-Cookie", c)
        resp.raw = MagicMock()
        resp.raw.headers = h
        resp.url = url
        resp.history = history or []
        return resp

    def _run(self, final_url, final_cookies, history_entries=None):
        """history_entries: list of (url, [cookie_strs])"""
        with patch("api.scanner.modules.http_security.safe_request") as mock_req:
            hist = []
            if history_entries:
                for hurl, hcookies in history_entries:
                    hist.append(self._make_resp(hurl, hcookies))
            resp = self._make_resp(final_url, final_cookies, history=hist)
            mock_req.return_value = resp
            hostname = final_url.split("//")[1].split("/")[0]
            return self.module.run(final_url, hostname, MagicMock())

    def _rules(self, findings):
        return {f["rule_id"] for f in findings}

    # 1. HTTPS final safe session -> no transport finding
    def test_https_final_safe_no_transport(self):
        f = self._run("https://example.com", ["session=abc; Secure; HttpOnly; SameSite=Lax"])
        self.assertNotIn("cookies_session_set_over_http", self._rules(f))

    # 2. HTTP final session -> finding
    def test_http_final_session(self):
        f = self._run("http://example.com", ["session=abc"])
        self.assertIn("cookies_session_set_over_http", self._rules(f))

    # 3. HTTP final session + Secure -> finding
    def test_http_final_session_with_secure(self):
        f = self._run("http://example.com", ["session=abc; Secure; HttpOnly; SameSite=Lax"])
        self.assertIn("cookies_session_set_over_http", self._rules(f))

    # 4. HTTP redirect session -> HTTPS final no cookie -> finding
    def test_http_redirect_session_https_no_cookie(self):
        f = self._run(
            "https://example.com", [],
            history_entries=[("http://example.com/login", ["session=abc"])]
        )
        self.assertIn("cookies_session_set_over_http", self._rules(f))

    # 5. HTTP redirect session -> HTTPS safe replacement -> finding persists
    def test_http_redirect_session_https_safe_replacement(self):
        f = self._run(
            "https://example.com", ["session=xyz; Secure; HttpOnly; SameSite=Lax"],
            history_entries=[("http://example.com/login", ["session=abc"])]
        )
        self.assertIn("cookies_session_set_over_http", self._rules(f))

    # 6. HTTP redirect session+Secure -> HTTPS safe final -> finding
    def test_http_redirect_secure_session_https_safe(self):
        f = self._run(
            "https://example.com", ["session=xyz; Secure; HttpOnly; SameSite=Lax"],
            history_entries=[("http://example.com/login", ["session=abc; Secure; HttpOnly; SameSite=Lax"])]
        )
        self.assertIn("cookies_session_set_over_http", self._rules(f))

    # 7. HTTPS redirect unsafe session -> HTTPS safe final -> no transport finding
    def test_https_redirect_no_transport_finding(self):
        f = self._run(
            "https://example.com", ["session=xyz; Secure; HttpOnly; SameSite=Lax"],
            history_entries=[("https://example.com/login", ["session=abc"])]
        )
        self.assertNotIn("cookies_session_set_over_http", self._rules(f))

    # 8. HTTP non-session preference cookie -> no transport finding
    def test_http_nonsession_no_transport(self):
        f = self._run("http://example.com", ["theme=dark"])
        self.assertNotIn("cookies_session_set_over_http", self._rules(f))

    # 9. Cross-host HTTP redirect session -> ignored
    def test_cross_host_ignored(self):
        f = self._run(
            "https://example.com", [],
            history_entries=[("http://third.example.net/login", ["session=abc"])]
        )
        self.assertNotIn("cookies_session_set_over_http", self._rules(f))

    # 10. Two HTTP hops same session -> one finding
    def test_two_http_hops_one_finding(self):
        f = self._run(
            "https://example.com", [],
            history_entries=[
                ("http://example.com/one", ["session=abc"]),
                ("http://example.com/two", ["session=xyz"]),
            ]
        )
        count = sum(1 for x in f if x["rule_id"] == "cookies_session_set_over_http")
        self.assertEqual(count, 1)

    # 11. Two different sensitive names -> two findings
    def test_two_different_names(self):
        f = self._run("http://example.com", ["session=abc", "auth_token=xyz"])
        http_findings = [x for x in f if x["rule_id"] == "cookies_session_set_over_http"]
        names = {x["instance_key"] for x in http_findings}
        self.assertEqual(names, {"session", "auth_token"})

    # 12. instance_key remains cookie name
    def test_instance_key_is_cookie_name(self):
        f = self._run("http://example.com", ["session=abc"])
        http_f = [x for x in f if x["rule_id"] == "cookies_session_set_over_http"]
        self.assertEqual(len(http_f), 1)
        self.assertEqual(http_f[0]["instance_key"], "session")

    # 13. Cookie values redacted
    def test_cookie_values_redacted(self):
        f = self._run("http://example.com", ["session=SUPER_SECRET_REDIRECT_TOKEN"])
        text = str(f)
        self.assertNotIn("SUPER_SECRET_REDIRECT_TOKEN", text)

    # 14. Phase54A final-response behavior unchanged
    def test_phase54a_unchanged(self):
        f = self._run("https://example.com", ["session=abc"])
        rules = self._rules(f)
        self.assertIn("cookies_session_missing_secure", rules)
        self.assertNotIn("cookies_session_set_over_http", rules)

    # 15. No existing rule severity changes (spot check)
    def test_existing_severity_preserved(self):
        f = self._run("https://example.com", ["session=abc"])
        for finding in f:
            if finding["rule_id"] == "cookies_session_missing_secure":
                self.assertEqual(finding["severity"], "Medium")
            if finding["rule_id"] == "cookies_session_missing_samesite":
                self.assertEqual(finding["severity"], "Low")
