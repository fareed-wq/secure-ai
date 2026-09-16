import unittest
from unittest.mock import patch, MagicMock
from api.scanner.modules.http_security import SecurityHeadersModule

class TestPhase52ClickjackingAccuracy(unittest.TestCase):
    def setUp(self):
        self.module = SecurityHeadersModule()

    def _mock_response(self, headers=None):
        mock_resp = MagicMock()
        from requests.structures import CaseInsensitiveDict
        mock_resp.headers = CaseInsensitiveDict(headers or {})
        mock_resp.url = "https://example.com"
        mock_resp.text = "<html></html>"
        return mock_resp

    def _run_with_headers(self, headers):
        with patch('api.scanner.modules.http_security.safe_request') as mock_safe_req:
            mock_safe_req.return_value = self._mock_response(headers)
            findings = self.module.run("https://example.com", "example.com", MagicMock())
            return [f for f in findings if f['rule_id'] == 'headers_clickjacking_protection_missing']

    def test_1_no_protection(self):
        findings = self._run_with_headers({})
        self.assertEqual(len(findings), 1)

    def test_2_xfo_deny(self):
        findings = self._run_with_headers({"X-Frame-Options": "DENY"})
        self.assertEqual(len(findings), 0)

    def test_3_xfo_sameorigin(self):
        findings = self._run_with_headers({"X-Frame-Options": "SAMEORIGIN"})
        self.assertEqual(len(findings), 0)

    def test_4_lowercase_xfo(self):
        findings = self._run_with_headers({"X-Frame-Options": "deny"})
        self.assertEqual(len(findings), 0)

    def test_5_invalid_xfo(self):
        findings = self._run_with_headers({"X-Frame-Options": "INVALID"})
        self.assertEqual(len(findings), 1)

    def test_6_allow_from(self):
        findings = self._run_with_headers({"X-Frame-Options": "ALLOW-FROM https://example.com"})
        self.assertEqual(len(findings), 1)

    def test_7_deny_deny(self):
        findings = self._run_with_headers({"X-Frame-Options": "DENY, DENY"})
        self.assertEqual(len(findings), 0)

    def test_8_sameorigin_sameorigin(self):
        findings = self._run_with_headers({"X-Frame-Options": "SAMEORIGIN, SAMEORIGIN"})
        self.assertEqual(len(findings), 0)

    def test_9_sameorigin_deny(self):
        findings = self._run_with_headers({"X-Frame-Options": "SAMEORIGIN, DENY"})
        self.assertEqual(len(findings), 0)

    def test_10_fa_none(self):
        findings = self._run_with_headers({"Content-Security-Policy": "frame-ancestors 'none'"})
        self.assertEqual(len(findings), 0)

    def test_11_fa_self(self):
        findings = self._run_with_headers({"Content-Security-Policy": "frame-ancestors 'self'"})
        self.assertEqual(len(findings), 0)

    def test_12_uppercase_fa(self):
        findings = self._run_with_headers({"Content-Security-Policy": "FRAME-ANCESTORS 'none'"})
        self.assertEqual(len(findings), 0)

    def test_13_fa_trusted_origin(self):
        findings = self._run_with_headers({"Content-Security-Policy": "frame-ancestors https://trusted.example"})
        self.assertEqual(len(findings), 0)

    def test_14_fa_wildcard(self):
        findings = self._run_with_headers({"Content-Security-Policy": "frame-ancestors *"})
        self.assertEqual(len(findings), 1)

    def test_15_fa_https(self):
        findings = self._run_with_headers({"Content-Security-Policy": "frame-ancestors https:"})
        self.assertEqual(len(findings), 1)

    def test_16_fa_http(self):
        findings = self._run_with_headers({"Content-Security-Policy": "frame-ancestors http:"})
        self.assertEqual(len(findings), 1)

    def test_17_empty_fa(self):
        findings = self._run_with_headers({"Content-Security-Policy": "frame-ancestors ;"})
        self.assertEqual(len(findings), 0)

    def test_18_default_src_only(self):
        findings = self._run_with_headers({"Content-Security-Policy": "default-src 'none'"})
        self.assertEqual(len(findings), 1)

    def test_19_ro_fa_none(self):
        findings = self._run_with_headers({"Content-Security-Policy-Report-Only": "frame-ancestors 'none'"})
        self.assertEqual(len(findings), 1)

    def test_20_xfo_deny_plus_ro_wildcard(self):
        findings = self._run_with_headers({
            "X-Frame-Options": "DENY",
            "Content-Security-Policy-Report-Only": "frame-ancestors *"
        })
        self.assertEqual(len(findings), 0)

    def test_21_xfo_deny_plus_enforced_fa_wildcard(self):
        findings = self._run_with_headers({
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "frame-ancestors *"
        })
        self.assertEqual(len(findings), 1)

    def test_22_xfo_deny_plus_enforced_fa_https(self):
        findings = self._run_with_headers({
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "frame-ancestors https:"
        })
        self.assertEqual(len(findings), 1)

    def test_23_xfo_deny_plus_enforced_fa_self(self):
        findings = self._run_with_headers({
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "frame-ancestors 'self'"
        })
        self.assertEqual(len(findings), 0)

    def test_24_fa_none_plus_trusted(self):
        findings = self._run_with_headers({"Content-Security-Policy": "frame-ancestors 'none' https://trusted.example"})
        self.assertEqual(len(findings), 0)

    def test_25_fa_none_plus_wildcard(self):
        findings = self._run_with_headers({"Content-Security-Policy": "frame-ancestors 'none' *"})
        self.assertEqual(len(findings), 1)

    def test_26_frame_ancestorsx(self):
        findings = self._run_with_headers({"Content-Security-Policy": "frame-ancestorsx 'none'"})
        self.assertEqual(len(findings), 1)

    def test_27_frame_ancestors_extra(self):
        findings = self._run_with_headers({"Content-Security-Policy": "frame-ancestors-extra 'none'"})
        self.assertEqual(len(findings), 1)

    def test_28_sameorigin_invalid(self):
        findings = self._run_with_headers({"X-Frame-Options": "SAMEORIGIN, INVALID"})
        self.assertEqual(len(findings), 0)

    def test_29_sameorigin_allowall(self):
        findings = self._run_with_headers({"X-Frame-Options": "SAMEORIGIN, ALLOWALL"})
        self.assertEqual(len(findings), 0)

    def test_30_invalid_invalid(self):
        findings = self._run_with_headers({"X-Frame-Options": "INVALID, INVALID"})
        self.assertEqual(len(findings), 1)

    def test_31_allowall_invalid(self):
        findings = self._run_with_headers({"X-Frame-Options": "ALLOWALL, INVALID"})
        self.assertEqual(len(findings), 0)

    def test_32_deny_invalid(self):
        findings = self._run_with_headers({"X-Frame-Options": "DENY, INVALID"})
        self.assertEqual(len(findings), 0)

    def test_33_allow_from_invalid(self):
        findings = self._run_with_headers({"X-Frame-Options": "ALLOW-FROM https://example.com, INVALID"})
        self.assertEqual(len(findings), 1)

    def test_34_allowall_allow_from(self):
        findings = self._run_with_headers({"X-Frame-Options": "ALLOWALL, ALLOW-FROM https://example.com"})
        self.assertEqual(len(findings), 0)


    def test_35_allowall(self):
        findings = self._run_with_headers({"X-Frame-Options": "ALLOWALL"})
        self.assertEqual(len(findings), 1)

if __name__ == '__main__':
    unittest.main()
