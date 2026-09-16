import unittest
from unittest.mock import patch, MagicMock
from requests.structures import CaseInsensitiveDict
from api.scanner.modules.discovery import InformationDisclosureModule

class TestPhase53ServerBannerPrecision(unittest.TestCase):
    def setUp(self):
        self.module = InformationDisclosureModule()

    def _run_with_headers(self, headers):
        with patch("api.scanner.modules.discovery.safe_request") as mock_req:
            resp = MagicMock()
            resp.headers = CaseInsensitiveDict(headers)
            resp.text = ""
            resp.status_code = 200
            mock_req.return_value = resp

            return self.module.run("https://example.com", "example.com", MagicMock())

    def _has_finding(self, findings):
        for f in findings:
            if f.get("rule_id") == "info_disclosure_server_banner":
                return True
        return False

    def test_01_no_header(self):
        findings = self._run_with_headers({})
        self.assertFalse(self._has_finding(findings))

    def test_02_generic_nginx(self):
        findings = self._run_with_headers({"Server": "nginx"})
        self.assertFalse(self._has_finding(findings))

    def test_03_generic_apache(self):
        findings = self._run_with_headers({"Server": "Apache"})
        self.assertFalse(self._has_finding(findings))

    def test_04_generic_cloudflare(self):
        findings = self._run_with_headers({"Server": "cloudflare"})
        self.assertFalse(self._has_finding(findings))

    def test_05_generic_gws(self):
        findings = self._run_with_headers({"Server": "gws"})
        self.assertFalse(self._has_finding(findings))

    def test_06_generic_granian(self):
        findings = self._run_with_headers({"Server": "granian"})
        self.assertFalse(self._has_finding(findings))

    def test_07_version_nginx_patch(self):
        findings = self._run_with_headers({"Server": "nginx/1.24.0"})
        self.assertTrue(self._has_finding(findings))

    def test_08_version_nginx_minor(self):
        findings = self._run_with_headers({"Server": "nginx/1.24"})
        self.assertTrue(self._has_finding(findings))

    def test_09_version_apache(self):
        findings = self._run_with_headers({"Server": "Apache/2.4.58"})
        self.assertTrue(self._has_finding(findings))

    def test_10_version_apache_os(self):
        findings = self._run_with_headers({"Server": "Apache/2.4.58 (Ubuntu)"})
        self.assertTrue(self._has_finding(findings))

    def test_11_version_iis(self):
        findings = self._run_with_headers({"Server": "Microsoft-IIS/10.0"})
        self.assertTrue(self._has_finding(findings))

    def test_12_version_gunicorn(self):
        findings = self._run_with_headers({"Server": "gunicorn/21.2.0"})
        self.assertTrue(self._has_finding(findings))

    def test_13_version_uvicorn(self):
        findings = self._run_with_headers({"Server": "uvicorn/0.30.1"})
        self.assertTrue(self._has_finding(findings))

    def test_14_version_ats(self):
        findings = self._run_with_headers({"Server": "ATS/9.2.15"})
        self.assertTrue(self._has_finding(findings))

    def test_15_ambiguous_awselb(self):
        findings = self._run_with_headers({"Server": "awselb/2.0"})
        self.assertTrue(self._has_finding(findings))

    def test_16_numeric_edge(self):
        findings = self._run_with_headers({"Server": "edge-2026"})
        self.assertFalse(self._has_finding(findings))

    def test_17_numeric_proxy(self):
        findings = self._run_with_headers({"Server": "proxy-2"})
        self.assertFalse(self._has_finding(findings))

    def test_18_numeric_service(self):
        findings = self._run_with_headers({"Server": "service-123"})
        self.assertFalse(self._has_finding(findings))

    def test_19_numeric_backend(self):
        findings = self._run_with_headers({"Server": "backend-2024.09"})
        self.assertFalse(self._has_finding(findings))

    def test_20_insufficient_product_major(self):
        findings = self._run_with_headers({"Server": "product/2"})
        self.assertFalse(self._has_finding(findings))

    def test_21_insufficient_product_latest(self):
        findings = self._run_with_headers({"Server": "product/latest"})
        self.assertFalse(self._has_finding(findings))

    def test_22_insufficient_product_v2(self):
        findings = self._run_with_headers({"Server": "product/v2"})
        self.assertFalse(self._has_finding(findings))

if __name__ == "__main__":
    unittest.main()
