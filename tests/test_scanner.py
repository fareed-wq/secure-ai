import unittest

from api.scanner.core import ModuleResult
def _findings(result):
    return result.findings if isinstance(result, ModuleResult) else result
from unittest.mock import patch, MagicMock
import requests
import datetime
import socket

from api.index import (
    TechFingerprintModule,
    InformationDisclosureModule,
    RobotsTxtModule,
    SitemapModule,
    SecurityTxtModule,
    CORSModule,
    AdvancedCookieModule,
    HTTPSRedirectModule,
    EnhancedTLSModule,
    SecurityHeadersModule,
    AdvancedSecurityHeadersModule,
    ScannerModule,
    scan_url,
    Config,
    is_public_hostname
)

class TestScannerModules(unittest.TestCase):
    def setUp(self):
        self.session = requests.Session()
        self.url = "https://google.com"
        self.hostname = "google.com"

    def mock_response(self, status_code=200, text="", headers=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.headers = headers or {}
        resp.is_redirect = False
        del resp.raw
        return resp

    @patch('requests.Session.request')
    def test_tech_fingerprint_module(self, mock_get):
        mock_get.return_value = self.mock_response(headers={"Server": "nginx", "X-Powered-By": "PHP"})
        module = TechFingerprintModule()
        result = module.run(self.url, self.hostname, self.session)
        findings = _findings(result)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f['name'] == 'Technology Fingerprint Identified' for f in findings))

    @patch('requests.Session.request')
    def test_tech_fingerprint_module_empty(self, mock_get):
        mock_get.return_value = self.mock_response(headers={})
        module = TechFingerprintModule()
        result = module.run(self.url, self.hostname, self.session)
        findings = _findings(result)
        self.assertEqual(len(findings), 0)

    @patch('requests.Session.request')
    def test_information_disclosure_module(self, mock_get):
        mock_get.return_value = self.mock_response(headers={"Server": "nginx/1.18.0"})
        module = InformationDisclosureModule()
        result = module.run(self.url, self.hostname, self.session)
        findings = _findings(result)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['name'], 'Verbose Server Banner')

    @patch('requests.Session.request')
    def test_information_disclosure_module_safe(self, mock_get):
        mock_get.return_value = self.mock_response(headers={"Server": "nginx"})
        module = InformationDisclosureModule()
        result = module.run(self.url, self.hostname, self.session)
        findings = _findings(result)
        self.assertEqual(len(findings), 0)

    @patch('requests.Session.request')
    def test_robots_txt_module(self, mock_get):
        mock_get.return_value = self.mock_response(status_code=200, text="User-agent: *\nDisallow: /admin")
        module = RobotsTxtModule()
        result = module.run(self.url, self.hostname, self.session)
        findings = _findings(result)
        self.assertEqual(len(findings), 1)

    @patch('requests.Session.request')
    def test_sitemap_module(self, mock_get):
        mock_get.return_value = self.mock_response(status_code=200, text="<urlset></urlset>")
        module = SitemapModule()
        result = module.run(self.url, self.hostname, self.session)
        findings = _findings(result)
        self.assertEqual(len(findings), 1)

    @patch('requests.Session.request')
    def test_security_txt_module(self, mock_get):
        hp_resp = self.mock_response(status_code=200, text="homepage" * 200)
        target_resp = self.mock_response(status_code=200, text="Contact: mailto:security@google.com\nExpires: 2030-12-31T23:59:59Z", headers={"Content-Type": "text/plain"})
        mock_get.side_effect = [hp_resp, target_resp]
        module = SecurityTxtModule()
        result = module.run(self.url, self.hostname, self.session)
        findings = _findings(result)
        self.assertEqual(findings[0]['severity'], 'Passed')

    @patch('requests.Session.request')
    def test_cors_module(self, mock_get):
        mock_get.return_value = self.mock_response(headers={"Access-Control-Allow-Origin": "*"})
        module = CORSModule()
        result = module.run(self.url, self.hostname, self.session)
        findings = _findings(result)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], 'Informational')

    @patch('requests.Session.request')
    def test_advanced_cookie_module(self, mock_get):
        mock_get.return_value = self.mock_response(headers={"Set-Cookie": "session=123; path=/"})
        module = AdvancedCookieModule()
        result = module.run(self.url, self.hostname, self.session)
        findings = _findings(result)
        self.assertEqual(len(findings), 3) # Missing HttpOnly, Secure, SameSite

    @patch('requests.Session.request')
    def test_https_redirect_module(self, mock_get):
        mock_get.return_value = self.mock_response(status_code=301, headers={"Location": "https://google.com"})
        module = HTTPSRedirectModule()
        result = module.run(self.url, self.hostname, self.session)
        findings = _findings(result)
        self.assertEqual(findings[0]['severity'], 'Passed')
        self.assertEqual(findings[0]['rule_id'], 'https_redirect_configured')


    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_enhanced_tls_module(self, mock_ssl, mock_sock):
        mock_context = MagicMock()
        mock_ssock = MagicMock()

        # Valid future date
        future_date = (datetime.datetime.utcnow() + datetime.timedelta(days=40)).strftime("%b %d %H:%M:%S %Y GMT")
        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "*.google.com"),),),
            "notAfter": future_date
        }
        mock_ssock.version.return_value = "TLSv1.3"

        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ssl.return_value = mock_context

        module = EnhancedTLSModule()
        result = module.run(self.url, self.hostname, self.session)
        findings = _findings(result)

        self.assertTrue(any(f['severity'] == 'Passed' for f in findings))
        self.assertTrue(any(f['name'] == 'Wildcard Certificate in Use' for f in findings))

    @patch('requests.Session.request')
    def test_security_headers_module(self, mock_get):
        mock_get.return_value = self.mock_response(headers={})
        module = SecurityHeadersModule()
        result = module.run(self.url, self.hostname, self.session)
        findings = _findings(result)
        self.assertEqual(len(findings), 8) # All missing headers
        hsts_finding = next((f for f in findings if "Missing Strict-Transport-Security" in f["name"]), None)
        self.assertIsNotNone(hsts_finding)
        self.assertEqual(hsts_finding["rule_id"], "headers_hsts_missing")


    @patch('requests.Session.request')
    def test_advanced_security_headers_module(self, mock_get):
        mock_get.return_value = self.mock_response(headers={})
        module = AdvancedSecurityHeadersModule()
        result = module.run(self.url, self.hostname, self.session)
        findings = _findings(result)
        self.assertEqual(len(findings), 3)

    # Edge Cases & Timeouts
    @patch('requests.Session.request')
    def test_timeout_handling(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")
        module = SecurityHeadersModule()
        result = module.run(self.url, self.hostname, self.session)
        findings = _findings(result)
        self.assertEqual(len(findings), 0)

    @patch('requests.Session.request')
    def test_redirect_loop_handling(self, mock_get):
        mock_get.side_effect = requests.exceptions.TooManyRedirects("Exceeded redirects")
        module = HTTPSRedirectModule()
        result = module.run(self.url, self.hostname, self.session)
        findings = _findings(result)
        self.assertEqual(len(findings), 0)

    def test_is_public_hostname(self):
        self.assertFalse(is_public_hostname("localhost"))
        self.assertFalse(is_public_hostname("127.0.0.1"))
        self.assertFalse(is_public_hostname("192.168.1.1"))
        self.assertFalse(is_public_hostname("10.0.0.1"))

        # Test a public IP directly since DNS can be flaky in tests
        with patch('socket.getaddrinfo') as mock_dns:
            mock_dns.return_value = [(2, 1, 6, '', ('8.8.8.8', 0))]
            self.assertTrue(is_public_hostname("google.com"))

    @patch('api.scanner.orchestrator.validate_scan_target')
    @patch('api.index.is_public_hostname')
    def test_scan_url_orchestration(self, mock_public, mock_validate):
        mock_public.return_value = True
        mock_validate.return_value = None

        # Create a dummy module that always returns a known finding
        class DummyModule(ScannerModule):
            module_name = "Dummy"
            enabled = True
            timeout = 1.0
            def run(self, url, hostname, session):
                return [{"name": "Test Finding", "severity": "High", "description": "Test", "evidence": "None", "owasp": "A01"}]

        # Override the global REGISTERED_MODULES for this test
        with patch('api.index.REGISTERED_MODULES', [DummyModule()]), \
             patch('api.scanner.data.registry.REGISTERED_MODULES', [DummyModule()]), \
             patch('api.scanner.data.registry.PASSIVE_MODULES', [DummyModule()]), \
             patch('api.scanner.data.registry.ACTIVE_MODULES', [DummyModule()]), \
             patch('api.scanner.orchestrator.REGISTERED_MODULES', [DummyModule()]), \
             patch('api.scanner.orchestrator.PASSIVE_MODULES', [DummyModule()]), \
             patch('api.scanner.orchestrator.ACTIVE_MODULES', [DummyModule()]):
            result = scan_url("https://google.com")

            self.assertEqual(result['score'], 90) # 100 - 10 (High)
            self.assertEqual(result['severity_counts']['High'], 1)
            self.assertTrue("A01" in result['owasp_coverage'])

if __name__ == '__main__':
    unittest.main()

class TestScannerBaseFactory(unittest.TestCase):
    def setUp(self):
        class DummyModule(ScannerModule):
            module_name = "DummyFactoryModule"
            enabled = True
            def run(self, url, hostname, session):
                return []
        self.module = DummyModule()

    def test_make_finding_legacy_unchanged(self):
        # Call without new fields
        f = self.module.make_finding("Test", "High", "Desc", "Ev")
        self.assertNotIn("rule_id", f)
        self.assertNotIn("instance_key", f)
        self.assertEqual(f["name"], "Test")
        self.assertEqual(f["severity"], "High")

    def test_make_finding_rule_id_only(self):
        f = self.module.make_finding(
            "Test", "High", "Desc", "Ev",
            rule_id="test_rule_1"
        )
        self.assertEqual(f["rule_id"], "test_rule_1")
        self.assertNotIn("instance_key", f)

    def test_make_finding_rule_id_and_instance_key(self):
        f = self.module.make_finding(
            "Test", "High", "Desc", "Ev",
            rule_id="test_rule_2",
            instance_key="/api/test"
        )
        self.assertEqual(f["rule_id"], "test_rule_2")
        self.assertEqual(f["instance_key"], "/api/test")

    def test_make_finding_instance_key_only(self):
        f = self.module.make_finding(
            "Test", "High", "Desc", "Ev",
            instance_key="/api/only"
        )
        self.assertNotIn("rule_id", f)
        self.assertEqual(f["instance_key"], "/api/only")

    def test_make_finding_blank_optional_values(self):
        f = self.module.make_finding(
            "Test", "High", "Desc", "Ev",
            rule_id="",
            instance_key="   "
        )
        self.assertNotIn("rule_id", f)
        self.assertNotIn("instance_key", f)

    def test_make_finding_existing_fields_preserved(self):
        f = self.module.make_finding(
            "Test", "High", "Desc", "Ev",
            category="custom_cat",
            rule_id="r1"
        )
        self.assertEqual(f["name"], "Test")
        self.assertEqual(f["severity"], "High")
        self.assertEqual(f["category"], "custom_cat")
        self.assertEqual(f["description"], "Desc")
        self.assertEqual(f["evidence"]["raw"], "Ev")
        self.assertEqual(f["module"], "DummyFactoryModule")


def test_technology_fingerprint_identity_metadata():
    from api.scanner.modules.headers import TechFingerprintModule
    import requests
    from unittest.mock import Mock

    mod = TechFingerprintModule()
    session = Mock(spec=requests.Session)

    def mock_get(method, url, **kwargs):
        resp = Mock()
        resp.status_code = 200
        resp.headers = {'Server': 'nginx/1.23.4', 'X-Powered-By': 'PHP/8.1'}
        resp.text = ""
        resp.iter_content = Mock(return_value=[b''])
        return resp

    session.request.side_effect = mock_get

    result_findings = mod.run("https://example.com", "example.com", session)
    findings = _findings(result_findings)

    tech_findings = [f for f in findings if f["name"] == "Technology Fingerprint Identified"]
    assert len(tech_findings) == 2

    techs = [f.get("instance_key") for f in tech_findings]
    assert "nginx" in techs
    assert "PHP" in techs

    for f in tech_findings:
        assert f.get("rule_id") == "technology_detected"
        assert "version" not in f["instance_key"].lower()

def test_robots_txt_identity_metadata():
    from api.scanner.modules.discovery import RobotsTxtModule
    import requests
    from unittest.mock import Mock

    mod = RobotsTxtModule()
    mod.is_spa_fallback = Mock(return_value=False)
    session = Mock(spec=requests.Session)

    def mock_get(method, url, **kwargs):
        resp = Mock()
        resp.status_code = 200
        if "robots.txt" in url:
            resp.text = "User-agent: *" + chr(10) + "Disallow: /admin" + chr(10) + "Disallow: /backup"
        else:
            resp.text = "HOMEPAGE"
        resp.url = url
        resp.history = []
        resp.headers = {'Content-Type': 'text/plain'}
        resp.iter_content = Mock(return_value=[resp.text.encode()])
        return resp



    session.request.side_effect = mock_get
    result = mod.run("https://example.com", "example.com", session)
    findings = _findings(result)

    disc = [f for f in findings if f["name"] == "Internal Paths Disclosed in Robots.txt"]
    assert len(disc) > 0
    assert disc[0].get("rule_id") == "robots_txt_disclosure"
    assert "instance_key" not in disc[0]

    admin = [f for f in findings if f["name"] == "Privileged / Administrative Surface Discovered"]
    assert len(admin) > 0
    assert admin[0].get("rule_id") == "robots_txt_admin_surface"
    assert "instance_key" not in admin[0]

def test_security_txt_branches():
    from api.scanner.modules.discovery import SecurityTxtModule
    import requests
    from unittest.mock import Mock

    mod = SecurityTxtModule()
    mod.is_spa_fallback = Mock(return_value=False)
    session = Mock(spec=requests.Session)

    # 1. Regex fail branch
    def mock_get1(method, url, **kwargs):
        resp = Mock()
        resp.status_code = 200
        if "security.txt" in url:
            resp.text = "Contact: mailto:security@google.com" + chr(10) + "Expires: 2030-12-31"
        else:
            resp.text = "HOMEPAGE"
        resp.headers = {'Content-Type': 'text/plain'}
        resp.iter_content = Mock(return_value=[resp.text.encode()])
        return resp



    session.request.side_effect = mock_get1
    result_findings1 = mod.run("https://example.com", "example.com", session)
    findings1 = _findings(result_findings1)
    inv1 = [f for f in findings1 if f["name"] == "security.txt Invalid Expires"]
    assert len(inv1) > 0
    assert inv1[0].get("rule_id") == "security_txt_invalid_expires"

    # 2. Value fail branch
    def mock_get2(method, url, **kwargs):
        resp = Mock()
        resp.status_code = 200
        if "security.txt" in url:
            resp.text = "Contact: mailto:security@google.com" + chr(10) + "Expires: 2030-99-99T99:99:99Z"
        else:
            resp.text = "HOMEPAGE"
        resp.headers = {'Content-Type': 'text/plain'}
        resp.iter_content = Mock(return_value=[resp.text.encode()])
        return resp



    session.request.side_effect = mock_get2
    result_findings2 = mod.run("https://example.com", "example.com", session)
    findings2 = _findings(result_findings2)
    inv2 = [f for f in findings2 if f["name"] == "security.txt Invalid Expires"]
    assert len(inv2) > 0
    assert inv2[0].get("rule_id") == "security_txt_invalid_expires"


def test_information_disclosure_identity_metadata():
    from api.scanner.modules.discovery import InformationDisclosureModule
    import requests
    from unittest.mock import Mock

    mod = InformationDisclosureModule()
    session = Mock(spec=requests.Session)

    def mock_get(method, url, **kwargs):
        resp = Mock()
        resp.status_code = 200
        resp.headers = {"Server": "nginx/1.18.0"}
        resp.iter_content = Mock(return_value=[b''])
        return resp

    session.request.side_effect = mock_get
    result_findings = mod.run("https://example.com", "example.com", session)
    findings = _findings(result_findings)

    assert len(findings) > 0
    assert findings[0]['name'] == 'Verbose Server Banner'
    assert findings[0].get('rule_id') == 'info_disclosure_server_banner'
    assert 'instance_key' not in findings[0]



def test_3b2_caa_dnssec_identities(monkeypatch):
    import requests
    session = requests.Session()
    from unittest.mock import MagicMock
    from api.scanner.modules.dns import DNSCAAModule
    mod = DNSCAAModule()

    # Mock query_doh to return CAA and DS records
    def mock_query(domain, rtype, session):
        if rtype == "CAA":
            return {"Status": 0, "Answer": [{"data": 'issue "ca.example.com"'}]}
        elif rtype == "DS":
            return {"Status": 0, "Answer": [{"data": "ds_record_data"}]}
        elif rtype == "A": # wildcard
            return {"Status": 0, "Answer": [{"data": "1.2.3.4"}]}
        return None

    monkeypatch.setattr("api.scanner.modules.dns.query_doh", mock_query)
    result_findings = mod.run("https://example.com", "example.com", session)
    findings = _findings(result_findings)

    caa = next((f for f in findings if f["name"] == "CAA Records Observed"), None)
    assert caa and caa.get("rule_id") == "dns_caa_observed"
    assert "instance_key" not in caa

    ds = next((f for f in findings if f["name"] == "DNSSEC Delegation Observed"), None)
    assert ds and ds.get("rule_id") == "dns_dnssec_observed"
    assert "instance_key" not in ds

    wd = next((f for f in findings if f["name"] == "Wildcard DNS Record Detected"), None)
    assert wd and wd.get("rule_id") == "dns_wildcard_detected"
    assert "instance_key" not in wd

    # Test missing
    def mock_query_missing(domain, rtype, session):
        if rtype in ("CAA", "DS", "A"):
            return {"Status": 0}
        return None
    monkeypatch.setattr("api.scanner.modules.dns.query_doh", mock_query_missing)
    result_findings_missing = mod.run("https://example.com", "example.com", session)
    findings_missing = _findings(result_findings_missing)

    caa_m = next((f for f in findings_missing if f["name"] == "CAA Record Not Observed"), None)
    assert caa_m and caa_m.get("rule_id") == "dns_caa_missing"
    assert "instance_key" not in caa_m

    ds_m = next((f for f in findings_missing if f["name"] == "DNSSEC Delegation Not Observed"), None)
    assert ds_m and ds_m.get("rule_id") == "dns_dnssec_missing"
    assert "instance_key" not in ds_m



def test_3b2_subdomain_checks_identities(monkeypatch):
    import requests
    session = requests.Session()
    from api.scanner.modules.network_checks import SubdomainProbingModule, SubdomainTakeoverModule
    mod_probe = SubdomainProbingModule()

    def mock_safe_req(method, url, **kwargs):
        from unittest.mock import MagicMock
        if url == "https://admin.example.com" or url == "https://api.example.com":
            return MagicMock()
        return None
    monkeypatch.setattr("api.scanner.modules.network_checks.safe_request", mock_safe_req)
    monkeypatch.setattr("api.scanner.modules.network_checks.Config.COMMON_SUBDOMAINS", ["admin", "api", "dev"])

    findings_probe = mod_probe.run("https://example.com", "example.com", session)
    admin = next((f for f in findings_probe if f["name"] == "Active Subdomain Found: admin.example.com"), None)
    assert admin is not None
    assert admin.get("rule_id") == "network_subdomain_probed"
    assert admin.get("instance_key") == "admin.example.com"

    api = next((f for f in findings_probe if f["name"] == "Active Subdomain Found: api.example.com"), None)
    assert api is not None
    assert api.get("rule_id") == "network_subdomain_probed"
    assert api.get("instance_key") == "api.example.com"

    mod_take = SubdomainTakeoverModule()

    def mock_takeover_vuln(method, url, **kwargs):
        from unittest.mock import MagicMock
        m = MagicMock()
        m.status_code = 200
        if "dns.google" in url:
            m.json.return_value = {"Answer": [{"data": "test.s3.amazonaws.com"}]}
            return m
        m.text = "NoSuchBucket The specified bucket does not exist"
        return m
    monkeypatch.setattr("api.scanner.modules.network_checks.safe_request", mock_takeover_vuln)

    findings_take = _findings(mod_take.run("https://example.com", "example.com", session))
    vuln = next((f for f in findings_take if f["name"] == "Subdomain Takeover Vulnerability (Dangling CNAME)"), None)
    assert vuln is not None
    assert vuln.get("rule_id") == "network_subdomain_takeover_vulnerability"
    assert "instance_key" not in vuln

    def mock_takeover_alias(method, url, **kwargs):
        from unittest.mock import MagicMock
        m = MagicMock()
        m.status_code = 200
        if "dns.google" in url:
            m.json.return_value = {"Answer": [{"data": "test.s3.amazonaws.com"}]}
            return m
        m.text = "Welcome to S3"
        return m
    monkeypatch.setattr("api.scanner.modules.network_checks.safe_request", mock_takeover_alias)

    findings_take2 = _findings(mod_take.run("https://example.com", "example.com", session))
    alias = next((f for f in findings_take2 if f["name"] == "CNAME Alias Configured"), None)
    assert alias is not None
    assert alias.get("rule_id") == "network_cname_alias_configured"
    assert "instance_key" not in alias

    def mock_takeover_none(method, url, **kwargs):
        from unittest.mock import MagicMock
        m = MagicMock()
        m.status_code = 200
        m.json.return_value = {"Answer": []}
        return m
    monkeypatch.setattr("api.scanner.modules.network_checks.safe_request", mock_takeover_none)
    findings_take3 = _findings(mod_take.run("https://example.com", "example.com", session))
    none_f = next((f for f in findings_take3 if f["name"] == "No Subdomain Takeover Risk Detected"), None)
    assert none_f is not None
    assert none_f.get("rule_id") == "network_subdomain_takeover_risk_none"
    assert "instance_key" not in none_f


