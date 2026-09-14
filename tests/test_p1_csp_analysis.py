import pytest
from unittest.mock import MagicMock
from api.scanner.modules.http_security import SecurityHeadersModule

from api.scanner.modules.headers import CSPQualityModule

def run_csp(headers, body=""):
    mod1 = SecurityHeadersModule()
    mod2 = CSPQualityModule()

    mock_resp = MagicMock()
    mock_resp.headers = headers
    mock_resp.text = body
    mock_resp.all_headers = headers

    def get_header_safe(resp, key, default=""):
        return resp.headers.get(key, default)

    mod1.get_header_safe = get_header_safe

    import api.scanner.modules.http_security as http_sec
    old_safe_request = http_sec.safe_request
    http_sec.safe_request = lambda *a, **k: mock_resp

    import api.scanner.modules.headers as headers_mod
    old_headers_safe_request = headers_mod.safe_request
    headers_mod.safe_request = lambda *a, **k: mock_resp

    try:
        findings = mod1.run("https://example.com", "example.com", None)
        findings.extend(mod2.run("https://example.com", "example.com", None))
    finally:
        http_sec.safe_request = old_safe_request
        headers_mod.safe_request = old_headers_safe_request

    return findings

def test_report_only_only():
    headers = {"Content-Security-Policy-Report-Only": "default-src 'self'"}
    findings = run_csp(headers)
    assert any(f["name"] == "Content-Security-Policy in Report-Only Mode" for f in findings)
    assert any(f["name"] == "Missing Content-Security-Policy (CSP)" and f["severity"] == "High" for f in findings)

def test_enforced_and_report_only():
    headers = {
        "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'",
        "Content-Security-Policy-Report-Only": "default-src 'self' 'unsafe-inline'"
    }
    findings = run_csp(headers)
    assert any(f["name"] == "Content-Security-Policy Configured" for f in findings)
    assert any(f["name"] == "Content-Security-Policy-Report-Only Also Present" for f in findings)
    assert not any(f["name"] == "Weak Content-Security-Policy" for f in findings)

def test_http_script_src():
    headers = {"Content-Security-Policy": "script-src http://evil.com"}
    findings = run_csp(headers)
    weak_findings = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak_findings) == 1
    assert "http:" in weak_findings[0]["evidence"]["raw"]

def test_http_default_src_no_script_src():
    headers = {"Content-Security-Policy": "default-src http://evil.com"}
    findings = run_csp(headers)
    weak_findings = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak_findings) == 1
    assert "http:" in weak_findings[0]["evidence"]["raw"]

def test_http_default_src_with_strong_script_src():
    headers = {"Content-Security-Policy": "default-src http://evil.com; script-src 'self'"}
    findings = run_csp(headers)
    weak_findings = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak_findings) == 1
    assert "http:" in weak_findings[0]["evidence"]["raw"]

def test_default_src_wildcard():
    headers = {"Content-Security-Policy": "default-src *"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 1
    assert "wildcard '*'" in weak[0]["evidence"]["raw"]

def test_default_src_wildcard_with_strong_script_src():
    headers = {"Content-Security-Policy": "default-src *; script-src 'self'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 0

def test_form_no_form_action():
    headers = {"Content-Security-Policy": "default-src 'self'"}
    body = "<html><body><form action='/submit'></form></body></html>"
    findings = run_csp(headers, body)
    assert any(f["name"] == "CSP Form Actions Not Restricted" for f in findings)

def test_no_form_no_form_action():
    headers = {"Content-Security-Policy": "default-src 'self'"}
    body = "<html><body></body></html>"
    findings = run_csp(headers, body)
    assert any(f["name"] == "CSP Form Actions Not Restricted" for f in findings)
    assert not any(f["name"] == "CSP form-action Configured" for f in findings)

def test_upgrade_insecure_requests():
    headers = {"Content-Security-Policy": "default-src 'self'; upgrade-insecure-requests"}
    findings = run_csp(headers)
    adv = [f for f in findings if f["name"] == "Advanced CSP Hardening Detected"]
    assert len(adv) == 1
    assert "upgrade-insecure-requests" in adv[0]["evidence"]["raw"]

def test_strict_dynamic():
    headers = {"Content-Security-Policy": "script-src 'strict-dynamic' 'unsafe-inline'"}
    findings = run_csp(headers)
    adv = [f for f in findings if f["name"] == "Advanced CSP Hardening Detected"]
    assert len(adv) == 1
    assert "strict-dynamic" in adv[0]["evidence"]["raw"]

def test_malformed_csp():
    headers = {"Content-Security-Policy": "default-src 'self' script-src 'none"}
    findings = run_csp(headers)
    # Shouldn't crash
    assert len(findings) > 0
def test_csp_structured_metadata():
    from api.scanner.modules.http_security import SecurityHeadersModule
    from unittest.mock import MagicMock
    import requests
    import api.scanner.modules.http_security as http_sec

    module = SecurityHeadersModule()
    response = MagicMock(spec=requests.Response)
    response.text = ""
    response.headers = {
        'Content-Security-Policy': 'default-src \'self\'; script-src \'self\' https://example.com; object-src \'none\'; base-uri \'none\'; frame-ancestors \'none\'; form-action \'self\'; style-src \'unsafe-inline\'; other-src \'ignore\''
    }
    http_sec.safe_request = MagicMock(return_value=response)
    findings = module.run('https://example.com', 'example.com', MagicMock())

    csp_finding = next(f for f in findings if f['name'] == 'Content-Security-Policy Configured')

    evidence = csp_finding['evidence']
    assert 'directives' in evidence
    directives = evidence['directives']

    assert directives['default-src'] == '\'self\''
    assert directives['script-src'] == '\'self\' https://example.com'
    assert directives['object-src'] == '\'none\''
    assert directives['base-uri'] == '\'none\''
    assert directives['frame-ancestors'] == '\'none\''
    assert directives['form-action'] == '\'self\''
    assert directives['style-src'] == '\'unsafe-inline\''

    assert 'other-src' not in directives
    assert 'connect-src' not in directives
    assert evidence['raw'] == response.headers['Content-Security-Policy'][:180]

def test_csp_structured_metadata_multiple_headers():
    from api.scanner.modules.http_security import SecurityHeadersModule
    from unittest.mock import MagicMock
    import requests
    import api.scanner.modules.http_security as http_sec

    module = SecurityHeadersModule()
    response = MagicMock(spec=requests.Response)
    response.text = ""
    response.headers = {
        'Content-Security-Policy': 'default-src \'self\', script-src \'none\''
    }
    http_sec.safe_request = MagicMock(return_value=response)
    findings = module.run('https://example.com', 'example.com', MagicMock())

    csp_finding = next(f for f in findings if f['name'] == 'Content-Security-Policy Configured')

    evidence = csp_finding['evidence']
    assert 'directives' not in evidence
    assert 'raw' in evidence
