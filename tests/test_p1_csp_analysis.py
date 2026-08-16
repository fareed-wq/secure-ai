import pytest
from unittest.mock import MagicMock
from api.scanner.modules.http_security import SecurityHeadersModule

def run_csp(headers, body=""):
    mod = SecurityHeadersModule()
    mock_resp = MagicMock()
    mock_resp.headers = headers
    mock_resp.text = body
    
    # safe_request normally sets all_headers
    mock_resp.all_headers = headers
    
    def get_header_safe(resp, key, default=""):
        return resp.headers.get(key, default)
    mod.get_header_safe = get_header_safe
    
    # We patch safe_request within the run to return mock_resp
    import api.scanner.modules.http_security as http_sec
    old_safe_request = http_sec.safe_request
    http_sec.safe_request = lambda *a, **k: mock_resp
    
    try:
        findings = mod.run("https://example.com", "example.com", None)
    finally:
        http_sec.safe_request = old_safe_request
        
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
    assert not any(f["name"] == "Weak Content-Security-Policy (CSP)" for f in findings)

def test_http_script_src():
    headers = {"Content-Security-Policy": "script-src http://evil.com"}
    findings = run_csp(headers)
    weak_findings = [f for f in findings if f["name"] == "Weak Content-Security-Policy (CSP)"]
    assert len(weak_findings) == 1
    assert "insecure 'http:' sources permitted" in weak_findings[0]["description"]
    assert weak_findings[0]["severity"] == "Low"

def test_http_default_src_no_script_src():
    headers = {"Content-Security-Policy": "default-src http://evil.com"}
    findings = run_csp(headers)
    weak_findings = [f for f in findings if f["name"] == "Weak Content-Security-Policy (CSP)"]
    assert len(weak_findings) == 1
    assert "insecure 'http:' sources permitted" in weak_findings[0]["description"]
    assert weak_findings[0]["severity"] == "Low"

def test_http_default_src_with_strong_script_src():
    headers = {"Content-Security-Policy": "default-src http://evil.com; script-src 'self'"}
    findings = run_csp(headers)
    # The default-src http: should NOT trigger the script warning since script-src is present.
    # It might trigger missing object-src, etc.
    weak_findings = [f for f in findings if f["name"] == "Weak Content-Security-Policy (CSP)"]
    assert "insecure 'http:' sources permitted" not in weak_findings[0]["description"]

def test_default_src_wildcard():
    headers = {"Content-Security-Policy": "default-src *"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy (CSP)"]
    assert len(weak) == 1
    assert "wildcard '*'" in weak[0]["description"]
    assert weak[0]["severity"] == "Medium"

def test_default_src_wildcard_with_strong_script_src():
    headers = {"Content-Security-Policy": "default-src *; script-src 'self'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy (CSP)"]
    # Still weak because of missing base-uri/object-src, but NOT because of wildcard script source
    assert "wildcard '*' default source" not in weak[0]["description"]
    assert "wildcard '*' script source" not in weak[0]["description"]

def test_form_no_form_action():
    headers = {"Content-Security-Policy": "default-src 'self'"}
    body = "<html><body><form action='/submit'></form></body></html>"
    findings = run_csp(headers, body)
    assert any(f["name"] == "CSP Missing form-action Directive" for f in findings)

def test_no_form_no_form_action():
    headers = {"Content-Security-Policy": "default-src 'self'"}
    body = "<html><body></body></html>"
    findings = run_csp(headers, body)
    assert not any(f["name"] == "CSP Missing form-action Directive" for f in findings)
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
