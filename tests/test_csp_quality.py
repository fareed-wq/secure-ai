import pytest
from unittest.mock import MagicMock
from api.scanner.modules.headers import CSPQualityModule

def run_csp(headers):
    mod = CSPQualityModule()
    mock_resp = MagicMock()
    mock_resp.headers = headers

    def get_header_safe(resp, key, default=""):
        return resp.headers.get(key, default)
    mod.get_header_safe = get_header_safe

    import api.scanner.modules.headers as headers_mod
    old_safe_request = headers_mod.safe_request
    headers_mod.safe_request = lambda *a, **k: mock_resp

    try:
        findings = mod.run("https://example.com", "example.com", None)
    finally:
        headers_mod.safe_request = old_safe_request

    return findings

def test_strong_csp_with_nonce():
    headers = {"Content-Security-Policy": "script-src 'nonce-12345' 'unsafe-inline'; object-src 'none'; default-src 'none'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 0

def test_script_nonce_does_not_suppress_style():
    headers = {"Content-Security-Policy": "script-src 'nonce-123' 'unsafe-inline'; style-src 'unsafe-inline'; default-src 'none'; object-src 'none'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 1
    assert "unsafe-inline in style-src" in weak[0]["evidence"]["raw"]

def test_style_nonce_does_not_suppress_script():
    headers = {"Content-Security-Policy": "style-src 'nonce-123' 'unsafe-inline'; script-src 'unsafe-inline'; default-src 'none'; object-src 'none'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 1
    assert "unsafe-inline in script-src" in weak[0]["evidence"]["raw"]

def test_strict_dynamic_in_script_does_not_suppress_img():
    headers = {"Content-Security-Policy": "script-src 'nonce-12' 'strict-dynamic' http:; img-src http:; default-src 'none'; object-src 'none'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 1
    assert "http: sources" in weak[0]["evidence"]["raw"]

def test_strict_dynamic_no_nonce_does_not_suppress_inline():
    headers = {"Content-Security-Policy": "script-src 'strict-dynamic' 'unsafe-inline'; default-src 'none'; object-src 'none'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 1
    assert "unsafe-inline in script-src" in weak[0]["evidence"]["raw"]

def test_missing_default_src_sufficient_policy():
    headers = {"Content-Security-Policy": "script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; frame-src 'self'; worker-src 'self'; manifest-src 'self'"}
    findings = run_csp(headers)
    df = [f for f in findings if f["name"] == "CSP Missing Default Source Fallback"]
    assert len(df) == 0

def test_missing_default_src_uncovered_fetch():
    headers = {"Content-Security-Policy": "script-src 'self'; object-src 'none'"}
    findings = run_csp(headers)
    df = [f for f in findings if f["name"] == "CSP Missing Default Source Fallback"]
    assert len(df) == 1
    assert df[0]["severity"] == "Low"

def test_default_src_none_no_object_src():
    headers = {"Content-Security-Policy": "default-src 'none'"}
    findings = run_csp(headers)
    obj = [f for f in findings if f["name"] == "CSP Object Sources Not Explicitly Disabled"]
    assert len(obj) == 0

def test_default_src_self_no_object_src():
    headers = {"Content-Security-Policy": "default-src 'self'"}
    findings = run_csp(headers)
    obj = [f for f in findings if f["name"] == "CSP Object Sources Not Explicitly Disabled"]
    assert len(obj) == 1

def test_strict_dynamic_without_nonce_does_not_mitigate_http():
    headers = {"Content-Security-Policy": "script-src 'strict-dynamic' http:; default-src 'none'; object-src 'none'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 1
    assert "http: sources" in weak[0]["evidence"]["raw"]

def test_strict_dynamic_with_nonce_mitigates_http():
    headers = {"Content-Security-Policy": "script-src 'nonce-1' 'strict-dynamic' http:; default-src 'none'; object-src 'none'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 0

def test_unsafe_eval_globally_ignored_if_not_in_script_src():
    headers = {"Content-Security-Policy": "report-uri http://unsafe-eval; default-src 'none'; object-src 'none'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 0

def test_http_globally_ignored_if_not_fetch_directive():
    headers = {"Content-Security-Policy": "report-uri http://example.com; default-src 'none'; object-src 'none'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 0

def test_duplicate_directive():
    headers = {"Content-Security-Policy": "script-src 'self'; script-src 'unsafe-inline'; default-src 'none'; object-src 'none'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 0

def test_valid_nonce_mitigates_same_directive_unsafe_inline():
    headers = {"Content-Security-Policy": "script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'; default-src 'none'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 0

def test_empty_malformed_nonce_does_not_mitigate():
    headers = {"Content-Security-Policy": "script-src 'nonce-' 'unsafe-inline'; object-src 'none'; default-src 'none'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 1

def test_valid_hash_mitigates():
    headers = {"Content-Security-Policy": "script-src 'sha256-abcdef' 'unsafe-inline'; object-src 'none'; default-src 'none'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 0

def test_empty_malformed_hash_does_not_mitigate():
    headers = {"Content-Security-Policy": "script-src 'sha256-' 'unsafe-inline'; object-src 'none'; default-src 'none'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 1

def test_url_text_containing_sha256_does_not_count_as_hash():
    # Enclosed in single quotes to test token validation bypass
    headers = {"Content-Security-Policy": "script-src 'http://example.com/sha256-' 'unsafe-inline'; object-src 'none'; default-src 'none'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 1

def test_malformed_trust_anchor_strict_dynamic_does_not_suppress_http():
    headers = {"Content-Security-Policy": "script-src 'nonce-' 'strict-dynamic' http:; default-src 'none'; object-src 'none'"}
    findings = run_csp(headers)
    weak = [f for f in findings if f["name"] == "Weak Content-Security-Policy"]
    assert len(weak) == 1
import pytest
from unittest.mock import MagicMock

def test_registry_has_csp_quality_module():
    from api.scanner.data.registry import PASSIVE_MODULES, DOMAIN_MAP

    # Verify exactly one instance in PASSIVE_MODULES
    csp_instances = [m for m in PASSIVE_MODULES if m.__class__.__name__ == 'CSPQualityModule']
    assert len(csp_instances) == 1, "CSPQualityModule should be registered exactly once in PASSIVE_MODULES"

    # Verify DOMAIN_MAP
    assert DOMAIN_MAP.get('CSPQualityModule') == 'browser_defense', "CSPQualityModule must map to browser_defense"

def test_orchestrator_executes_csp_quality_module():
    from api.scanner.orchestrator import scan_url
    import api.scanner.orchestrator as orch_mod

    old_get_http = orch_mod.get_http_session
    old_safe_req = orch_mod.safe_request

    mock_session = MagicMock()
    orch_mod.get_http_session = lambda: mock_session

    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Security-Policy": "script-src 'unsafe-inline'; default-src 'self'"}
    orch_mod.safe_request = lambda *a, **k: mock_resp

    try:
        # run_modules(url, hostname, scan_mode="passive")
        # We need to mock safe_request inside the headers module too since it runs in a thread
        import api.scanner.modules.headers as headers_mod
        old_headers_req = headers_mod.safe_request
        headers_mod.safe_request = lambda *a, **k: mock_resp

        try:
            results = scan_url("http://example.com", scan_mode="passive").get("findings", [])
        finally:
            headers_mod.safe_request = old_headers_req

    finally:
        orch_mod.get_http_session = old_get_http
        orch_mod.safe_request = old_safe_req

    csp_findings = [f for f in results if f.get("name") in ["Weak Content-Security-Policy", "CSP Object Sources Not Explicitly Disabled"]]
    assert len(csp_findings) == 2, "Expected CSPQualityModule findings from the passive scan"
    assert csp_findings[0]["domain"] == "browser_defense", "Finding should have correct domain"
    assert csp_findings[1]["domain"] == "browser_defense", "Finding should have correct domain"
