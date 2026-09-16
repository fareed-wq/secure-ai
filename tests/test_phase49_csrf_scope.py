import pytest
from unittest.mock import MagicMock, patch
from api.scanner.modules.auth_session_security import AuthenticationSessionSecurityModule

def run_module(html_content, url='https://example.com'):
    with patch('api.scanner.modules.auth_session_security.safe_request') as mock_safe_req:
        mod = AuthenticationSessionSecurityModule()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = html_content
        mock_resp.headers = {'Content-Type': 'text/html'}
        mock_safe_req.return_value = mock_resp
        return mod.run(url, 'example.com', session=MagicMock())

# 1. GET / READ-ONLY
def test_get_search():
    html = '<form method="GET" action="/search"><input name="q"></form>'
    findings = run_module(html)
    assert not any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)

# 2. SAME-ORIGIN WITHOUT TOKEN (relative)
def test_same_origin_relative():
    html = '<form method="POST" action="/profile"><input name="display_name"></form>'
    findings = run_module(html)
    assert any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)

# 3. SAME-ORIGIN WITHOUT TOKEN (absolute)
def test_same_origin_absolute():
    html = '<form method="POST" action="https://example.com/profile"><input name="display_name"></form>'
    findings = run_module(html)
    assert any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)

# 4. SAME-ORIGIN WITHOUT TOKEN (empty)
def test_same_origin_empty():
    html = '<form method="POST"><input name="display_name"></form>'
    findings = run_module(html)
    assert any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)

# 5. SAME-ORIGIN WITH TOKEN (csrf_token)
def test_same_origin_token():
    html = '<form method="POST" action="/profile"><input type="hidden" name="csrf_token" value="abc"></form>'
    findings = run_module(html)
    assert not any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)

# 6. SAME-ORIGIN WITH TOKEN (RequestVerificationToken)
def test_same_origin_token2():
    html = '<form method="POST" action="/profile"><input type="hidden" name="__RequestVerificationToken" value="abc"></form>'
    findings = run_module(html)
    assert not any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)

# 7. EXTERNAL POST
def test_external_post():
    html = '<form method="POST" action="https://thirdparty.test/subscribe"><input type="email" name="email"></form>'
    findings = run_module(html)
    assert not any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)

# 8. EXTERNAL POST (Mozilla AWS)
def test_external_mozilla():
    html = '<form method="POST" action="https://abdri3ttkb.execute-api.us-east-2.amazonaws.com/api/newsletter/mozillaorg"><input type="email" name="email"></form>'
    findings = run_module(html, url='https://www.mozilla.org')
    assert not any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)

# 9. RELATIVE ACTION profile
def test_relative_profile():
    html = '<form method="POST" action="profile"><input name="display_name"></form>'
    findings = run_module(html)
    assert any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)

# 10. RELATIVE ACTION ./profile
def test_relative_dot_profile():
    html = '<form method="POST" action="./profile"><input name="display_name"></form>'
    findings = run_module(html)
    assert any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)

# 11. ACTION empty string
def test_relative_empty():
    html = '<form method="POST" action=""><input name="display_name"></form>'
    findings = run_module(html)
    assert any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)

# 12. NON-HTTP ACTION javascript:
def test_non_http_js():
    html = '<form method="POST" action="javascript:void(0)"><input name="display_name"></form>'
    findings = run_module(html)
    assert not any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)

# CASE A - scheme mismatch
def test_case_a():
    html = '<form method="POST" action="http://example.com/profile"><input name="name"></form>'
    findings = run_module(html, url='https://example.com')
    assert not any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)

# CASE B - default HTTPS port equivalence
def test_case_b():
    html = '<form method="POST" action="https://example.com:443/profile"><input name="name"></form>'
    findings = run_module(html, url='https://example.com')
    assert any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)

# CASE C - non-default port
def test_case_c():
    html = '<form method="POST" action="https://example.com:8443/profile"><input name="name"></form>'
    findings = run_module(html, url='https://example.com')
    assert not any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)

# CASE D - subdomain
def test_case_d():
    html = '<form method="POST" action="https://api.example.com/profile"><input name="name"></form>'
    findings = run_module(html, url='https://example.com')
    assert not any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)

# CASE E - HTTP default port equivalence
def test_case_e():
    html = '<form method="POST" action="http://example.com:80/profile"><input name="name"></form>'
    findings = run_module(html, url='http://example.com')
    assert any(f.get('rule_id') == 'auth_csrf_missing' for f in findings)
