import pytest
from unittest.mock import MagicMock, patch
from api.scanner.modules.auth_session_security import AuthenticationSessionSecurityModule
import requests

def helper_cache(url, html, headers):
    with patch('api.scanner.modules.auth_session_security.safe_request') as mock_req:
        resp = MagicMock()
        resp.url = url
        resp.text = html
        resp.headers = headers
        mock_req.return_value = resp
        mod = AuthenticationSessionSecurityModule()
        findings = mod.run(url, 'example.com', requests.Session())
        for f in findings:
            if f.get('rule_id') == 'auth_response_cacheable':
                return f
        return None

# 1. PUBLIC HOMEPAGE
def test_public_homepage():
    html = '<a href="/login">Sign in</a><p>Create your account.</p><p>User profile</p>'
    f = helper_cache('https://example.com/', html, {'Cache-Control': 'public, max-age=600'})
    assert f is None

# 2. PUBLIC LOGIN PAGE
def test_public_login():
    html = '<form><input type="email"><input type="password"></form>'
    f = helper_cache('https://example.com/login', html, {'Cache-Control': 'public, max-age=300'})
    assert f is None

# 3. SET-COOKIE ONLY (analytics)
def test_cookie_analytics():
    html = '<form><input type="email"><input type="password"></form>'
    f = helper_cache('https://example.com/login', html, {'Cache-Control': 'public', 'Set-Cookie': 'analytics=123'})
    assert f is None

# 4. SET-COOKIE ONLY (session)
def test_cookie_session():
    html = '<form><input type="email"><input type="password"></form>'
    f = helper_cache('https://example.com/login', html, {'Cache-Control': 'public', 'Set-Cookie': 'session=opaquevalue'})
    assert f is None

# 5. RESET TOKEN
def test_reset_token():
    f = helper_cache('https://example.com/reset-password?token=SECRET123', '', {'Cache-Control': 'public, max-age=600'})
    assert f is not None
    ev = str(f.get('evidence', ''))
    assert 'SECRET123' not in ev
    assert 'token' in ev

# 6. RESET TOKEN + no-store
def test_reset_token_no_store():
    f = helper_cache('https://example.com/reset-password?token=SECRET123', '', {'Cache-Control': 'no-store'})
    assert f is None

# 7. RESET TOKEN + private
def test_reset_token_private():
    f = helper_cache('https://example.com/reset-password?token=SECRET123', '', {'Cache-Control': 'private'})
    assert f is None

# 8. RESET TOKEN + no-cache
def test_reset_token_no_cache():
    f = helper_cache('https://example.com/reset-password?token=SECRET123', '', {'Cache-Control': 'no-cache'})
    assert f is None

# 9. RESET PAGE WITHOUT TOKEN
def test_reset_page_no_token():
    f = helper_cache('https://example.com/reset-password', '', {'Cache-Control': 'public'})
    assert f is None

# 10. EMAIL VERIFICATION
def test_email_verification():
    f = helper_cache('https://example.com/verify-email?token=SECRET456', '', {'Cache-Control': 'public'})
    assert f is not None
    ev = str(f.get('evidence', ''))
    assert 'SECRET456' not in ev
    assert 'token' in ev

# 11. OAUTH CALLBACK
def test_oauth_callback():
    f = helper_cache('https://example.com/oauth/callback?code=AUTHCODE&state=STATEVALUE', '', {'Cache-Control': 'public'})
    assert f is not None
    ev = str(f.get('evidence', ''))
    assert 'AUTHCODE' not in ev
    assert 'STATEVALUE' not in ev
    assert 'code' in ev

# 12. ORDINARY QUERY PARAMETER
def test_ordinary_query():
    f = helper_cache('https://example.com/?id=123', '', {'Cache-Control': 'public'})
    assert f is None


# 13. NEUTRAL BODY RESET TOKEN
def test_neutral_body_reset():
    html = '<html><p>Continue</p></html>'
    f = helper_cache('https://example.com/reset-password?token=SECRET123', html, {'Cache-Control': 'public, max-age=600'})
    assert f is not None
    ev = str(f.get('evidence', ''))
    assert 'SECRET123' not in ev
    assert 'token' in ev

# 14. PRESET BOUNDARY
def test_preset_boundary():
    f = helper_cache('https://example.com/preset?token=abc', '', {'Cache-Control': 'public'})
    assert f is None
