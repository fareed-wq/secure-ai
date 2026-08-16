import pytest
from unittest.mock import patch, MagicMock
from api.scanner.modules.api_web_security import ApiWebSecurityModule
from api.scanner.modules.auth_session_security import AuthenticationSessionSecurityModule

@pytest.fixture
def api_module():
    return ApiWebSecurityModule()

@pytest.fixture
def auth_module():
    return AuthenticationSessionSecurityModule()

@pytest.fixture
def mock_safe_request():
    with patch('api.scanner.modules.api_web_security.safe_request') as mock_api_req, \
         patch('api.scanner.modules.auth_session_security.safe_request') as mock_auth_req:
        
        def set_mock_response(resp):
            mock_api_req.return_value = resp
            mock_auth_req.return_value = resp
            return resp
            
        yield set_mock_response

def test_cache_directive_conflict_sensitive(api_module, mock_safe_request):
    resp = MagicMock()
    resp.url = "https://example.com/api/user/profile"
    resp.headers = {"Cache-Control": "no-store, max-age=3600"}
    resp.text = "{}"
    resp.history = []
    mock_safe_request(resp)
    
    findings = api_module.run("https://example.com/api/user/profile", "example.com", None)
    finding_names = [f["name"] for f in findings]
    
    assert "Contradictory Cache-Control Directives" in finding_names
    f = next(f for f in findings if f["name"] == "Contradictory Cache-Control Directives")
    assert f["severity"] == "Low"

def test_sensitive_no_store_missing_vary_safe(api_module, mock_safe_request):
    resp = MagicMock()
    resp.url = "https://example.com/api/user/profile"
    resp.headers = {"Cache-Control": "no-store, private"}
    resp.text = "{}"
    resp.history = []
    mock_safe_request(resp)
    
    findings = api_module.run("https://example.com/api/user/profile", "example.com", None)
    finding_names = [f["name"] for f in findings]
    
    assert "Missing Cache Vary Protection on Sensitive Content" not in finding_names

def test_sensitive_shared_caching_missing_vary(auth_module, mock_safe_request):
    resp = MagicMock()
    resp.url = "https://example.com/login"
    resp.headers = {"Cache-Control": "public, max-age=3600"}
    resp.text = "<html>login form</html>"
    mock_safe_request(resp)
    
    findings = auth_module.run("https://example.com/login", "example.com", None)
    finding_names = [f["name"] for f in findings]
    
    assert "Missing Cache Vary Protection on Sensitive Content" in finding_names
    f = next(f for f in findings if f["name"] == "Missing Cache Vary Protection on Sensitive Content")
    assert f["severity"] == "Medium"

def test_sensitive_etag_tracking(api_module, mock_safe_request):
    resp = MagicMock()
    resp.url = "https://example.com/api/user/data"
    resp.headers = {"Cache-Control": "no-store", "ETag": '"12345"'}
    resp.text = "{}"
    resp.history = []
    mock_safe_request(resp)
    
    findings = api_module.run("https://example.com/api/user/data", "example.com", None)
    finding_names = [f["name"] for f in findings]
    
    assert "Sensitive Response Tracking Indicator (ETag/Last-Modified)" in finding_names
    f = next(f for f in findings if f["name"] == "Sensitive Response Tracking Indicator (ETag/Last-Modified)")
    assert f["severity"] == "Informational"

def test_public_etag_no_finding(api_module, mock_safe_request):
    resp = MagicMock()
    resp.url = "https://example.com/api/v1/public"
    resp.headers = {"Cache-Control": "public, max-age=3600", "ETag": '"12345"'}
    resp.text = "{}"
    resp.history = []
    mock_safe_request(resp)
    
    findings = api_module.run("https://example.com/api/v1/public", "example.com", None)
    finding_names = [f["name"] for f in findings]
    
    assert "Sensitive Response Tracking Indicator (ETag/Last-Modified)" not in finding_names
    assert "Missing Cache Vary Protection on Sensitive Content" not in finding_names

def test_cdn_cache_permissive_sensitive(auth_module, mock_safe_request):
    resp = MagicMock()
    resp.url = "https://example.com/account/settings"
    resp.headers = {
        "Cache-Control": "no-store",
        "Cloudflare-CDN-Cache-Control": "max-age=3600"
    }
    resp.text = "Account Settings"
    mock_safe_request(resp)
    
    findings = auth_module.run("https://example.com/account/settings", "example.com", None)
    finding_names = [f["name"] for f in findings]
    
    assert "Permissive CDN Caching on Sensitive Content" in finding_names
    assert "Missing Cache Vary Protection on Sensitive Content" in finding_names

def test_cdn_cache_restrictive_no_fp(api_module, mock_safe_request):
    resp = MagicMock()
    resp.url = "https://example.com/api/user/me"
    resp.headers = {
        "Cache-Control": "no-store",
        "CDN-Cache-Control": "no-store"
    }
    resp.text = "{}"
    resp.history = []
    mock_safe_request(resp)
    
    findings = api_module.run("https://example.com/api/user/me", "example.com", None)
    finding_names = [f["name"] for f in findings]
    
    assert "Permissive CDN Caching on Sensitive Content" not in finding_names
    assert "Missing Cache Vary Protection on Sensitive Content" not in finding_names

def test_malformed_headers(auth_module, mock_safe_request):
    resp = MagicMock()
    resp.url = "https://example.com/login"
    resp.headers = {}
    resp.text = "login form"
    mock_safe_request(resp)
    
    findings = auth_module.run("https://example.com/login", "example.com", None)
    finding_names = [f["name"] for f in findings]
    
    assert "Authentication Response May Be Publicly Cacheable" in finding_names
    assert "Missing Cache Vary Protection on Sensitive Content" in finding_names
