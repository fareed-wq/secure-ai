import pytest
import requests
from unittest.mock import MagicMock
from api.scanner.modules.discovery import SecurityTxtModule
from api.scanner.modules.headers import PermissionsPolicyModule
from api.scanner.modules.http_security import AdvancedCookieModule, AdvancedSecurityHeadersModule

@pytest.fixture
def session():
    return requests.Session()

def create_mock_response(text="", status_code=200, headers=None):
    if headers is None:
        headers = {}
    mock_resp = MagicMock()
    mock_resp.text = text
    mock_resp.status_code = status_code
    mock_resp.headers = headers
    # Simulate get_all_headers
    mock_resp.raw = MagicMock()
    mock_resp.raw.headers = MagicMock()
    mock_resp.raw.headers.get = headers.get
    return mock_resp

def test_security_txt_valid(monkeypatch, session):
    module = SecurityTxtModule()

    def mock_safe_request(method, url, **kwargs):
        if url.endswith(".well-known/security.txt"):
            content = "Contact: mailto:security@example.com\nExpires: 2030-12-31T23:59:59Z\nPolicy: https://example.com/policy\nPreferred-Languages: en, es"
            return create_mock_response(text=content, headers={"Content-Type": "text/plain"})
        return create_mock_response(text="homepage" * 200, headers={"Content-Type": "text/html"})

    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", mock_safe_request)
    findings = module.run("http://example.com", "example.com", session)

    assert any(f["name"] == "Valid security.txt" for f in findings)
    assert any(f["name"] == "security.txt Policy Configured" for f in findings)
    assert any(f["name"] == "security.txt Preferred-Languages Configured" for f in findings)

def test_security_txt_missing_contact(monkeypatch, session):
    module = SecurityTxtModule()

    def mock_safe_request(method, url, **kwargs):
        if url.endswith(".well-known/security.txt"):
            content = "Expires: 2030-12-31T23:59:59Z"
            return create_mock_response(text=content, headers={"Content-Type": "text/plain"})
        return create_mock_response(text="homepage" * 200, headers={"Content-Type": "text/html"})

    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", mock_safe_request)
    findings = module.run("http://example.com", "example.com", session)
    assert any(f["name"] == "security.txt Missing Contact" for f in findings)

def test_security_txt_expired(monkeypatch, session):
    module = SecurityTxtModule()

    def mock_safe_request(method, url, **kwargs):
        if url.endswith(".well-known/security.txt"):
            content = "Contact: mailto:a@b.com\nExpires: 2020-01-01T00:00:00Z"
            return create_mock_response(text=content, headers={"Content-Type": "text/plain"})
        return create_mock_response(text="homepage" * 200, headers={"Content-Type": "text/html"})

    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", mock_safe_request)
    findings = module.run("http://example.com", "example.com", session)
    assert any(f["name"] == "Expired security.txt" for f in findings)

def test_security_txt_invalid_expires(monkeypatch, session):
    module = SecurityTxtModule()

    def mock_safe_request(method, url, **kwargs):
        if url.endswith(".well-known/security.txt"):
            content = "Contact: mailto:a@b.com\nExpires: not-a-date"
            return create_mock_response(text=content, headers={"Content-Type": "text/plain"})
        return create_mock_response(text="homepage" * 200, headers={"Content-Type": "text/html"})

    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", mock_safe_request)
    findings = module.run("http://example.com", "example.com", session)
    assert any(f["name"] == "security.txt Invalid Expires" for f in findings)

def test_permissions_policy_permissive(monkeypatch, session):
    module = PermissionsPolicyModule()

    def mock_safe_request(method, url, **kwargs):
        return create_mock_response(headers={"Permissions-Policy": "geolocation=*, camera=*, microphone=()"})

    monkeypatch.setattr("api.scanner.modules.headers.safe_request", mock_safe_request)
    # mock get_all_headers
    monkeypatch.setattr("api.scanner.modules.headers.get_all_headers", lambda r: {"Permissions-Policy": "geolocation=*, camera=*, microphone=()"})

    findings = module.run("http://example.com", "example.com", session)
    assert any(f["name"] == "Permissive Permissions-Policy" for f in findings)

def test_permissions_policy_restrictive(monkeypatch, session):
    module = PermissionsPolicyModule()

    def mock_safe_request(method, url, **kwargs):
        return create_mock_response(headers={"Permissions-Policy": "geolocation=(), camera=()"})

    monkeypatch.setattr("api.scanner.modules.headers.safe_request", mock_safe_request)
    monkeypatch.setattr("api.scanner.modules.headers.get_all_headers", lambda r: {"Permissions-Policy": "geolocation=(), camera=()"})

    findings = module.run("http://example.com", "example.com", session)
    assert any(f["name"] == "Permissions-Policy Configured" for f in findings)

def test_cross_origin_isolation_all_missing(monkeypatch, session):
    module = AdvancedSecurityHeadersModule()

    def mock_safe_request(method, url, **kwargs):
        return create_mock_response(headers={})

    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", mock_safe_request)
    findings = module.run("http://example.com", "example.com", session)

    # Missing headers remain informational
    assert any(f["name"] == "Missing COOP Header" and f["severity"] == "Informational" for f in findings)
    assert any(f["name"] == "Missing COEP Header" and f["severity"] == "Informational" for f in findings)
    assert any(f["name"] == "Missing CORP Header" and f["severity"] == "Informational" for f in findings)

    # No duplicate findings for Weak
    assert not any(f["name"] == "Weak Cross-Origin Isolation" for f in findings)

def test_cross_origin_isolation_all_present_and_valid(monkeypatch, session):
    module = AdvancedSecurityHeadersModule()

    def mock_safe_request(method, url, **kwargs):
        return create_mock_response(headers={
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Resource-Policy": "same-origin"
        })

    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", mock_safe_request)
    findings = module.run("http://example.com", "example.com", session)
    assert any(f["name"] == "Cross-Origin Isolation Configured" and f["severity"] == "Passed" for f in findings)
    assert not any(f["name"] == "Missing COOP Header" for f in findings)

def test_cross_origin_isolation_weak_coop(monkeypatch, session):
    module = AdvancedSecurityHeadersModule()

    def mock_safe_request(method, url, **kwargs):
        return create_mock_response(headers={
            "Cross-Origin-Opener-Policy": "unsafe-none",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Resource-Policy": "same-origin"
        })

    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", mock_safe_request)
    findings = module.run("http://example.com", "example.com", session)
    assert any(f["name"] == "Weak Cross-Origin Isolation" and "COOP" in str(f.get("evidence", "")) for f in findings)
    assert not any(f["name"] == "Missing COOP Header" for f in findings)

def test_cross_origin_isolation_weak_coep_corp(monkeypatch, session):
    module = AdvancedSecurityHeadersModule()

    def mock_safe_request(method, url, **kwargs):
        return create_mock_response(headers={
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "unsafe-none",
            "Cross-Origin-Resource-Policy": "unsafe-none"
        })

    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", mock_safe_request)
    findings = module.run("http://example.com", "example.com", session)
    assert any(f["name"] == "Weak Cross-Origin Isolation" and "COEP" in str(f.get("evidence", "")) and "CORP" in str(f.get("evidence", "")) for f in findings)

def test_cookie_lifetime_excessive(monkeypatch, session):
    module = AdvancedCookieModule()

    def mock_safe_request(method, url, **kwargs):
        resp = create_mock_response(headers={})
        resp.raw.headers.getlist = lambda x: ["session=123; Max-Age=315360000"] # 10 years
        return resp

    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", mock_safe_request)
    findings = module.run("https://example.com", "example.com", session)
    assert any(f["name"] == "Persistent Authentication Cookie" for f in findings)

def test_cookie_lifetime_informational(monkeypatch, session):
    module = AdvancedCookieModule()

    def mock_safe_request(method, url, **kwargs):
        resp = create_mock_response(headers={})
        resp.raw.headers.getlist = lambda x: ["tracking_cookie=123; Max-Age=315360000"] # 10 years
        return resp

    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", mock_safe_request)
    findings = module.run("https://example.com", "example.com", session)
    assert any(f["name"] == "Excessive Cookie Lifetime" for f in findings)

def test_cookie_lifetime_expired(monkeypatch, session):
    module = AdvancedCookieModule()

    def mock_safe_request(method, url, **kwargs):
        resp = create_mock_response(headers={})
        resp.raw.headers.getlist = lambda x: ["non_session=123; Max-Age=0"] # delete
        return resp

    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", mock_safe_request)
    findings = module.run("https://example.com", "example.com", session)
    assert not any(f["name"] == "Excessive Cookie Lifetime" for f in findings)
    assert not any(f["name"] == "Persistent Authentication Cookie" for f in findings)
