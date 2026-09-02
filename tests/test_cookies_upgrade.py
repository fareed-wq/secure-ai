
import pytest
from unittest.mock import MagicMock
from api.scanner.modules.http_security import AdvancedCookieModule

@pytest.fixture
def module():
    return AdvancedCookieModule()

def mock_resp(headers_list):
    resp = MagicMock()
    # Mock for getlist
    resp.raw.headers.getlist.return_value = headers_list
    return resp

def test_cookie_classification_anti_forgery(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp(["anti-forgery-token=123"]))
    findings = module.run("https://example.com", "example.com", MagicMock())
    # Should not be treated as session cookie -> no Medium findings, only Informational
    assert not any(f["severity"] == "Medium" for f in findings)
    assert any("Non-Session Cookie" in f["name"] for f in findings)

def test_cookie_classification_xsrf_token(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp(["XSRF-TOKEN=123"]))
    findings = module.run("https://example.com", "example.com", MagicMock())
    assert not any(f["severity"] == "Medium" for f in findings)
    assert any("Non-Session Cookie" in f["name"] for f in findings)

def test_cookie_classification_session_token(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp(["session_token=123"]))
    findings = module.run("https://example.com", "example.com", MagicMock())
    # Missing Secure/HttpOnly on session cookie -> Medium
    assert any(f["severity"] == "Medium" for f in findings)

def test_cookie_classification_auth_state(module, monkeypatch):
    # contains "state" but also "auth" -> should be session cookie
    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp(["auth_state=123"]))
    findings = module.run("https://example.com", "example.com", MagicMock())
    assert any(f["severity"] == "Medium" for f in findings)

def test_cookie_samesite_none_without_secure(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp(["analytics_cookie=123; SameSite=None"]))
    findings = module.run("https://example.com", "example.com", MagicMock())
    # Should flag SameSite=None without Secure as Low for non-session cookies
    samesite_finding = next((f for f in findings if "Cookie Uses SameSite=None Without Secure" in f["name"]), None)
    print(f"DEBUG FINDINGS: {findings}")
    assert samesite_finding is not None
    assert samesite_finding["severity"] == "Low"

def test_cookie_samesite_none_session_suppression(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp(["session_token=123; SameSite=None"]))
    findings = module.run("https://example.com", "example.com", MagicMock())
    # Should flag missing Secure as Medium, but NOT emit Cookie Uses SameSite=None Without Secure
    secure_finding = next((f for f in findings if "Session Cookie Missing Secure Flag" in f["name"]), None)
    samesite_finding = next((f for f in findings if "Cookie Uses SameSite=None Without Secure" in f["name"]), None)
    assert secure_finding is not None
    assert "SameSite=None" in secure_finding["description"]
    assert samesite_finding is None

def test_cookie_prefix_host_valid(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp(["__Host-valid=1; Secure; Path=/"]))
    findings = module.run("https://example.com", "example.com", MagicMock())
    assert not any("Prefix" in f["name"] for f in findings)

def test_cookie_prefix_host_invalid_path(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp(["__Host-inv=1; Secure; Path=/foo"]))
    findings = module.run("https://example.com", "example.com", MagicMock())
    prefix_finding = next((f for f in findings if "Invalid __Host-" in f["name"]), None)
    assert prefix_finding is not None
    assert prefix_finding["severity"] == "Low"
    assert "Path is not '/'" in prefix_finding["evidence"]["raw"]

def test_cookie_prefix_host_domain(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp(["__Host-inv=1; Secure; Path=/; Domain=foo"]))
    findings = module.run("https://example.com", "example.com", MagicMock())
    prefix_finding = next((f for f in findings if "Invalid __Host-" in f["name"]), None)
    assert prefix_finding is not None
    assert prefix_finding["severity"] == "Low"
    assert "Domain is present" in prefix_finding["evidence"]["raw"]

def test_cookie_prefix_secure(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp(["__Secure-valid=1; Secure"]))
    findings = module.run("https://example.com", "example.com", MagicMock())
    assert not any("Prefix" in f["name"] for f in findings)

    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp(["__Secure-inv=1; Path=/"]))
    findings2 = module.run("https://example.com", "example.com", MagicMock())
    assert any("Invalid __Secure-" in f["name"] for f in findings2)
    assert any(f["severity"] == "Low" for f in findings2 if "Invalid __Secure-" in f["name"])

    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp(["__secure-lowercase=1; Path=/"]))
    findings3 = module.run("https://example.com", "example.com", MagicMock())
    assert not any("Prefix" in f["name"] for f in findings3)

def test_cookie_quoted_values(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp(['__Host-test=1; Secure; Path="/"; SameSite="None"']))
    findings = module.run("https://example.com", "example.com", MagicMock())
    assert not any("Invalid __Host-" in f["name"] for f in findings)

def test_cookie_multiple_headers_comma(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp([
        "cookie1=1; Expires=Wed, 21 Oct 2030 07:28:00 GMT",
        "cookie2=2"
    ]))
    findings = module.run("https://example.com", "example.com", MagicMock())
    cookie_str = str(findings)
    assert "cookie1" in cookie_str
    assert "cookie2" in cookie_str

def test_cookie_value_privacy(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp(["session_token=SUPER_SECRET_123; Secure"]))
    findings = module.run("https://example.com", "example.com", MagicMock())
    for f in findings:
        assert "SUPER_SECRET_123" not in f["evidence"]["raw"]
        assert "SUPER_SECRET_123" not in f["description"]



def test_cookie_classification_false_positives(module, monkeypatch):
    fp_names = [
        "author_name", "resident_id", "outside_link", "analytics_token_expiry",
        "authentication_preference", "visitor_id", "consent_id",
        "marketing_token_version", "token_expiry_setting"
    ]
    for name in fp_names:
        monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp([f"{name}=abc"]))
        findings = module.run("https://example.com", "example.com", MagicMock())
        assert not any(f["severity"] == "Medium" for f in findings), f"{name} should NOT be session"
        assert any("Non-Session" in f["name"] for f in findings), f"{name} should be non-session"

def test_cookie_classification_true_positives(module, monkeypatch):
    tp_names = [
        "session", "session_id", "session_token", "auth_token", "auth_state",
        "access_token", "refresh_token", "token", "jwt", "connect.sid",
        "PHPSESSID", "JSESSIONID"
    ]
    for name in tp_names:
        monkeypatch.setattr("api.scanner.modules.http_security.safe_request", lambda *a, **kw: mock_resp([f"{name}=abc"]))
        findings = module.run("https://example.com", "example.com", MagicMock())
        assert any(f["severity"] == "Medium" for f in findings), f"{name} SHOULD be session"
