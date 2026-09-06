import pytest
from unittest.mock import MagicMock
import requests

from api.scanner.modules.http_security import SecurityHeadersModule, AdvancedSecurityHeadersModule
from api.scanner.modules.headers import PermissionsPolicyModule
from api.scanner.modules.discovery import SecurityTxtModule

def run_headers(module, headers, monkeypatch, session, module_path="api.scanner.modules.http_security.safe_request"):
    def mock_safe_request(method, url, **kwargs):
        mock_resp = MagicMock()
        mock_resp.headers = requests.structures.CaseInsensitiveDict(headers)
        mock_resp.status_code = 200
        mock_resp.text = ""
        return mock_resp
    monkeypatch.setattr(module_path, mock_safe_request)
    if "headers" in module_path:
        monkeypatch.setattr("api.scanner.modules.headers.get_all_headers", lambda r: requests.structures.CaseInsensitiveDict(headers))
    return module.run("https://example.com", "example.com", MagicMock())

# --- REFERRER-POLICY ---
def test_referrer_missing(monkeypatch):
    findings = run_headers(SecurityHeadersModule(), {}, monkeypatch, MagicMock())
    f = next((x for x in findings if x["name"] == "Referrer-Policy Not Configured"), None)
    assert f is not None
    assert f["severity"] == "Informational"

def test_referrer_strict(monkeypatch):
    findings = run_headers(SecurityHeadersModule(), {"Referrer-Policy": "strict-origin-when-cross-origin"}, monkeypatch, MagicMock())
    assert not any(x["severity"] in ["Low", "Medium", "High", "Critical"] for x in findings if "Referrer" in x["name"])

def test_referrer_noreferrer(monkeypatch):
    findings = run_headers(SecurityHeadersModule(), {"Referrer-Policy": "no-referrer"}, monkeypatch, MagicMock())
    assert not any(x["severity"] in ["Low", "Medium", "High", "Critical"] for x in findings if "Referrer" in x["name"])

def test_referrer_unsafe_url(monkeypatch):
    findings = run_headers(SecurityHeadersModule(), {"Referrer-Policy": "unsafe-url"}, monkeypatch, MagicMock())
    f = next((x for x in findings if x["name"] == "Unsafe Referrer Policy Configured"), None)
    assert f is not None
    assert f["severity"] == "Low"

def test_referrer_invalid(monkeypatch):
    findings = run_headers(SecurityHeadersModule(), {"Referrer-Policy": "garbage"}, monkeypatch, MagicMock())
    f = next((x for x in findings if x["name"] == "Invalid Referrer-Policy"), None)
    assert f is not None
    assert f["severity"] == "Informational"


def test_referrer_multiple(monkeypatch):
    findings = run_headers(SecurityHeadersModule(), {"Referrer-Policy": "garbage, strict-origin-when-cross-origin"}, monkeypatch, MagicMock())
    assert any(x["name"] == "Referrer-Policy Configured" for x in findings)

def test_referrer_multiple_unsafe(monkeypatch):
    findings = run_headers(SecurityHeadersModule(), {"Referrer-Policy": "garbage, unsafe-url"}, monkeypatch, MagicMock())
    assert any(x["name"] == "Unsafe Referrer Policy Configured" for x in findings)

def test_referrer_safe_and_unknown(monkeypatch):
    findings = run_headers(SecurityHeadersModule(), {"Referrer-Policy": "no-referrer, future-policy"}, monkeypatch, MagicMock())
    assert any(x["name"] == "Referrer-Policy Configured" for x in findings)

# --- PERMISSIONS-POLICY ---
def test_permissions_missing(monkeypatch):
    findings = run_headers(PermissionsPolicyModule(), {}, monkeypatch, MagicMock(), "api.scanner.modules.headers.safe_request")
    f = next((x for x in findings if x["name"] == "Permissions-Policy Not Configured"), None)
    assert f is not None
    assert f["severity"] == "Informational"

def test_permissions_valid(monkeypatch):
    findings = run_headers(PermissionsPolicyModule(), {"Permissions-Policy": "geolocation=()"}, monkeypatch, MagicMock(), "api.scanner.modules.headers.safe_request")
    assert not any(x["name"] == "Permissions-Policy Not Configured" for x in findings)
    assert not any(x["name"] == "Permissive Permissions-Policy" for x in findings)

def test_permissions_explicit_broad(monkeypatch):
    findings = run_headers(PermissionsPolicyModule(), {"Permissions-Policy": "camera=*"}, monkeypatch, MagicMock(), "api.scanner.modules.headers.safe_request")
    f = next((x for x in findings if x["name"] == "Permissive Permissions-Policy"), None)
    assert f is not None
    assert f["severity"] == "Low"

# --- CORP ---
def test_corp_missing(monkeypatch):
    findings = run_headers(AdvancedSecurityHeadersModule(), {}, monkeypatch, MagicMock())
    f = next((x for x in findings if x["name"] == "CORP Not Configured"), None)
    assert f is not None
    assert f["severity"] == "Informational"

def test_corp_valid(monkeypatch):
    for val in ["same-origin", "same-site", "cross-origin"]:
        findings = run_headers(AdvancedSecurityHeadersModule(), {"Cross-Origin-Resource-Policy": val}, monkeypatch, MagicMock())
        assert not any(x["name"] in ["Invalid Cross-Origin-Resource-Policy", "CORP Not Configured"] for x in findings)

def test_corp_invalid(monkeypatch):
    for val in ["unsafe-none", "garbage"]:
        findings = run_headers(AdvancedSecurityHeadersModule(), {"Cross-Origin-Resource-Policy": val}, monkeypatch, MagicMock())
        f = next((x for x in findings if x["name"] == "Invalid Cross-Origin-Resource-Policy"), None)
        assert f is not None
        assert f["severity"] == "Informational"

# --- SECURITY.TXT ---
def run_security_txt(responses_map, monkeypatch, session):
    def mock_safe_request(method, url, **kwargs):
        mock_resp = MagicMock()
        if url in responses_map:
            resp_data = responses_map[url]
            mock_resp.status_code = resp_data.get("status_code", 200)
            mock_resp.text = resp_data.get("text", "")
            mock_resp.headers = requests.structures.CaseInsensitiveDict(resp_data.get("headers", {"Content-Type": "text/plain"}))
        else:
            mock_resp.status_code = 404
            mock_resp.text = ""
        return mock_resp
    monkeypatch.setattr("api.scanner.modules.discovery.safe_request", mock_safe_request)
    return SecurityTxtModule().run("https://example.com", "example.com", MagicMock())

def test_sectxt_valid(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "Valid security.txt" for x in findings)

def test_sectxt_legacy(monkeypatch):
    findings = run_security_txt({
        "https://example.com/security.txt": {"text": "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "security.txt Uses Legacy Location" for x in findings)
    assert not any(x["name"] == "Valid security.txt" for x in findings)

def test_sectxt_both_wellknown_wins(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:well@a.com\nExpires: 2099-01-01T00:00:00Z"},
        "https://example.com/security.txt": {"text": "Contact: mailto:legacy@a.com\nExpires: 2099-01-01T00:00:00Z"}
    }, monkeypatch, MagicMock())
    assert not any(x["name"] == "security.txt Uses Legacy Location" for x in findings)
    assert any(x["name"] == "Valid security.txt" for x in findings)

def test_sectxt_neither(monkeypatch):
    findings = run_security_txt({}, monkeypatch, MagicMock())
    assert any(x["name"] == "security.txt Not Found" for x in findings)

def test_sectxt_missing_contact(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Expires: 2099-01-01T00:00:00Z"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "security.txt Missing Contact" for x in findings)

def test_sectxt_multiple_contact(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:security@example.com\nContact: https://example.com/security\nExpires: 2099-01-01T00:00:00Z"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "Valid security.txt" for x in findings)


def test_sectxt_invalid_contact_email(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: security@example.com\nExpires: 2099-01-01T00:00:00Z"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "security.txt Missing Contact" for x in findings)

def test_sectxt_invalid_contact_http(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: http://example.com/security\nExpires: 2099-01-01T00:00:00Z"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "security.txt Missing Contact" for x in findings)

def test_sectxt_invalid_contact_garbage(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: garbage\nExpires: 2099-01-01T00:00:00Z"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "security.txt Missing Contact" for x in findings)

def test_sectxt_valid_contact_tel(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: tel:+12015550123\nExpires: 2099-01-01T00:00:00Z"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "Valid security.txt" for x in findings)
def test_sectxt_missing_expires(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:security@example.com"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "security.txt Missing Expires" for x in findings)

def test_sectxt_invalid_expires(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:security@example.com\nExpires: garbage"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "security.txt Invalid Expires" for x in findings)

def test_sectxt_expired(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:security@example.com\nExpires: 2000-01-01T00:00:00Z"}
    }, monkeypatch, MagicMock())
    f = next((x for x in findings if x["name"] == "Expired security.txt"), None)
    assert f is not None
    assert f["severity"] == "Low"

def test_sectxt_multiple_expires(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z\nExpires: 2099-01-01T00:00:00Z"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "security.txt Multiple Expires" for x in findings)


def test_sectxt_timezone_naive_expires(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "security.txt Invalid Expires" for x in findings)
def test_sectxt_comments(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "# This is a comment\nContact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "Valid security.txt" for x in findings)

def test_sectxt_html_fallback(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "<html><body>Not Found</body></html>"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "security.txt Not Found" for x in findings)

def test_sectxt_correct_content_type(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z", "headers": {"Content-Type": "text/plain; charset=utf-8"}}
    }, monkeypatch, MagicMock())
    assert not any(x["name"] == "security.txt Incorrect Content-Type" for x in findings)

def test_sectxt_incorrect_content_type(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z", "headers": {"Content-Type": "application/json"}}
    }, monkeypatch, MagicMock())
    f = next((x for x in findings if x["name"] == "security.txt Incorrect Content-Type"), None)
    assert f is not None
    assert f["severity"] == "Informational"


def test_sectxt_html_primary_valid_legacy(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "<html><body>Not Found</body></html>", "headers": {"Content-Type": "text/html"}},
        "https://example.com/security.txt": {"text": "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z", "headers": {"Content-Type": "text/plain"}}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "security.txt Uses Legacy Location" for x in findings)
    assert not any(x["name"] == "Valid security.txt" for x in findings)

def test_sectxt_rfc3339_bad_format_1(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:security@example.com\nExpires: 2099-01-01 00:00:00Z"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "security.txt Invalid Expires" for x in findings)

def test_sectxt_rfc3339_bad_format_2(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:security@example.com\nExpires: 2099/01/01T00:00:00Z"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "security.txt Invalid Expires" for x in findings)

def test_sectxt_rfc3339_fractional(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00.123Z"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "Valid security.txt" for x in findings)

def test_sectxt_valid_unfamiliar_schemes(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: sip:security@example.com\nContact: xmpp:security@example.com\nExpires: 2099-01-01T00:00:00Z"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "Valid security.txt" for x in findings)
    assert not any(x["name"] == "security.txt Missing Contact" for x in findings)

def test_sectxt_invalid_unfamiliar_schemes(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: sip:\nContact: xmpp:\nContact: custom:\nExpires: 2099-01-01T00:00:00Z"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "security.txt Missing Contact" for x in findings)

def test_sectxt_whitespace_uri(monkeypatch):
    findings = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:a\tb@c.com\nExpires: 2099-01-01T00:00:00Z"}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "security.txt Missing Contact" for x in findings)

def test_sectxt_content_type_micro(monkeypatch):
    # Valid
    findings1 = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z", "headers": {"Content-Type": "text/plain; charset=utf-8"}}
    }, monkeypatch, MagicMock())
    assert any(x["name"] == "Valid security.txt" for x in findings1)

    # Invalid
    findings2 = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z", "headers": {"Content-Type": "application/text/plain"}}
    }, monkeypatch, MagicMock())
    assert not any(x["name"] == "Valid security.txt" for x in findings2)

    findings3 = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z", "headers": {"Content-Type": "application/text/plain+json"}}
    }, monkeypatch, MagicMock())
    assert not any(x["name"] == "Valid security.txt" for x in findings3)

    findings4 = run_security_txt({
        "https://example.com/.well-known/security.txt": {"text": "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z", "headers": {"Content-Type": "text/plainfake"}}
    }, monkeypatch, MagicMock())
    assert not any(x["name"] == "Valid security.txt" for x in findings4)

