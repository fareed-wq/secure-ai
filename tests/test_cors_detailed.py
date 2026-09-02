import pytest
from unittest.mock import MagicMock
from api.scanner.modules.headers import CORSModule

@pytest.fixture
def module():
    return CORSModule()

def mock_response(headers):
    resp = MagicMock()
    resp.headers = headers
    return resp

def test_cors_wildcard_no_creds(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.headers.safe_request", lambda *a, **kw: mock_response({"Access-Control-Allow-Origin": "*"}))
    findings = module.run("http://example.com", "example.com", MagicMock())
    assert len(findings) == 1
    assert findings[0]["name"] == "CORS Enabled (Wildcard)"
    assert findings[0]["severity"] == "Informational"
    assert "Origin sent: https://cors-test.invalid" in findings[0]["evidence"]["raw"]
    assert "Access-Control-Allow-Origin: *" in findings[0]["evidence"]["raw"]

def test_cors_wildcard_with_creds(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.headers.safe_request", lambda *a, **kw: mock_response({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}))
    findings = module.run("http://example.com", "example.com", MagicMock())
    assert len(findings) == 1
    assert findings[0]["name"] == "Insecure CORS Policy (Wildcard with Credentials)"
    assert findings[0]["severity"] == "Low"

def test_cors_reflected_creds(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.headers.safe_request", lambda *a, **kw: mock_response({"Access-Control-Allow-Origin": "https://cors-test.invalid", "Access-Control-Allow-Credentials": "True"}))
    findings = module.run("http://example.com", "example.com", MagicMock())
    assert len(findings) == 1
    assert findings[0]["name"] == "Insecure CORS Policy (Arbitrary Origin Reflection with Credentials)"
    assert findings[0]["severity"] == "High"

def test_cors_reflected_no_creds(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.headers.safe_request", lambda *a, **kw: mock_response({"Access-Control-Allow-Origin": "https://cors-test.invalid", "Access-Control-Allow-Credentials": "false"}))
    findings = module.run("http://example.com", "example.com", MagicMock())
    assert len(findings) == 1
    assert findings[0]["name"] == "Insecure CORS Policy (Arbitrary Origin Reflection)"
    assert findings[0]["severity"] == "Low"

def test_cors_trusted_origin(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.headers.safe_request", lambda *a, **kw: mock_response({"Access-Control-Allow-Origin": "https://trusted.com"}))
    findings = module.run("http://example.com", "example.com", MagicMock())
    assert len(findings) == 1
    assert findings[0]["name"] == "CORS Configured for Specific Origin"
    assert findings[0]["severity"] == "Informational"

def test_cors_null_creds(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.headers.safe_request", lambda *a, **kw: mock_response({"Access-Control-Allow-Origin": "null", "Access-Control-Allow-Credentials": "tRuE"}))
    findings = module.run("http://example.com", "example.com", MagicMock())
    assert len(findings) == 1
    assert findings[0]["name"] == "CORS Null-Origin Configuration Observed"
    assert findings[0]["severity"] == "Low"

def test_cors_null_no_creds(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.headers.safe_request", lambda *a, **kw: mock_response({"Access-Control-Allow-Origin": "null"}))
    findings = module.run("http://example.com", "example.com", MagicMock())
    assert len(findings) == 1
    assert findings[0]["name"] == "CORS Null-Origin Configuration Observed"
    assert findings[0]["severity"] == "Informational"

def test_cors_missing(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.headers.safe_request", lambda *a, **kw: mock_response({}))
    findings = module.run("http://example.com", "example.com", MagicMock())
    assert len(findings) == 1
    assert findings[0]["name"] == "Strict CORS Policy Enforced"
    assert findings[0]["severity"] == "Passed"

def test_cors_invalid_acac(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.headers.safe_request", lambda *a, **kw: mock_response({"Access-Control-Allow-Origin": "https://cors-test.invalid", "Access-Control-Allow-Credentials": "yes"}))
    findings = module.run("http://example.com", "example.com", MagicMock())
    assert len(findings) == 1
    assert findings[0]["name"] == "Insecure CORS Policy (Arbitrary Origin Reflection)"
    assert findings[0]["severity"] == "Low"

import requests

def test_cors_timeout(module, monkeypatch):
    def mock_raise(*args, **kwargs):
        raise requests.exceptions.Timeout("Timeout")
    monkeypatch.setattr("api.scanner.modules.headers.safe_request", mock_raise)
    findings = module.run("http://example.com", "example.com", MagicMock())
    assert len(findings) == 0

def test_cors_connection_error(module, monkeypatch):
    def mock_raise(*args, **kwargs):
        raise requests.exceptions.ConnectionError("ConnError")
    monkeypatch.setattr("api.scanner.modules.headers.safe_request", mock_raise)
    findings = module.run("http://example.com", "example.com", MagicMock())
    assert len(findings) == 0

def test_cors_request_exception(module, monkeypatch):
    def mock_raise(*args, **kwargs):
        raise requests.exceptions.RequestException("ReqError")
    monkeypatch.setattr("api.scanner.modules.headers.safe_request", mock_raise)
    findings = module.run("http://example.com", "example.com", MagicMock())
    assert len(findings) == 0

def test_cors_none_response(module, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.headers.safe_request", lambda *a, **kw: None)
    findings = module.run("http://example.com", "example.com", MagicMock())
    assert len(findings) == 0

def test_cors_evaluation_exception(module, monkeypatch):
    def mock_resp(*args, **kwargs):
        resp = MagicMock()
        type(resp).headers = property(lambda self: (_ for _ in ()).throw(Exception("Eval Error")))
        return resp
    monkeypatch.setattr("api.scanner.modules.headers.safe_request", mock_resp)
    findings = module.run("http://example.com", "example.com", MagicMock())
    assert len(findings) == 0
