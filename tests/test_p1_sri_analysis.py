import pytest
from unittest.mock import patch, MagicMock
from api.scanner.modules.http_security import SecurityHeadersModule

@pytest.fixture
def module():
    return SecurityHeadersModule()

@pytest.fixture
def mock_safe_request():
    with patch('api.scanner.modules.http_security.safe_request') as mock_req:
        def set_mock_response(resp):
            mock_req.return_value = resp
            return resp
        yield set_mock_response

def run_with_html(module, url, html_content, mock_safe_request):
    resp = MagicMock()
    resp.url = url
    resp.text = html_content
    resp.headers = {}
    resp.history = []
    mock_safe_request(resp)
    return module.run(url, "example.com", None)

def test_first_party_script(module, mock_safe_request):
    html = '<script src="https://example.com/app.js"></script>'
    findings = run_with_html(module, "https://example.com", html, mock_safe_request)
    names = [f["name"] for f in findings]
    assert "Third-Party Script Execution Detected" not in names
    assert "Missing Subresource Integrity" not in names

def test_first_party_subdomain_script(module, mock_safe_request):
    html = '<script src="https://assets.example.com/app.js"></script>'
    findings = run_with_html(module, "https://www.example.com", html, mock_safe_request)
    names = [f["name"] for f in findings]
    assert "Third-Party Script Execution Detected" not in names
    assert "Missing Subresource Integrity" not in names

def test_third_party_script_inventory(module, mock_safe_request):
    html = '<script src="https://cdn.otherdomain.com/app.js"></script>'
    findings = run_with_html(module, "https://example.com", html, mock_safe_request)
    names = [f["name"] for f in findings]
    assert "Third-Party Script Execution Detected" in names
    f = next(f for f in findings if f["name"] == "Third-Party Script Execution Detected")
    assert "cdn.otherdomain.com" in str(f["evidence"])

def test_third_party_script_without_integrity(module, mock_safe_request):
    html = '<script src="https://cdn.otherdomain.com/app.js"></script>'
    findings = run_with_html(module, "https://example.com", html, mock_safe_request)
    names = [f["name"] for f in findings]
    assert "Missing Subresource Integrity" in names

def test_valid_sha256(module, mock_safe_request):
    html = '<script src="https://cdn.otherdomain.com/app.js" integrity="sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" crossorigin="anonymous"></script>'
    findings = run_with_html(module, "https://example.com", html, mock_safe_request)
    names = [f["name"] for f in findings]
    assert "Malformed Subresource Integrity (SRI) Attribute" not in names
    assert "Missing Subresource Integrity" not in names

def test_valid_sha384(module, mock_safe_request):
    html = '<script src="https://cdn.otherdomain.com/app.js" integrity="sha384-H8BRh8j48O9oYat+NdfrDc+GWT5N/h65rF/Gq2s3F4Y2v/g=" crossorigin="anonymous"></script>'
    findings = run_with_html(module, "https://example.com", html, mock_safe_request)
    names = [f["name"] for f in findings]
    assert "Malformed Subresource Integrity (SRI) Attribute" not in names

def test_valid_sha512(module, mock_safe_request):
    html = '<script src="https://cdn.otherdomain.com/app.js" integrity="sha512-H8BRh8j48O9oYat+NdfrDc+GWT5N/h65rF/Gq2s3F4Y2v/g=" crossorigin="anonymous"></script>'
    findings = run_with_html(module, "https://example.com", html, mock_safe_request)
    names = [f["name"] for f in findings]
    assert "Malformed Subresource Integrity (SRI) Attribute" not in names

def test_malformed_integrity(module, mock_safe_request):
    html = '<script src="https://cdn.otherdomain.com/app.js" integrity="md5-invalid" crossorigin="anonymous"></script>'
    findings = run_with_html(module, "https://example.com", html, mock_safe_request)
    names = [f["name"] for f in findings]
    assert "Malformed Subresource Integrity (SRI) Attribute" in names

def test_multiple_valid_integrity_tokens(module, mock_safe_request):
    html = '<script src="https://cdn.otherdomain.com/app.js" integrity="sha256-val1 sha384-val2=" crossorigin="anonymous"></script>'
    findings = run_with_html(module, "https://example.com", html, mock_safe_request)
    names = [f["name"] for f in findings]
    assert "Malformed Subresource Integrity (SRI) Attribute" not in names

def test_third_party_sri_without_crossorigin(module, mock_safe_request):
    html = '<script src="https://cdn.otherdomain.com/app.js" integrity="sha384-val1"></script>'
    findings = run_with_html(module, "https://example.com", html, mock_safe_request)
    names = [f["name"] for f in findings]
    assert "Missing crossorigin for SRI Resource" in names

def test_third_party_sri_with_crossorigin(module, mock_safe_request):
    html = '<script src="https://cdn.otherdomain.com/app.js" integrity="sha384-val1" crossorigin="anonymous"></script>'
    findings = run_with_html(module, "https://example.com", html, mock_safe_request)
    names = [f["name"] for f in findings]
    assert "Missing crossorigin for SRI Resource" not in names

def test_same_origin_sri_without_crossorigin(module, mock_safe_request):
    html = '<script src="https://example.com/app.js" integrity="sha384-val1"></script>'
    findings = run_with_html(module, "https://example.com", html, mock_safe_request)
    names = [f["name"] for f in findings]
    assert "Missing crossorigin for SRI Resource" not in names
