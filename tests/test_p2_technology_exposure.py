import pytest
from unittest.mock import MagicMock, patch
from api.scanner.modules.headers import TechFingerprintModule
import requests

@pytest.fixture
def headers_module():
    return TechFingerprintModule()

@pytest.fixture
def mock_session():
    return MagicMock(spec=requests.Session)

def create_mock_response(status_code, text, headers=None):
    mock = MagicMock()
    mock.status_code = status_code
    mock.text = text
    mock.headers = headers or {}
    return mock

def test_x_powered_by_versioned(headers_module, mock_session):
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, "<html></html>", {"X-Powered-By": "PHP/8.2"})):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        assert len(findings) == 1
        assert "Technology Fingerprint Identified" in findings[0]["name"]
        assert "Detected: PHP 8.2" in str(findings[0]["evidence"])
        assert findings[0]["severity"] == "Informational"

def test_server_versioned(headers_module, mock_session):
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, "<html></html>", {"Server": "nginx/1.24.0"})):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        assert len(findings) == 1
        assert "Detected: nginx 1.24.0" in str(findings[0]["evidence"])

def test_x_aspnet_version_detected(headers_module, mock_session):
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, "", {"X-AspNet-Version": "4.0.30319"})):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        assert len(findings) == 1
        assert "Detected: ASP.NET 4.0.30319" in str(findings[0]["evidence"])
        assert findings[0]["severity"] == "Informational"

def test_fake_version_amazon_s3(headers_module, mock_session):
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, "", {"Server": "AmazonS3"})):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        assert len(findings) == 1
        assert "Detected: AmazonS3" in str(findings[0]["evidence"])
        assert "Detected: AmazonS3 " not in str(findings[0]["evidence"])

def test_fake_version_platform(headers_module, mock_session):
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, "", {"X-Powered-By": "Platform365"})):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        assert len(findings) == 1
        assert "Detected: Platform365" in str(findings[0]["evidence"])

def test_wp_generator_html(headers_module, mock_session):
    html = '<html><head><meta name="generator" content="WordPress 6.6"></head></html>'
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, html)):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        assert len(findings) == 1
        assert "Detected: WordPress 6.6" in str(findings[0]["evidence"])
        assert "meta generator" in str(findings[0]["evidence"])

def test_wp_path_html(headers_module, mock_session):
    html = '<html><script src="/wp-content/themes/style.css"></script></html>'
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, html)):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        assert len(findings) == 1
        assert "Detected: WordPress" in str(findings[0]["evidence"])
        assert "HTML references /wp-content/" in str(findings[0]["evidence"])
        assert findings[0]["confidence"] == "Medium"

def test_nextjs_data_html(headers_module, mock_session):
    html = '<html><script id="__NEXT_DATA__" type="application/json">{}</script></html>'
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, html)):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        assert len(findings) == 1
        assert "Detected: Next.js" in str(findings[0]["evidence"])
        assert "High" == findings[0]["confidence"]

def test_nextjs_static_html(headers_module, mock_session):
    html = '<html><script src="/_next/static/chunks/main.js"></script></html>'
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, html)):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        assert len(findings) == 1
        assert "Detected: Next.js" in str(findings[0]["evidence"])
        assert "Medium" == findings[0]["confidence"]

def test_nuxt_html(headers_module, mock_session):
    html = '<html><script>window.__NUXT__={}</script></html>'
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, html)):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        assert len(findings) == 1
        assert "Detected: Nuxt" in str(findings[0]["evidence"])

def test_angular_html(headers_module, mock_session):
    html = '<html ng-version="18.2.0"></html>'
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, html)):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        assert len(findings) == 1
        assert "Detected: Angular 18.2.0" in str(findings[0]["evidence"])

def test_dedup_wordpress(headers_module, mock_session):
    html = '<html><head><meta name="generator" content="WordPress 6.6"></head><script src="/wp-content/themes/style.css"></script></html>'
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, html)):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        assert len(findings) == 1
        assert "Detected: WordPress 6.6" in str(findings[0]["evidence"])
        assert "High" == findings[0]["confidence"]

def test_dedup_nextjs(headers_module, mock_session):
    html = '<html><script id="__NEXT_DATA__" type="application/json">{}</script><script src="/_next/static/main.js"></script></html>'
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, html)):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        assert len(findings) == 1
        assert "Detected: Next.js" in str(findings[0]["evidence"])
        assert "High" == findings[0]["confidence"]

def test_missing_headers_ignored(headers_module, mock_session):
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, "", {})):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        assert len(findings) == 0
