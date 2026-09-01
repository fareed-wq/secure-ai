import pytest
from unittest.mock import MagicMock, patch
from api.scanner.modules.headers import TechFingerprintModule
from api.scanner.modules.discovery import InformationDisclosureModule
import requests

@pytest.fixture
def headers_module():
    return TechFingerprintModule()

@pytest.fixture
def discovery_module():
    return InformationDisclosureModule()

@pytest.fixture
def mock_session():
    return MagicMock(spec=requests.Session)

def create_mock_response(status_code, text, headers=None):
    mock = MagicMock()
    mock.status_code = status_code
    mock.text = text
    mock.headers = headers or {}
    return mock

def test_x_powered_by_detected_by_headers_module(headers_module, mock_session):
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, "<html></html>", {"X-Powered-By": "Express"})):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if "Information Disclosed" in f["name"] or "Header Exposed" in f["name"]]
        assert len(tech) == 1
        assert "X-Powered-By: Express" in str(tech[0]["evidence"])
        assert tech[0]["severity"] == "Informational"  # Without versions, it's Informational
        assert tech[0]["name"] == "Server Software Information Disclosed" or tech[0]["name"] == "Server Header Exposed"

def test_x_aspnet_version_detected(headers_module, mock_session):
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, "", {"X-AspNet-Version": "4.0.30319"})):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if "Information Disclosed" in f["name"] or "Header Exposed" in f["name"]]
        assert len(tech) == 1
        assert "X-AspNet-Version: 4.0.30319" in str(tech[0]["evidence"])
        assert tech[0]["severity"] == "Low"  # Has numbers/versions

def test_discovery_module_does_not_duplicate(discovery_module, mock_session):
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(200, "", {"X-Powered-By": "Express"})):
        findings = discovery_module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if "Information Disclosure" in f["name"] or "Information Disclosed" in f["name"]]
        assert len(tech) == 0

def test_multiple_headers_consolidated(headers_module, mock_session):
    headers = {
        "X-Powered-By": "ASP.NET",
        "X-AspNet-Version": "4.0.30319"
    }
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, "", headers)):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if "Information Disclosed" in f["name"] or "Header Exposed" in f["name"]]
        assert len(tech) == 1
        evidence = str(tech[0]["evidence"])
        assert "X-Powered-By: ASP.NET" in evidence
        assert "X-AspNet-Version: 4.0.30319" in evidence

def test_missing_headers_ignored(headers_module, mock_session):
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, "", {})):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if "Information Disclosed" in f["name"] or "Header Exposed" in f["name"]]
        assert len(tech) == 0

def test_server_header_versioned(headers_module, mock_session):
    headers = {"Server": "nginx/1.18.0", "X-Powered-By": "Express"}
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, "", headers)):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if "Version Information Disclosed" in f["name"]]
        assert len(tech) == 1
        assert "nginx/1.18.0" in str(tech[0]["evidence"])

def test_normal_headers_do_not_trigger(headers_module, mock_session):
    headers = {"Content-Type": "text/html", "Cache-Control": "no-cache", "Age": "10"}
    with patch("api.scanner.modules.headers.safe_request", return_value=create_mock_response(200, "", headers)):
        findings = headers_module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if "Information Disclosed" in f["name"] or "Header Exposed" in f["name"]]
        assert len(tech) == 0
