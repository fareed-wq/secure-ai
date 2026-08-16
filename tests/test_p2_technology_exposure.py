import pytest
from unittest.mock import MagicMock, patch
from api.scanner.modules.discovery import InformationDisclosureModule
import requests

@pytest.fixture
def module():
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

def test_x_powered_by_detected(module, mock_session):
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(200, "<html></html>", {"X-Powered-By": "Express"})):
        findings = module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if f["name"] == "Technology Information Disclosure"]
        assert len(tech) == 1
        assert "X-Powered-By: Express" in str(tech[0]["evidence"])
        assert tech[0]["severity"] == "Low"
        assert tech[0]["confidence"] == "High"

def test_x_aspnet_version_detected(module, mock_session):
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(200, "", {"X-AspNet-Version": "4.0.30319"})):
        findings = module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if f["name"] == "Technology Information Disclosure"]
        assert len(tech) == 1
        assert "X-AspNet-Version: 4.0.30319" in str(tech[0]["evidence"])

def test_x_aspnetmvc_version_detected(module, mock_session):
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(200, "", {"X-AspNetMvc-Version": "5.2"})):
        findings = module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if f["name"] == "Technology Information Disclosure"]
        assert len(tech) == 1
        assert "X-AspNetMvc-Version: 5.2" in str(tech[0]["evidence"])

def test_x_generator_detected(module, mock_session):
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(200, "", {"X-Generator": "Drupal 9 (https://www.drupal.org)"})):
        findings = module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if f["name"] == "Technology Information Disclosure"]
        assert len(tech) == 1
        assert "X-Generator: Drupal 9 (https://www.drupal.org)" in str(tech[0]["evidence"])

def test_multiple_headers_consolidated(module, mock_session):
    headers = {
        "X-Powered-By": "ASP.NET",
        "X-AspNet-Version": "4.0.30319"
    }
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(200, "", headers)):
        findings = module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if f["name"] == "Technology Information Disclosure"]
        assert len(tech) == 1
        evidence = str(tech[0]["evidence"])
        assert "X-Powered-By: ASP.NET" in evidence
        assert "X-AspNet-Version: 4.0.30319" in evidence

def test_header_name_case_variation(module, mock_session):
    headers = {"x-POwered-bY": "PHP/7.4.3"}
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(200, "", headers)):
        findings = module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if f["name"] == "Technology Information Disclosure"]
        assert len(tech) == 1
        assert "x-POwered-bY: PHP/7.4.3" in str(tech[0]["evidence"])

def test_missing_headers_ignored(module, mock_session):
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(200, "", {})):
        findings = module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if f["name"] == "Technology Information Disclosure"]
        assert len(tech) == 0

def test_empty_header_values_ignored(module, mock_session):
    headers = {"X-Powered-By": "   ", "X-Generator": ""}
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(200, "", headers)):
        findings = module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if f["name"] == "Technology Information Disclosure"]
        assert len(tech) == 0

def test_server_header_remains_unchanged(module, mock_session):
    headers = {"Server": "nginx/1.18.0", "X-Powered-By": "Express"}
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(200, "", headers)):
        findings = module.run("https://example.com", "example.com", mock_session)
        server_findings = [f for f in findings if f["name"] == "Verbose Server Banner"]
        tech_findings = [f for f in findings if f["name"] == "Technology Information Disclosure"]
        assert len(server_findings) == 1
        assert "nginx/1.18.0" in str(server_findings[0]["evidence"])
        assert len(tech_findings) == 1

def test_normal_headers_do_not_trigger(module, mock_session):
    headers = {"Content-Type": "text/html", "Cache-Control": "no-cache", "Age": "10"}
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(200, "", headers)):
        findings = module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if f["name"] == "Technology Information Disclosure"]
        assert len(tech) == 0

def test_evidence_sanitized(module, mock_session):
    long_value = "A" * 150
    headers = {"X-Powered-By": long_value}
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(200, "", headers)):
        findings = module.run("https://example.com", "example.com", mock_session)
        tech = [f for f in findings if f["name"] == "Technology Information Disclosure"]
        assert len(tech) == 1
        evidence = str(tech[0]["evidence"])
        assert "..." in evidence
        assert len(evidence) < 150

def test_existing_information_disclosure_intact(module, mock_session):
    headers = {"X-Powered-By": "PHP"}
    body = "There isn't a GitHub Pages site here. Private IP 192.168.1.1"
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(404, body, headers)):
        findings = module.run("https://example.com", "example.com", mock_session)
        names = [f["name"] for f in findings]
        assert "Technology Information Disclosure" in names
        assert "Potential Subdomain Takeover Signal" in names
        assert "Private IP Disclosure" in names
