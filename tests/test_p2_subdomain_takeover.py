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

def test_takeover_github_pages(module, mock_session):
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(404, "<html><body>There isn't a GitHub Pages site here.</body></html>")):
        findings = module.run("https://sub.example.com", "sub.example.com", mock_session)
        takeovers = [f for f in findings if f["name"] == "Potential Subdomain Takeover Signal"]
        assert len(takeovers) == 1
        assert "Provider: GitHub Pages" in str(takeovers[0]["evidence"])
        assert takeovers[0]["severity"] == "Medium"
        assert takeovers[0]["confidence"] == "Medium"

def test_takeover_heroku(module, mock_session):
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(404, "<iframe src='//www.herokucdn.com/error-pages/no-such-app.html'></iframe>")):
        findings = module.run("https://sub.example.com", "sub.example.com", mock_session)
        takeovers = [f for f in findings if f["name"] == "Potential Subdomain Takeover Signal"]
        assert len(takeovers) == 1
        assert "Provider: Heroku" in str(takeovers[0]["evidence"])

def test_takeover_s3(module, mock_session):
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(404, "<?xml version='1.0'?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>")):
        findings = module.run("https://sub.example.com", "sub.example.com", mock_session)
        takeovers = [f for f in findings if f["name"] == "Potential Subdomain Takeover Signal"]
        assert len(takeovers) == 1
        assert "Provider: AWS S3" in str(takeovers[0]["evidence"])

def test_takeover_fastly_case_insensitive(module, mock_session):
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(500, "Fastly Error: Unknown Domain: foo")):
        findings = module.run("https://sub.example.com", "sub.example.com", mock_session)
        takeovers = [f for f in findings if f["name"] == "Potential Subdomain Takeover Signal"]
        assert len(takeovers) == 1
        assert "Provider: Fastly" in str(takeovers[0]["evidence"])

def test_takeover_generic_404_ignored(module, mock_session):
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(404, "<html>404 Not Found - The specified page could not be found.</html>")):
        findings = module.run("https://sub.example.com", "sub.example.com", mock_session)
        takeovers = [f for f in findings if f["name"] == "Potential Subdomain Takeover Signal"]
        assert len(takeovers) == 0

def test_takeover_normal_page_ignored(module, mock_session):
    # even if it mentions AWS S3, if it's a 200 OK we shouldn't flag it as takeover to reduce FPs
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(200, "Welcome! We host our assets on AWS S3, but you might get a <Code>NoSuchBucket</Code> if you typoe the URL.")):
        findings = module.run("https://sub.example.com", "sub.example.com", mock_session)
        takeovers = [f for f in findings if f["name"] == "Potential Subdomain Takeover Signal"]
        assert len(takeovers) == 0

def test_existing_findings_intact(module, mock_session):
    with patch("api.scanner.modules.discovery.safe_request", return_value=create_mock_response(404, "There isn't a GitHub Pages site here. Also internal ip 10.0.0.1", headers={"Server": "nginx/1.2.3"})):
        findings = module.run("https://sub.example.com", "sub.example.com", mock_session)
        names = [f["name"] for f in findings]
        assert "Potential Subdomain Takeover Signal" in names
        assert "Verbose Server Banner" in names
        assert "Private IP Disclosure" in names
