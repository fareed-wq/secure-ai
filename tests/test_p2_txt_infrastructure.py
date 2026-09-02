import pytest
from unittest.mock import MagicMock, patch
from api.scanner.modules.dns import DNSEmailSecurityModule
import requests

@pytest.fixture
def module():
    return DNSEmailSecurityModule()

@pytest.fixture
def mock_session():
    return MagicMock(spec=requests.Session)

def create_dns_response(status_code, records):
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = {"Status": 0, "Answer": [{"data": r} for r in records]}
    return mock

def test_private_rfc1918_ip(module, mock_session):
    with patch("api.scanner.modules.dns.safe_request", return_value=create_dns_response(200, ["v=spf1 include:_spf.example.com ~all", "internal-ip=192.168.1.100"])):
        findings = module.run("https://example.com", "example.com", mock_session)
        infra = [f for f in findings if f["name"] == "Potential Infrastructure Information Disclosure"]
        assert len(infra) == 1
        assert "Private IP address (192.168.1.100)" in str(infra[0]["evidence"])
        assert infra[0]["severity"] == "Medium"
        assert infra[0]["confidence"] == "High"

def test_loopback_ip(module, mock_session):
    with patch("api.scanner.modules.dns.safe_request", return_value=create_dns_response(200, ["v=spf1 ~all", "localhost=127.0.0.1"])):
        findings = module.run("https://example.com", "example.com", mock_session)
        infra = [f for f in findings if f["name"] == "Potential Infrastructure Information Disclosure"]
        assert len(infra) == 1
        assert "Private IP address (127.0.0.1)" in str(infra[0]["evidence"])

def test_link_local_ip(module, mock_session):
    with patch("api.scanner.modules.dns.safe_request", return_value=create_dns_response(200, ["v=spf1 ~all", "aws-magic=169.254.169.254"])):
        findings = module.run("https://example.com", "example.com", mock_session)
        infra = [f for f in findings if f["name"] == "Potential Infrastructure Information Disclosure"]
        assert len(infra) == 1
        assert "Private IP address (169.254.169.254)" in str(infra[0]["evidence"])

def test_public_ip_no_finding(module, mock_session):
    with patch("api.scanner.modules.dns.safe_request", return_value=create_dns_response(200, ["v=spf1 ~all", "public-ip=8.8.8.8"])):
        findings = module.run("https://example.com", "example.com", mock_session)
        infra = [f for f in findings if f["name"] == "Potential Infrastructure Information Disclosure"]
        assert len(infra) == 0

def test_internal_hostname(module, mock_session):
    with patch("api.scanner.modules.dns.safe_request", return_value=create_dns_response(200, ["v=spf1 ~all", "db01.internal.example"])):
        findings = module.run("https://example.com", "example.com", mock_session)
        infra = [f for f in findings if f["name"] == "Potential Infrastructure Information Disclosure"]
        assert len(infra) == 1
        assert "Internal hostname (db01.internal.example)" in str(infra[0]["evidence"])
        assert infra[0]["confidence"] == "Medium"

def test_generic_dev_text_no_finding(module, mock_session):
    with patch("api.scanner.modules.dns.safe_request", return_value=create_dns_response(200, ["v=spf1 ~all", "we love dev and test environments"])):
        findings = module.run("https://example.com", "example.com", mock_session)
        infra = [f for f in findings if f["name"] == "Potential Infrastructure Information Disclosure"]
        assert len(infra) == 0

def test_verification_tokens_ignored(module, mock_session):
    records = [
        "v=spf1 ~all",
        "google-site-verification=abc123",
        "facebook-domain-verification=abc123",
        "atlassian-domain-verification=abc123",
        "stripe-verification=123",
        "apple-domain-verification=123"
    ]
    with patch("api.scanner.modules.dns.safe_request", return_value=create_dns_response(200, records)):
        findings = module.run("https://example.com", "example.com", mock_session)
        infra = [f for f in findings if f["name"] == "Potential Infrastructure Information Disclosure"]
        assert len(infra) == 0

def test_normal_spf_and_dmarc_unchanged(module, mock_session):
    records = ["v=spf1 include:_spf.google.com ~all"]
    # Mock safe_request side effects for SPF and DMARC respectively
    def mock_safe_request(method, url, **kwargs):
        if "_dmarc" in url:
            return create_dns_response(200, ["v=DMARC1; p=none"])
        else:
            return create_dns_response(200, records)
    
    with patch("api.scanner.modules.dns.safe_request", side_effect=mock_safe_request):
        findings = module.run("https://example.com", "example.com", mock_session)
        infra = [f for f in findings if f["name"] == "Potential Infrastructure Information Disclosure"]
        assert len(infra) == 0
        names = [f["name"] for f in findings]
        assert "SPF Policy Analysis" in names or "SPF Record Configured" in names
        assert any("DMARC" in name for name in names)

def test_multiple_txt_records_deduplicated(module, mock_session):
    records = [
        "v=spf1 ~all",
        "ip=10.0.0.1",
        "another-ip=10.0.0.1"
    ]
    with patch("api.scanner.modules.dns.safe_request", return_value=create_dns_response(200, records)):
        findings = module.run("https://example.com", "example.com", mock_session)
        infra = [f for f in findings if f["name"] == "Potential Infrastructure Information Disclosure"]
        assert len(infra) == 1
        evidence = str(infra[0]["evidence"])
        assert evidence.count("Private IP address (10.0.0.1)") == 1

def test_evidence_sanitized(module, mock_session):
    long_txt = "ip=10.0.0.1 " + "A" * 150
    with patch("api.scanner.modules.dns.safe_request", return_value=create_dns_response(200, ["v=spf1 ~all", long_txt])):
        findings = module.run("https://example.com", "example.com", mock_session)
        infra = [f for f in findings if f["name"] == "Potential Infrastructure Information Disclosure"]
        assert len(infra) == 1
        evidence = str(infra[0]["evidence"])
        assert "..." in evidence
        raw_evidence = infra[0]["evidence"]["raw"] if isinstance(infra[0]["evidence"], dict) else evidence
        assert len(raw_evidence) < 150

def test_empty_malformed_txt(module, mock_session):
    records = ["", " ", "v=spf1 ~all", None] # mock might return None if buggy, but let's test empty str
    with patch("api.scanner.modules.dns.safe_request", return_value=create_dns_response(200, ["v=spf1 ~all", "", " "])):
        findings = module.run("https://example.com", "example.com", mock_session)
        infra = [f for f in findings if f["name"] == "Potential Infrastructure Information Disclosure"]
        assert len(infra) == 0

def test_verification_plus_private_ip(module, mock_session):
    with patch("api.scanner.modules.dns.safe_request", return_value=create_dns_response(200, ["v=spf1 ~all", "verification failed at 10.10.10.5"])):
        findings = module.run("https://example.com", "example.com", mock_session)
        infra = [f for f in findings if f["name"] == "Potential Infrastructure Information Disclosure"]
        assert len(infra) == 1
        assert "Private IP address (10.10.10.5)" in str(infra[0]["evidence"])

def test_dkim_plus_private_ip(module, mock_session):
    with patch("api.scanner.modules.dns.safe_request", return_value=create_dns_response(200, ["v=spf1 ~all", "dkim proxy at 192.168.1.50"])):
        findings = module.run("https://example.com", "example.com", mock_session)
        infra = [f for f in findings if f["name"] == "Potential Infrastructure Information Disclosure"]
        assert len(infra) == 1
        assert "Private IP address (192.168.1.50)" in str(infra[0]["evidence"])

def test_spf_plus_private_ip(module, mock_session):
    with patch("api.scanner.modules.dns.safe_request", return_value=create_dns_response(200, ["v=spf1 ~all", "internal spf server: 172.16.0.10"])):
        findings = module.run("https://example.com", "example.com", mock_session)
        infra = [f for f in findings if f["name"] == "Potential Infrastructure Information Disclosure"]
        assert len(infra) == 1
        assert "Private IP address (172.16.0.10)" in str(infra[0]["evidence"])

def test_dmarc_plus_private_ip(module, mock_session):
    with patch("api.scanner.modules.dns.safe_request", return_value=create_dns_response(200, ["v=spf1 ~all", "dmarc reports sent to 10.0.0.5"])):
        findings = module.run("https://example.com", "example.com", mock_session)
        infra = [f for f in findings if f["name"] == "Potential Infrastructure Information Disclosure"]
        assert len(infra) == 1
        assert "Private IP address (10.0.0.5)" in str(infra[0]["evidence"])
