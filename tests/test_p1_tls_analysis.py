import pytest
import datetime
from unittest.mock import MagicMock
from api.scanner.modules.tls import EnhancedTLSModule

def mock_getpeercert(issuer=None, subject_alt_name=None, not_before=None, not_after=None):
    cert = {
        "subject": ((("commonName", "example.com"),),)
    }
    if issuer:
        cert["issuer"] = issuer
    if subject_alt_name:
        cert["subjectAltName"] = subject_alt_name
    if not_before:
        cert["notBefore"] = not_before
    if not_after:
        cert["notAfter"] = not_after
    return cert

@pytest.fixture
def module():
    return EnhancedTLSModule()

@pytest.fixture
def session():
    return MagicMock()

def execute_with_mock(monkeypatch, module, session, version="TLSv1.2", getpeercert_mock=None):
    if getpeercert_mock is None:
        getpeercert_mock = mock_getpeercert()

    mock_sock = MagicMock()
    mock_ssock = MagicMock()
    mock_ssock.version.return_value = version
    mock_ssock.getpeercert.return_value = getpeercert_mock

    # Context manager setup
    mock_ssock.__enter__.return_value = mock_ssock
    mock_sock.__enter__.return_value = mock_sock

    mock_safe_create_connection = MagicMock(return_value=mock_sock)
    monkeypatch.setattr("api.scanner.modules.tls.safe_create_connection", mock_safe_create_connection)

    mock_context = MagicMock()
    mock_context.wrap_socket.return_value = mock_ssock
    mock_ssl_create_default_context = MagicMock(return_value=mock_context)
    monkeypatch.setattr("ssl.create_default_context", mock_ssl_create_default_context)

    return module.run("https://example.com", "example.com", session)

def test_issuer_extraction(monkeypatch, module, session):
    issuer = ((('countryName', 'US'),), (('organizationName', 'Test CA'),), (('commonName', 'Test CA Root'),))
    cert = mock_getpeercert(issuer=issuer)

    findings = execute_with_mock(monkeypatch, module, session, getpeercert_mock=cert)

    issuer_finding = next((f for f in findings if f["name"] == "Certificate Issuer Identified"), None)
    assert issuer_finding is not None
    assert issuer_finding["severity"] == "Informational"
    assert "Common Name: Test CA Root" in issuer_finding["evidence"]["raw"]
    assert "Organization: Test CA" in issuer_finding["evidence"]["raw"]

def test_san_extraction(monkeypatch, module, session):
    sans = (('DNS', 'example.com'), ('DNS', 'www.example.com'))
    cert = mock_getpeercert(subject_alt_name=sans)

    findings = execute_with_mock(monkeypatch, module, session, getpeercert_mock=cert)

    san_finding = next((f for f in findings if f["name"] == "Certificate Subject Alternative Names (SANs)"), None)
    assert san_finding is not None
    assert san_finding["severity"] == "Informational"
    assert "example.com" in san_finding["evidence"]["raw"]
    assert "www.example.com" in san_finding["evidence"]["raw"]

def test_tls_13_detection(monkeypatch, module, session):
    findings = execute_with_mock(monkeypatch, module, session, version="TLSv1.3")

    tls13 = next((f for f in findings if f["name"] == "Modern TLS 1.3 Supported"), None)
    assert tls13 is not None
    assert tls13["severity"] == "Informational"

def test_tls_12_behavior(monkeypatch, module, session):
    findings = execute_with_mock(monkeypatch, module, session, version="TLSv1.2")

    tls13 = next((f for f in findings if f["name"] == "Modern TLS 1.3 Supported"), None)
    assert tls13 is None

def test_applicable_exceeds_398_days(monkeypatch, module, session):
    not_before = "Jan 01 12:00:00 2021 GMT"
    not_after = "Jan 01 12:00:00 2023 GMT"
    cert = mock_getpeercert(not_before=not_before, not_after=not_after)

    findings = execute_with_mock(monkeypatch, module, session, getpeercert_mock=cert)

    lifespan = next((f for f in findings if "Validity Period Identified" in f["name"]), None)
    assert lifespan is not None
    assert lifespan["severity"] == "Informational"

def test_non_applicable_exceeds_398_days(monkeypatch, module, session):
    not_before = "Jan 01 12:00:00 2019 GMT"
    not_after = "Jan 01 12:00:00 2022 GMT"
    cert = mock_getpeercert(not_before=not_before, not_after=not_after)

    findings = execute_with_mock(monkeypatch, module, session, getpeercert_mock=cert)

    lifespan = next((f for f in findings if "Validity Period Identified" in f["name"]), None)
    assert lifespan is not None
    assert lifespan["severity"] == "Informational"

def test_valid_lifespan(monkeypatch, module, session):
    # Issued after Sept 1, 2020 and lifespan < 398 days
    not_before = "Jan 01 12:00:00 2022 GMT"
    not_after = "Jan 01 12:00:00 2023 GMT" # 1 year
    cert = mock_getpeercert(not_before=not_before, not_after=not_after)

    findings = execute_with_mock(monkeypatch, module, session, getpeercert_mock=cert)

    lifespan = next((f for f in findings if "Validity Period Identified" in f["name"]), None)
    assert lifespan is not None

def test_missing_dates(monkeypatch, module, session):
    cert = mock_getpeercert(not_before=None, not_after=None)
    findings = execute_with_mock(monkeypatch, module, session, getpeercert_mock=cert)

    lifespan = next((f for f in findings if "Validity Period Identified" in f["name"]), None)
    assert lifespan is None

def test_malformed_dates(monkeypatch, module, session):
    cert = mock_getpeercert(not_before="Not a date", not_after="Still not a date")
    findings = execute_with_mock(monkeypatch, module, session, getpeercert_mock=cert)

    lifespan = next((f for f in findings if "Validity Period Identified" in f["name"]), None)
    assert lifespan is None

def test_zero_network_requests(monkeypatch, module, session):
    # Ensure no additional requests are made beyond the existing safe_create_connection
    # execute_with_mock creates the mock and returns the findings, but we can't easily
    # access its internal mock. Let's just create a custom mock here and duplicate the setup briefly.

    mock_sock = MagicMock()
    mock_ssock = MagicMock()
    mock_ssock.version.return_value = "TLSv1.2"
    mock_ssock.getpeercert.return_value = mock_getpeercert()

    mock_ssock.__enter__.return_value = mock_ssock
    mock_sock.__enter__.return_value = mock_sock

    mock_safe_create_connection = MagicMock(return_value=mock_sock)
    monkeypatch.setattr("api.scanner.modules.tls.safe_create_connection", mock_safe_create_connection)

    mock_context = MagicMock()
    mock_context.wrap_socket.return_value = mock_ssock
    monkeypatch.setattr("ssl.create_default_context", MagicMock(return_value=mock_context))

    module.run("https://example.com", "example.com", session)

    # One for primary connection, one for legacy downgrade check
    assert mock_safe_create_connection.call_count == 2
