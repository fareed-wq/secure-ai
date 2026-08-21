import pytest
import time
from fastapi.testclient import TestClient
from api.index import app
from api.auth.entitlements import get_monday_utc_boundaries, Entitlements
from unittest.mock import patch, MagicMock
from api.scanner.core import check_rate_limit, acquire_scan_lease, acquire_guest_lease, release_scan_lease, release_guest_lease
from api.auth.entitlements import consume_guest_quota, check_guest_quota

client = TestClient(app)

@pytest.fixture
def mock_entitlements():
    with patch("api.index.Entitlements") as MockEntitlements:
        mock_instance = MockEntitlements.return_value
        mock_instance.plan = "guest"
        mock_instance.can_advanced_scan = False
        mock_instance.is_unlimited = False
        yield mock_instance

@pytest.fixture
def mock_rate_limit():
    with patch("api.index.check_rate_limit", return_value=True) as m:
        yield m

@pytest.fixture
def mock_global_lease():
    with patch("api.index.acquire_scan_lease", return_value="fake-lease-id") as m:
        yield m

@pytest.fixture
def mock_guest_lease():
    with patch("api.index.acquire_guest_lease", return_value=True) as m:
        yield m

@pytest.fixture
def mock_validation():
    with patch("api.scanner.orchestrator.validate_scan_target", return_value=None) as m:
        yield m

@pytest.fixture
def mock_consume_quota():
    with patch("api.index.consume_guest_quota", return_value=True) as m:
        yield m

@pytest.fixture
def mock_check_quota():
    with patch("api.index.check_guest_quota", return_value={"quota_remaining": 3}) as m:
        yield m

@pytest.fixture
def mock_scan_url():
    with patch("api.index.scan_url", return_value={"status": "completed"}) as m:
        yield m

def test_guest_quota_success(mock_entitlements, mock_rate_limit, mock_global_lease, mock_guest_lease, mock_validation, mock_consume_quota, mock_check_quota, mock_scan_url):
    response = client.post("/api/scan", json={"url": "https://example.com", "scan_mode": "passive", "report_mode": "simple"})
    assert response.status_code == 200

def test_advanced_guest_blocked(mock_entitlements, mock_rate_limit, mock_global_lease, mock_guest_lease, mock_validation, mock_consume_quota, mock_check_quota, mock_scan_url):
    response = client.post("/api/scan", json={"url": "https://example.com", "scan_mode": "advanced", "report_mode": "simple"})
    assert response.status_code == 403
    assert "Advanced scanning is not available" in response.json()["error"]
    mock_consume_quota.assert_not_called()

def test_validation_failure_no_quota_consumed(mock_entitlements, mock_rate_limit, mock_global_lease, mock_guest_lease, mock_consume_quota, mock_check_quota, mock_scan_url):
    with patch("api.scanner.orchestrator.validate_scan_target", return_value={"status": "failed", "error": "Invalid host"}):
        response = client.post("/api/scan", json={"url": "https://internal.local", "scan_mode": "passive", "report_mode": "simple"})
        assert response.status_code == 200
        assert response.json()["error"] == "Invalid host"
        mock_consume_quota.assert_not_called()
        mock_scan_url.assert_not_called()

def test_fourth_scan_blocked(mock_entitlements, mock_rate_limit, mock_global_lease, mock_guest_lease, mock_validation, mock_consume_quota, mock_scan_url):
    with patch("api.index.check_guest_quota", return_value={"quota_remaining": 0}):
        response = client.post("/api/scan", json={"url": "https://example.com", "scan_mode": "passive", "report_mode": "simple"})
        assert response.status_code == 429
        assert "3 free Basic scans" in response.json()["error"]
        mock_consume_quota.assert_not_called()
        mock_scan_url.assert_not_called()

def test_concurrency_rejection_no_quota_consumed(mock_entitlements, mock_rate_limit, mock_global_lease, mock_validation, mock_consume_quota, mock_check_quota, mock_scan_url):
    with patch("api.index.acquire_guest_lease", return_value=False):
        response = client.post("/api/scan", json={"url": "https://example.com", "scan_mode": "passive", "report_mode": "simple"})
        assert response.status_code == 429
        assert "scan in progress" in response.json()["error"]
        mock_consume_quota.assert_not_called()
        mock_scan_url.assert_not_called()

def test_authenticated_user_bypasses_guest_quota(mock_rate_limit, mock_global_lease, mock_validation, mock_consume_quota, mock_check_quota, mock_scan_url):
    with patch("api.index.Entitlements") as MockEntitlements:
        mock_instance = MockEntitlements.return_value
        mock_instance.plan = "free"  # Authenticated user
        mock_instance.can_advanced_scan = True
        
        response = client.post("/api/scan", json={"url": "https://example.com", "scan_mode": "advanced", "report_mode": "simple"})
        assert response.status_code == 200
        mock_check_quota.assert_not_called()
        mock_consume_quota.assert_not_called()

def test_monday_utc_reset_calculation():
    week_start, next_week = get_monday_utc_boundaries()
    assert next_week - week_start == 604800
    assert week_start % 86400 == 0
