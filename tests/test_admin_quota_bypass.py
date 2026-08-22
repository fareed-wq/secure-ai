import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from api.index import app

client = TestClient(app)

@patch("api.index.check_free_quota")
@patch("api.auth.entitlements.verify_jwt")
@patch("api.auth.entitlements.get_user_role")
@patch("api.auth.entitlements.get_user_plan_and_status")
def test_admin_quota_is_unlimited(mock_get_plan, mock_get_role, mock_verify, mock_check_free):
    mock_verify.return_value = {"sub": "admin123"}
    mock_get_role.return_value = "admin"
    mock_get_plan.return_value = ("free", "active")
    
    response = client.get("/api/quota", headers={"Authorization": "Bearer admin_token"})
    
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "admin"
    assert data["is_unlimited"] is True
    assert data["quota_limit"] is None
    assert data["quota_used"] is None
    assert data["quota_remaining"] is None
    
    mock_check_free.assert_not_called()

@patch("api.index.scan_url", return_value={"status": "success", "score": 100})
@patch("api.index.acquire_scan_lease", return_value="mock_lease")
@patch("api.index.release_scan_lease")
@patch("api.index.consume_free_quota")
@patch("api.index.check_rate_limit", return_value=True)
@patch("api.auth.entitlements.verify_jwt")
@patch("api.auth.entitlements.get_user_role")
@patch("api.auth.entitlements.get_user_plan_and_status")
def test_admin_scan_bypasses_free_quota(
    mock_get_plan, mock_get_role, mock_verify, mock_rate, mock_consume_free, mock_release, mock_acquire, mock_scan
):
    mock_verify.return_value = {"sub": "admin123"}
    mock_get_role.return_value = "admin"
    mock_get_plan.return_value = ("free", "active")
    
    response = client.post("/api/scan", json={"url": "example.com", "scan_mode": "active"}, headers={"Authorization": "Bearer admin_token"})
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    
    mock_acquire.assert_called_once_with(is_admin=True)
    mock_consume_free.assert_not_called()
    mock_scan.assert_called_once_with("https://example.com", False, "active")

@patch("api.index.scan_url", return_value={"status": "success", "score": 100})
@patch("api.index.acquire_scan_lease", return_value="mock_lease")
@patch("api.index.release_scan_lease")
@patch("api.index.consume_free_quota", return_value=False)
@patch("api.index.check_free_quota", return_value={"quota_remaining": 5})
@patch("api.index.check_rate_limit", return_value=True)
@patch("api.auth.entitlements.verify_jwt")
@patch("api.auth.entitlements.get_user_role")
@patch("api.auth.entitlements.get_user_plan_and_status")
def test_free_user_scan_consumes_free_quota(
    mock_get_plan, mock_get_role, mock_verify, mock_rate, mock_check_free, mock_consume_free, mock_release, mock_acquire, mock_scan
):
    mock_verify.return_value = {"sub": "user123"}
    mock_get_role.return_value = "user"
    mock_get_plan.return_value = ("free", "active")
    
    response = client.post("/api/scan", json={"url": "example.com", "scan_mode": "passive"}, headers={"Authorization": "Bearer user_token"})
    
    # consume_free_quota returns False meaning quota is reached
    assert response.status_code == 429
    data = response.json()
    assert "5 free scans" in data["error"]
    
    mock_consume_free.assert_called_once_with("user123")
    mock_scan.assert_not_called()
