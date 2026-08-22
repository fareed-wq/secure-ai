import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import os

from api.index import app
from api.admin import require_admin
from api.scanner.compare import compare_reports

client = TestClient(app)

def test_compare_reports_logic():
    old_scan = {
        "target_url": "https://example.com",
        "score": 80,
        "report_data": {
            "scan_mode": "passive",
            "findings": [
                {"name": "Missing Headers", "severity": "Medium", "evidence": "old"},
                {"name": "No CSP", "severity": "Low", "evidence": "old"}
            ]
        }
    }
    new_scan = {
        "target_url": "https://example.com",
        "score": 90,
        "report_data": {
            "scan_mode": "passive",
            "findings": [
                {"name": "Missing Headers", "severity": "Medium", "evidence": "new"},
                {"name": "New Issue", "severity": "High", "evidence": "new"}
            ]
        }
    }
    
    result = compare_reports(old_scan, new_scan)
    assert result["old_score"] == 80
    assert result["new_score"] == 90
    assert result["score_change"] == 10
    assert result["improved"] is True
    assert result["regressed"] is False
    
    assert len(result["added"]) == 1
    assert result["added"][0]["name"] == "New Issue"
    
    assert len(result["removed"]) == 1
    assert result["removed"][0]["name"] == "No CSP"
    
    assert len(result["unchanged"]) == 1
    assert result["unchanged"][0]["name"] == "Missing Headers"


def test_compare_reports_different_targets():
    old_scan = {"target_url": "https://example.com"}
    new_scan = {"target_url": "https://other.com"}
    with pytest.raises(ValueError, match="Cannot compare scans with different target URLs."):
        compare_reports(old_scan, new_scan)

def test_compare_reports_different_modes():
    old_scan = {"target_url": "https://example.com", "report_data": {"scan_mode": "passive"}}
    new_scan = {"target_url": "https://example.com", "report_data": {"scan_mode": "active"}}
    with pytest.raises(ValueError, match="Cannot compare scans with different scan modes."):
        compare_reports(old_scan, new_scan)

@patch.dict(os.environ, {"SUPABASE_URL": "http://mock", "SUPABASE_SECRET_KEY": "mock"})
@patch("api.admin.requests.get")
def test_admin_compare_endpoint(mock_requests_get):
    app.dependency_overrides[require_admin] = lambda: {"sub": "admin123", "role": "admin"}
    
    # Mock supabase responses
    def mock_get(url, *args, **kwargs):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        if "id=eq.1" in url:
            mock_resp.json.return_value = [{
                "target_url": "https://example.com",
                "score": 80,
                "report_data": {"scan_mode": "passive", "findings": []}
            }]
        elif "id=eq.2" in url:
            mock_resp.json.return_value = [{
                "target_url": "https://example.com",
                "score": 90,
                "report_data": {"scan_mode": "passive", "findings": []}
            }]
        return mock_resp

    mock_requests_get.side_effect = mock_get
    
    try:
        response = client.get("/api/admin/scans/compare?scan_id_1=1&scan_id_2=2", headers={"Authorization": "Bearer token"})
        assert response.status_code == 200
        data = response.json()
        assert data["old_score"] == 80
        assert data["new_score"] == 90
        assert data["score_change"] == 10
        assert data["improved"] is True
    finally:
        app.dependency_overrides.clear()
