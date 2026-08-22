import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from api.index import app
from api.admin import require_admin

client = TestClient(app)

def override_require_admin():
    return {"sub": "admin_user"}

@patch("api.admin.requests.get")
@patch("api.admin.os.environ.get")
def test_admin_scans_mapping_basic(mock_env, mock_get):
    app.dependency_overrides[require_admin] = override_require_admin
    
    try:
        def env_side_effect(key, default=None):
            if key == "SUPABASE_URL": return "http://fake.supabase"
            if key == "SUPABASE_SECRET_KEY": return "fake_key"
            return default
        mock_env.side_effect = env_side_effect
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        
        mock_resp.json.return_value = [
            {"id": "scan_basic", "user_id": "u1", "target_url": "example.com", "score": 100, "report_data": {"scan_mode": "basic"}, "created_at": "2023-01-01T00:00:00Z"},
            {"id": "scan_passive", "user_id": "u1", "target_url": "example.com", "score": 100, "report_data": {"scan_mode": "passive"}, "created_at": "2023-01-01T00:00:00Z"},
            {"id": "scan_active", "user_id": "u1", "target_url": "example.com", "score": 100, "report_data": {"scan_mode": "active"}, "created_at": "2023-01-01T00:00:00Z"},
            {"id": "scan_unknown", "user_id": "u1", "target_url": "example.com", "score": 100, "report_data": {}, "created_at": "2023-01-01T00:00:00Z"}
        ]
        mock_get.return_value = mock_resp
        
        response = client.get("/api/admin/scans")
        assert response.status_code == 200
        data = response.json()
        
        assert data[0]["scan_mode"] == "Basic"
        assert data[1]["scan_mode"] == "Basic"
        assert data[2]["scan_mode"] == "Advanced"
        assert data[3]["scan_mode"] == "Unknown"
    finally:
        app.dependency_overrides = {}
