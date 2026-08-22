from api.auth.entitlements import require_admin
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from api.index import app

client = TestClient(app)

@patch("api.admin.os.environ.get")
@patch("api.admin.requests.get")
@patch("api.auth.entitlements.verify_jwt")
def test_overview_metrics(mock_verify_jwt, mock_get, mock_env):
    mock_verify_jwt.return_value = {"sub": "admin123"}
    def env_side_effect(key, default=""):
        if key == "SUPABASE_URL": return "https://mock.supabase.co"
        if key == "SUPABASE_SECRET_KEY": return "mock_key"
        return default
    mock_env.side_effect = env_side_effect

    def get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        params = kwargs.get("params", {})
        
        if "/auth/v1/admin/users" in url:
            resp.json.return_value = {"users": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]}
        elif params.get("plan") == "eq.professional":
            resp.headers = {"Content-Range": "0-1/2"}
            resp.json.return_value = []
        elif params.get("status") == "eq.suspended":
            resp.headers = {"Content-Range": "0-0/1"}
            resp.json.return_value = []
        elif "created_at" in params and "gte" in params["created_at"]:
            resp.headers = {"Content-Range": "0-4/5"}
            resp.json.return_value = []
        elif "/rest/v1/scans" in url:
            resp.headers = {"Content-Range": "0-19/20"}
            resp.json.return_value = []
        else:
            resp.json.return_value = []
        return resp
    mock_get.side_effect = get_side_effect
    
    with patch("api.auth.entitlements.get_user_role", return_value="admin"):
        response = client.get("/api/admin/overview", headers={"Authorization": "Bearer admin_token"})
        
    assert response.status_code == 200
    data = response.json()
    assert data["total_users"] == 10
    assert data["professional_users"] == 2
    assert data["free_users"] == 8
    assert data["suspended_users"] == 1
    assert data["active_users"] == 9
    assert data["total_scans"] == 20
    


@patch("api.admin.verify_user_exists", return_value=None)
def test_quota_visibility(mock_verify):
    
    with patch("api.auth.entitlements.get_user_role", return_value="user"), \
         patch("api.admin.get_user_plan_and_status", return_value=("free", "active")), \
         patch("api.admin.check_free_quota", return_value={"quota_limit": 5, "quota_used": 2, "quota_remaining": 3, "reset_at": 1000}):
        
        from api.admin import require_admin
        app.dependency_overrides[require_admin] = lambda: {"sub": "admin123"}
        response = client.get("/api/admin/users/testuser/quota")
        app.dependency_overrides.clear()
            
        assert response.status_code == 200
        data = response.json()
        assert data["limit"] == 5
        assert data["used"] == 2
        assert data["remaining"] == 3

@patch("api.admin.verify_user_exists", return_value=None)
@patch("api.admin.audit_log")
def test_quota_reset_exact_key_admin_only(mock_audit, mock_verify):
    
    with patch("api.admin.reset_free_quota", return_value=True) as mock_reset, \
         patch("api.admin.check_free_quota", return_value={"quota_limit": 5, "quota_used": 3, "quota_remaining": 2, "reset_at": 1000}):
        
        from api.admin import require_admin
        app.dependency_overrides[require_admin] = lambda: {"sub": "admin123"}
        response = client.post("/api/admin/users/testuser/reset-quota", json={"reason": "test"})
        app.dependency_overrides.clear()
        
        assert response.status_code == 200
        mock_reset.assert_called_once_with("testuser")
        mock_audit.assert_called_once()
        args, kwargs = mock_audit.call_args
        assert kwargs["action"] == "reset_free_quota"
        assert kwargs["resource_id"] == "testuser"
        assert kwargs["before_state"]["quota_used"] == 3
        assert kwargs["after_state"]["quota_used"] == 0

def test_quota_reset_not_admin():
    with patch("api.auth.entitlements.verify_jwt", return_value={"sub": "user123"}), \
         patch("api.auth.entitlements.get_user_role", return_value="user"):
        response = client.post("/api/admin/users/testuser/reset-quota", headers={"Authorization": "Bearer token"})
        assert response.status_code == 403


@patch("api.auth.entitlements.requests.get")
@patch("api.auth.entitlements.os.environ.get")
def test_redis_quota_reset_exact_key(mock_env, mock_get):
    def env_side_effect(key, default=""):
        if key == "UPSTASH_REDIS_REST_URL": return "https://mock.redis.co"
        if key == "UPSTASH_REDIS_REST_TOKEN": return "mock_token"
        return default
    mock_env.side_effect = env_side_effect
    
    from api.auth.entitlements import reset_free_quota, get_monday_utc_boundaries
    import unittest.mock
    
    mock_resp = unittest.mock.MagicMock()
    mock_resp.status_code = 200
    mock_get.return_value = mock_resp
    
    week_start, _ = get_monday_utc_boundaries()
    
    result = reset_free_quota("testuser1")
    
    assert result == True
    
    # Assert exact key was deleted via REST
    mock_get.assert_called_once_with(f"https://mock.redis.co/del/free_quota:testuser1:{week_start}", headers={"Authorization": "Bearer mock_token"}, timeout=1.5)



@patch("api.admin.os.environ.get")
@patch("api.admin.requests.get")
@patch("api.auth.entitlements.verify_jwt")
def test_overview_accepts_206(mock_verify_jwt, mock_get, mock_env):
    mock_verify_jwt.return_value = {"sub": "admin123"}
    def env_side_effect(key, default=""):
        if key == "SUPABASE_URL": return "https://mock.supabase.co"
        if key == "SUPABASE_SECRET_KEY": return "mock_key"
        return default
    mock_env.side_effect = env_side_effect

    def get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 206
        params = kwargs.get("params", {})
        
        if "/auth/v1/admin/users" in url:
            resp.status_code = 200
            # Test total field in pagination
            resp.json.return_value = {"users": [1, 2], "total": 42}
        elif params.get("plan") == "eq.professional":
            resp.headers = {"Content-Range": "0-1/2"}
        elif params.get("status") == "eq.suspended":
            resp.headers = {"Content-Range": "0-0/1"}
        elif "created_at" in params and "gte" in params["created_at"]:
            resp.headers = {"Content-Range": "0-4/5"}
        elif "/rest/v1/scans" in url:
            resp.headers = {"Content-Range": "0-19/20"}
        else:
            resp.headers = {"Content-Range": "0-0/0"}
        return resp
    mock_get.side_effect = get_side_effect
    
    with patch("api.auth.entitlements.get_user_role", return_value="admin"):
        response = client.get("/api/admin/overview", headers={"Authorization": "Bearer admin_token"})
        
    assert response.status_code == 200
    data = response.json()
    assert data["total_users"] == 42
    assert data["professional_users"] == 2
    assert data["free_users"] == 40
    assert data["suspended_users"] == 1
    assert data["active_users"] == 41

@patch("api.admin.os.environ.get")
@patch("api.admin.requests.get")
@patch("api.auth.entitlements.verify_jwt")
def test_overview_missing_content_range(mock_verify_jwt, mock_get, mock_env):
    mock_verify_jwt.return_value = {"sub": "admin123"}
    def env_side_effect(key, default=""):
        if key == "SUPABASE_URL": return "https://mock.supabase.co"
        if key == "SUPABASE_SECRET_KEY": return "mock_key"
        return default
    mock_env.side_effect = env_side_effect

    def get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "/auth/v1/admin/users" in url:
            resp.json.return_value = {"users": [1]}
        else:
            resp.headers = {} # Missing Content-Range
        return resp
    mock_get.side_effect = get_side_effect
    
    with patch("api.auth.entitlements.get_user_role", return_value="admin"):
        response = client.get("/api/admin/overview", headers={"Authorization": "Bearer admin_token"})
        
    assert response.status_code == 502
    assert "Overview metric failed:" in response.json()["detail"]
