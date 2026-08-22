import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from api.index import app

client = TestClient(app)

def mock_get_current_user_admin():
    return {"sub": "admin-123", "role": "admin"}

def mock_get_current_user_normal():
    return {"sub": "user-456"}

def side_effect_role(uid):
    return "admin" if uid == "admin-123" else "user"

@patch.dict('os.environ', {'SUPABASE_URL': 'http://mock', 'SUPABASE_SECRET_KEY': 'token'})
def test_grant_professional_success():
    with patch('api.admin.verify_user_exists'), \
         patch('api.admin.get_user_role', side_effect=side_effect_role), \
         patch('api.admin.get_user_plan_and_status', return_value=("free", "active")), \
         patch('api.admin.upsert_user_plan') as mock_upsert, \
         patch('api.admin.audit_log') as mock_audit:
         
        from api.auth.entitlements import get_current_user
        app.dependency_overrides[get_current_user] = mock_get_current_user_admin
        
        response = client.post("/api/admin/users/target-1/grant-professional", json={"reason": "Upgraded"})
        
        assert response.status_code == 200
        assert response.json() == {"user_id": "target-1", "plan": "professional", "status": "active"}
        
        mock_upsert.assert_called_once_with("target-1", "professional", "active")
        mock_audit.assert_called_once_with(
            "admin-123", 
            "grant_professional", 
            "user", 
            "target-1", 
            "Upgraded", 
            {"role": "user", "plan": "free", "status": "active"}, 
            {"role": "user", "plan": "professional", "status": "active"}
        )
        
        app.dependency_overrides.clear()

@patch.dict('os.environ', {'SUPABASE_URL': 'http://mock', 'SUPABASE_SECRET_KEY': 'token'})
def test_grant_professional_normal_user():
    with patch('api.admin.verify_user_exists'), \
         patch('api.admin.get_user_role', return_value="user"):
        from api.auth.entitlements import get_current_user
        app.dependency_overrides[get_current_user] = mock_get_current_user_normal
        
        response = client.post("/api/admin/users/target-1/grant-professional")
        assert response.status_code == 403
        app.dependency_overrides.clear()

@patch.dict('os.environ', {'SUPABASE_URL': 'http://mock', 'SUPABASE_SECRET_KEY': 'token'})
def test_remove_professional_success():
    with patch('api.admin.verify_user_exists'), \
         patch('api.admin.get_user_role', side_effect=side_effect_role), \
         patch('api.admin.get_user_plan_and_status', return_value=("professional", "active")), \
         patch('api.admin.upsert_user_plan') as mock_upsert, \
         patch('api.admin.audit_log') as mock_audit:
         
        from api.auth.entitlements import get_current_user
        app.dependency_overrides[get_current_user] = mock_get_current_user_admin
        
        response = client.post("/api/admin/users/target-1/remove-professional", json={"reason": "Downgraded"})
        
        assert response.status_code == 200
        
        mock_upsert.assert_called_once_with("target-1", "free", "active")
        app.dependency_overrides.clear()

@patch.dict('os.environ', {'SUPABASE_URL': 'http://mock', 'SUPABASE_SECRET_KEY': 'token'})
def test_suspend_success():
    with patch('api.admin.verify_user_exists'), \
         patch('api.admin.get_user_role', side_effect=side_effect_role), \
         patch('api.admin.get_user_plan_and_status', return_value=("free", "active")), \
         patch('api.admin.upsert_user_plan') as mock_upsert, \
         patch('api.admin.audit_log') as mock_audit:
         
        from api.auth.entitlements import get_current_user
        app.dependency_overrides[get_current_user] = mock_get_current_user_admin
        
        response = client.post("/api/admin/users/target-1/suspend")
        
        assert response.status_code == 200
        mock_upsert.assert_called_once_with("target-1", "free", "suspended")
        app.dependency_overrides.clear()

@patch.dict('os.environ', {'SUPABASE_URL': 'http://mock', 'SUPABASE_SECRET_KEY': 'token'})
def test_suspend_self_blocked():
    with patch('api.admin.verify_user_exists'), \
         patch('api.admin.get_user_role', side_effect=side_effect_role), \
         patch('api.admin.get_user_plan_and_status', return_value=("free", "active")):
         
        from api.auth.entitlements import get_current_user
        app.dependency_overrides[get_current_user] = mock_get_current_user_admin
        
        # target self
        response = client.post("/api/admin/users/admin-123/suspend")
        
        assert response.status_code == 400
        assert "cannot suspend your own" in response.json()["detail"]
        app.dependency_overrides.clear()

@patch.dict('os.environ', {'SUPABASE_URL': 'http://mock', 'SUPABASE_SECRET_KEY': 'token'})
def test_reactivate_success():
    with patch('api.admin.verify_user_exists'), \
         patch('api.admin.get_user_role', side_effect=side_effect_role), \
         patch('api.admin.get_user_plan_and_status', return_value=("free", "suspended")), \
         patch('api.admin.upsert_user_plan') as mock_upsert, \
         patch('api.admin.audit_log') as mock_audit:
         
        from api.auth.entitlements import get_current_user
        app.dependency_overrides[get_current_user] = mock_get_current_user_admin
        
        response = client.post("/api/admin/users/target-1/reactivate")
        
        assert response.status_code == 200
        mock_upsert.assert_called_once_with("target-1", "free", "active")
        app.dependency_overrides.clear()

@patch.dict('os.environ', {'SUPABASE_URL': 'http://mock', 'SUPABASE_SECRET_KEY': 'token'})
def test_spoof_role_has_no_effect():
    with patch('api.admin.verify_user_exists'), \
         patch('api.admin.get_user_role', side_effect=side_effect_role), \
         patch('api.admin.get_user_plan_and_status', return_value=("free", "active")), \
         patch('api.admin.upsert_user_plan') as mock_upsert, \
         patch('api.admin.audit_log') as mock_audit:
         
        from api.auth.entitlements import get_current_user
        app.dependency_overrides[get_current_user] = mock_get_current_user_admin
        
        response = client.post("/api/admin/users/target-1/grant-professional", json={"role": "admin"})
        
        assert response.status_code == 200
        # Should not upsert role=admin anywhere
        mock_upsert.assert_called_once_with("target-1", "professional", "active")
        app.dependency_overrides.clear()

@patch.dict('os.environ', {'SUPABASE_URL': 'http://mock', 'SUPABASE_SECRET_KEY': 'token'})
def test_grant_professional_user_not_found():
    with patch('requests.get') as mock_get, patch('api.admin.get_user_role', side_effect=side_effect_role):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp
        
        from api.auth.entitlements import get_current_user
        app.dependency_overrides[get_current_user] = mock_get_current_user_admin
        
        response = client.post("/api/admin/users/fake-user-id/grant-professional")
        
        assert response.status_code == 404
        assert response.json()["detail"] == "User not found."
        app.dependency_overrides.clear()
