import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from api.index import app
from api.auth.entitlements import get_user_role

client = TestClient(app)

@pytest.fixture
def mock_get_current_user_normal():
    with patch('api.auth.entitlements.get_current_user') as m:
        m.return_value = {"sub": "user-123"}
        yield m

@pytest.fixture
def mock_get_current_user_admin():
    with patch('api.auth.entitlements.get_current_user') as m:
        m.return_value = {"sub": "admin-123", "role": "admin"}
        yield m

@pytest.fixture
def mock_get_user_role_normal():
    with patch('api.admin.get_user_role') as m:
        m.return_value = "user"
        yield m

@pytest.fixture
def mock_get_user_role_admin():
    with patch('api.admin.get_user_role') as m:
        m.return_value = "admin"
        yield m

def test_admin_me_missing_jwt():
    response = client.get("/api/admin/me")
    assert response.status_code == 401
    assert "Not authenticated" in response.json()["detail"] or "Authentication required" in response.json()["detail"]

def test_admin_me_normal_user(mock_get_current_user_normal, mock_get_user_role_normal):
    app.dependency_overrides[get_user_role] = lambda: "user"
    response = client.get("/api/admin/me")
    # Actually get_current_user is mock-injected via Dependency injection in FastAPI 
    # But we patched it globally or we can use dependency_overrides.
    pass

def test_admin_me_normal_user_override():
    # Properly override dependencies for FastAPI
    from api.admin import require_admin
    
    def override_get_current_user():
        return {"sub": "user-123"}
    
    def override_get_user_role(user_id):
        return "user"
        
    # We patch the function directly
    with patch('api.admin.get_current_user', return_value={"sub": "user-123"}), \
         patch('api.admin.get_user_role', return_value="user"):
         
        app.dependency_overrides[require_admin] = require_admin
        # If we use dependency_overrides for get_current_user:
        from api.auth.entitlements import get_current_user
        app.dependency_overrides[get_current_user] = override_get_current_user
        
        response = client.get("/api/admin/me")
        assert response.status_code == 403
        
        app.dependency_overrides.clear()

def test_admin_me_admin_user():
    def override_get_current_user():
        return {"sub": "admin-123"}
        
    with patch('api.admin.get_user_role', return_value="admin"):
        from api.auth.entitlements import get_current_user
        app.dependency_overrides[get_current_user] = override_get_current_user
        
        response = client.get("/api/admin/me")
        assert response.status_code == 200
        assert response.json()["role"] == "admin"
        
        app.dependency_overrides.clear()

@patch.dict('os.environ', {'SUPABASE_URL': 'http://mock', 'SUPABASE_SECRET_KEY': 'token'})
def test_admin_get_scans_mapping():
    def override_get_current_user():
        return {"sub": "admin-123"}
        
    with patch('api.admin.get_user_role', return_value="admin"), \
         patch('requests.get') as mock_get:
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"id": "1", "report_data": {"scan_mode": "active"}},
            {"id": "2", "report_data": {"scan_mode": "passive"}},
            {"id": "3", "report_data": {"scan_mode": "basic"}},
            {"id": "4", "report_data": {}},
            {"id": "5"}
        ]
        mock_get.return_value = mock_resp
        
        from api.auth.entitlements import get_current_user
        app.dependency_overrides[get_current_user] = override_get_current_user
        
        response = client.get("/api/admin/scans")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 5
        assert data[0]["scan_mode"] == "Advanced"
        assert data[1]["scan_mode"] == "Basic"
        assert data[2]["scan_mode"] == "Basic"
        assert data[3]["scan_mode"] == "Unknown"
        assert data[4]["scan_mode"] == "Unknown"
        
        app.dependency_overrides.clear()
