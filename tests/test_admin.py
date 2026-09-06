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
    with patch('api.auth.entitlements.get_user_role') as m:
        m.return_value = "user"
        yield m

@pytest.fixture
def mock_get_user_role_admin():
    with patch('api.auth.entitlements.get_user_role') as m:
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
         patch('api.auth.entitlements.get_user_role', return_value="user"):

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

    with patch('api.auth.entitlements.get_user_role', return_value="admin"):
        from api.auth.entitlements import get_current_user
        app.dependency_overrides[get_current_user] = override_get_current_user

        response = client.get("/api/admin/me")
        assert response.status_code == 200
        assert response.json()["role"] == "admin"

        app.dependency_overrides.clear()

def test_admin_users_search(mock_get_current_user_admin, mock_get_user_role_admin, monkeypatch):
    monkeypatch.setenv('SUPABASE_URL', 'https://example.com')
    monkeypatch.setenv('SUPABASE_SECRET_KEY', 'mock')
    from api.admin import require_admin
    app.dependency_overrides[require_admin] = lambda: {"sub": "admin-123"}

    # We mock ThreadPoolExecutor or requests to return fake users
    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
        def json(self):
            return self.json_data

    def mock_requests_get(url, *args, **kwargs):
        if "auth/v1/admin/users" in url:
            return MockResponse({"users": [
                {"id": "user-1", "email": "test@example.com"},
                {"id": "user-2", "email": "admin@example.com"}
            ]})
        if "user_plans" in url:
            return MockResponse([{"user_id": "user-1", "plan": "professional"}])
        if "user_roles" in url:
            return MockResponse([{"user_id": "user-1", "role": "user"}])
        return MockResponse({})

    monkeypatch.setattr("requests.get", mock_requests_get)

    # Search by email
    resp = client.get("/api/admin/users?search=admin@example.com")
    assert resp.status_code == 200, resp.json()
    assert len(resp.json()) == 1
    assert resp.json()[0]["email"] == "admin@example.com"

    # Search by ID
    resp2 = client.get("/api/admin/users?search=user-1")
    assert resp2.status_code == 200
    assert len(resp2.json()) == 1
    assert resp2.json()[0]["user_id"] == "user-1"



def test_admin_audit_logs_search(mock_get_current_user_admin, mock_get_user_role_admin, monkeypatch):
    monkeypatch.setenv('SUPABASE_URL', 'https://example.com')
    monkeypatch.setenv('SUPABASE_SECRET_KEY', 'mock')
    from api.admin import require_admin
    app.dependency_overrides[require_admin] = lambda: {"sub": "admin-123"}

    def mock_requests_get(url, *args, **kwargs):
        return MockResponse([{"id": "log-1", "action": url}])

    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
        def json(self):
            return self.json_data

    monkeypatch.setattr("requests.get", mock_requests_get)

    uuid_str = "12345678-1234-5678-1234-567812345678"
    resp = client.get(f"/api/admin/audit-logs?search={uuid_str}")
    assert resp.status_code == 200, resp.json()
    assert "admin_user_id.eq" in resp.json()[0]["action"]

    resp2 = client.get("/api/admin/audit-logs?search=login")
    assert resp2.status_code == 200
    assert "action=ilike.*login*" in resp2.json()[0]["action"]
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from api.index import app
from api.auth.entitlements import get_current_user

client = TestClient(app)

def test_admin_role_resolution_consistency():
    app.dependency_overrides.clear()
    from api.auth.entitlements import get_current_user, require_current_user
    # 1. JWT with role='admin', DB says 'user' -> BLOCKED
    def override_get_current_user_jwt_admin():
        return {"sub": "admin-123", "role": "admin"}

    app.dependency_overrides[get_current_user] = override_get_current_user_jwt_admin
    app.dependency_overrides[require_current_user] = override_get_current_user_jwt_admin

    from unittest.mock import patch
    with patch('api.auth.entitlements.get_user_role', return_value="user"):
        res_me = client.get("/api/admin/me")
        assert res_me.status_code == 403
        
        res_quota = client.get("/api/quota")
        assert res_quota.status_code == 200
        assert res_quota.json().get("role") != "admin"
        assert res_quota.json().get("is_unlimited") != True

    # 2. JWT with normal role, DB says 'admin' -> ALLOWED
    def override_get_current_user_jwt_normal():
        return {"sub": "admin-123", "role": "authenticated"}

    app.dependency_overrides[get_current_user] = override_get_current_user_jwt_normal
    app.dependency_overrides[require_current_user] = override_get_current_user_jwt_normal

    with patch('api.auth.entitlements.get_user_role', return_value="admin"):
        res_me = client.get("/api/admin/me")
        assert res_me.status_code == 200
        assert res_me.json().get("role") == "admin"
        
        res_quota = client.get("/api/quota")
        assert res_quota.status_code == 200
        assert res_quota.json().get("role") == "admin"
        assert res_quota.json().get("is_unlimited") is True

    app.dependency_overrides.clear()
