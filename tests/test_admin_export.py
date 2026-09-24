from fastapi.testclient import TestClient
from api.index import app
import pytest

client = TestClient(app)

def test_admin_export_csv(monkeypatch):
    monkeypatch.setenv('SUPABASE_URL', 'https://example.com')
    monkeypatch.setenv('SUPABASE_SECRET_KEY', 'mock')
    from api.admin import require_admin
    app.dependency_overrides[require_admin] = lambda: {"sub": "admin-123"}

    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
        def json(self):
            return self.json_data

    def mock_requests_get(url, *args, **kwargs):
        print('MOCK URL CALLED:', url)
        if "auth/v1/admin/users" in url:
            return MockResponse({"users": [
                {
                    "id": "u1",
                    "email": "test@example.com",
                    "phone": "+123456",
                    "phone_confirmed_at": "2026-09-24",
                    "user_metadata": {"full_name": "Test User"}
                },
                {
                    "id": "u2",
                    "email": "unverified@example.com",
                    "phone": "=cmd|' /C calc'!",
                    "phone_confirmed_at": None
                },
                {
                    "id": "u3",
                    "email": "legacy@example.com"
                }
            ]})
        if "user_plans" in url:
            return MockResponse([])
        if "user_roles" in url:
            return MockResponse([])
        return MockResponse({})
    monkeypatch.setattr("requests.get", mock_requests_get)

    resp = client.get("/api/admin/users/export?format=csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/csv; charset=utf-8"
    content = resp.text

    # Headers
    assert "User ID,Name,Email,Phone,Phone Verification Status,Role,Plan,Status,Created At" in content
    # u1
    assert "u1,Test User,test@example.com,'+123456,Verified" in content
    # u2 (formula protection on phone)
    assert "u2,,unverified@example.com,'=cmd|' /C calc'!,Unverified" in content
    # u3
    assert "u3,,legacy@example.com,Not provided,Not provided" in content

def test_admin_export_xlsx(monkeypatch):
    monkeypatch.setenv('SUPABASE_URL', 'https://example.com')
    monkeypatch.setenv('SUPABASE_SECRET_KEY', 'mock')
    from api.admin import require_admin
    app.dependency_overrides[require_admin] = lambda: {"sub": "admin-123"}

    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
        def json(self):
            return self.json_data

    def mock_requests_get(url, *args, **kwargs):
        print('MOCK URL CALLED:', url)
        if "auth/v1/admin/users" in url:
            return MockResponse({"users": [
                {"id": "u1", "email": "test@example.com"}
            ]})
        if "user_plans" in url:
            return MockResponse([])
        if "user_roles" in url:
            return MockResponse([])
        return MockResponse({})

    monkeypatch.setattr("requests.get", mock_requests_get)

    resp = client.get("/api/admin/users/export?format=xlsx")
    assert resp.status_code == 200
    assert "spreadsheetml.sheet" in resp.headers["content-type"]
    assert resp.content.startswith(b"PK") # ZIP file header for xlsx

def test_admin_export_unauthorized(monkeypatch):
    from api.admin import require_admin
    app.dependency_overrides.pop(require_admin, None)

    resp = client.get("/api/admin/users/export?format=csv")
    assert resp.status_code == 401

def test_admin_export_pagination(monkeypatch):
    monkeypatch.setenv('SUPABASE_URL', 'https://example.com')
    monkeypatch.setenv('SUPABASE_SECRET_KEY', 'mock')
    from api.admin import require_admin
    app.dependency_overrides[require_admin] = lambda: {"sub": "admin-123"}

    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
        def json(self):
            return self.json_data

    # We will simulate per_page=1000 fetching.
    # For testing, we just check the page param in the url.
    def mock_requests_get(url, *args, **kwargs):
        print('MOCK URL CALLED:', url)
        if "auth/v1/admin/users" in url:
            if "?page=1&" in url:
                users = [{"id": f"u_1_{i}", "email": f"page1_{i}@example.com"} for i in range(1000)]
                users[0] = {"id": "u1", "email": "page1a@example.com"}
                users[1] = {"id": "u2", "email": "page1b@example.com"}
                return MockResponse({"users": users})
            elif "?page=2&" in url:
                users = [{"id": f"u_2_{i}", "email": f"page2_{i}@example.com"} for i in range(1000)]
                users[0] = {"id": "u3", "email": "page2a@example.com"}
                users[1] = {"id": "u4", "email": "page2b@example.com"}
                return MockResponse({"users": users})
            elif "?page=3&" in url:
                return MockResponse({"users": [
                    {"id": "u5", "email": "page3a@example.com"}
                ]})
            else:
                return MockResponse({"users": []})
        if "user_plans" in url:
            return MockResponse([])
        if "user_roles" in url:
            return MockResponse([])
        return MockResponse({})
    monkeypatch.setattr("requests.get", mock_requests_get)

    # We will also test that search is applied to the combined dataset!
    resp = client.get("/api/admin/users/export?format=csv&search=page")
    assert resp.status_code == 200
    content = resp.text

    assert "u1" in content
    assert "u2" in content
    assert "u3" in content
    assert "u4" in content
    assert "u5" in content
    assert "page1a@example.com" in content
    assert "page2a@example.com" in content
    assert "page3a@example.com" in content

    # Verify search filtering actually filters from the combined dataset
    resp_filtered = client.get("/api/admin/users/export?format=csv&search=page2")
    assert resp_filtered.status_code == 200
    content_filtered = resp_filtered.text
    assert "u3" in content_filtered
    assert "u4" in content_filtered
    assert "u1" not in content_filtered
    assert "u5" not in content_filtered

def test_admin_export_pagination_failure(monkeypatch):
    monkeypatch.setenv('SUPABASE_URL', 'https://example.com')
    monkeypatch.setenv('SUPABASE_SECRET_KEY', 'mock')
    from api.admin import require_admin
    app.dependency_overrides[require_admin] = lambda: {"sub": "admin-123"}

    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
        def json(self):
            return self.json_data

    def mock_requests_get(url, *args, **kwargs):
        if "auth/v1/admin/users" in url:
            if "?page=1&" in url:
                # Return full page
                users = [{"id": f"u_1_{i}", "email": f"page1_{i}@example.com"} for i in range(1000)]
                return MockResponse({"users": users})
            elif "?page=2&" in url:
                # Simulate upstream 500 failure halfway through traversal
                return MockResponse({"error": "Internal Server Error"}, status_code=500)
            else:
                return MockResponse({"users": []})

        if "user_plans" in url:
            return MockResponse([])
        if "user_roles" in url:
            return MockResponse([])
        return MockResponse({})

    monkeypatch.setattr("requests.get", mock_requests_get)

    resp = client.get("/api/admin/users/export?format=csv")

    # Must fail securely
    assert resp.status_code == 500

    # Assert partial file isn't returned, verify safe generic error body
    assert resp.headers.get("content-type") != "text/csv; charset=utf-8"
    assert "Error fetching users" in resp.text

    # Ensure no raw Supabase error leak
    assert "Internal Server Error" not in resp.text

def test_admin_export_max_pages(monkeypatch):
    monkeypatch.setenv('SUPABASE_URL', 'https://example.com')
    monkeypatch.setenv('SUPABASE_SECRET_KEY', 'mock')
    from api.admin import require_admin
    app.dependency_overrides[require_admin] = lambda: {"sub": "admin-123"}

    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
        def json(self):
            return self.json_data

    # Simulate a full page every time
    def mock_requests_get(url, *args, **kwargs):
        if "auth/v1/admin/users" in url:
            users = [{"id": f"u_m_{i}", "email": f"m{i}@example.com"} for i in range(1000)]
            return MockResponse({"users": users})
        if "user_plans" in url:
            return MockResponse([])
        if "user_roles" in url:
            return MockResponse([])
        return MockResponse({})

    monkeypatch.setattr("requests.get", mock_requests_get)

    resp = client.get("/api/admin/users/export?format=csv")
    assert resp.status_code == 500
    assert "Export exceeds maximum supported size" in resp.json()["detail"]


def test_admin_export_plans_roles_pagination(monkeypatch):
    monkeypatch.setenv('SUPABASE_URL', 'https://example.com')
    monkeypatch.setenv('SUPABASE_SECRET_KEY', 'mock')
    from api.admin import require_admin
    app.dependency_overrides[require_admin] = lambda: {"sub": "admin-123"}

    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
        def json(self):
            return self.json_data

    def mock_requests_get(url, *args, **kwargs):
        if "auth/v1/admin/users" in url:
            if "?page=1&" in url:
                return MockResponse({"users": [
                    {"id": "u_early", "email": "early@example.com"},
                    {"id": "u_late", "email": "late@example.com"}
                ]})
            return MockResponse({"users": []})

        if "user_plans" in url:
            if "offset=0" in url:
                plans = [{"user_id": f"dummy{i}", "plan": "Free", "status": "active"} for i in range(1000)]
                plans[0] = {"user_id": "u_early", "plan": "Pro", "status": "active"}
                return MockResponse(plans)
            elif "offset=1000" in url:
                return MockResponse([
                    {"user_id": "u_late", "plan": "Enterprise", "status": "active"}
                ])
            return MockResponse([])

        if "user_roles" in url:
            if "offset=0" in url:
                roles = [{"user_id": f"dummy{i}", "role": "user"} for i in range(1000)]
                roles[0] = {"user_id": "u_early", "role": "admin"}
                return MockResponse(roles)
            elif "offset=1000" in url:
                return MockResponse([
                    {"user_id": "u_late", "role": "superadmin"}
                ])
            return MockResponse([])

        return MockResponse({})

    monkeypatch.setattr("requests.get", mock_requests_get)

    # Also test filtering to make sure late items are retained
    resp = client.get("/api/admin/users/export?format=csv&role=superadmin")
    assert resp.status_code == 200
    content = resp.text

    assert "u_late" in content
    assert "Enterprise" in content
    assert "superadmin" in content
    assert "u_early" not in content


def test_admin_export_plans_roles_failure(monkeypatch):
    monkeypatch.setenv('SUPABASE_URL', 'https://example.com')
    monkeypatch.setenv('SUPABASE_SECRET_KEY', 'mock')
    from api.admin import require_admin
    app.dependency_overrides[require_admin] = lambda: {"sub": "admin-123"}

    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
        def json(self):
            return self.json_data

    def mock_requests_get(url, *args, **kwargs):
        if "auth/v1/admin/users" in url:
            if "?page=1&" in url:
                return MockResponse({"users": [{"id": "u_1", "email": "a@a.com"}]})
            return MockResponse({"users": []})

        if "user_plans" in url:
            if "offset=1000" in url:
                return MockResponse({"error": "Failed"}, status_code=500)
            return MockResponse([{"user_id": f"dummy{i}", "plan": "Free"} for i in range(1000)])

        if "user_roles" in url:
            return MockResponse([])

        return MockResponse({})

    monkeypatch.setattr("requests.get", mock_requests_get)

    resp = client.get("/api/admin/users/export?format=csv")
    assert resp.status_code == 500
    assert "Error fetching users" in resp.text
