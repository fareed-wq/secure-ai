import pytest
from fastapi.testclient import TestClient
from api.index import app
from api.auth.entitlements import get_current_user, Entitlements
from unittest.mock import patch, MagicMock

client = TestClient(app)

@pytest.fixture
def mock_entitlements_free():
    with patch('api.index.Entitlements') as MockEntitlements:
        mock_instance = MockEntitlements.return_value
        mock_instance.plan = 'free'
        mock_instance.can_advanced_scan = True
        mock_instance.can_share_scan = True
        mock_instance.is_admin = False
        yield mock_instance

@pytest.fixture
def mock_entitlements_guest():
    with patch('api.index.Entitlements') as MockEntitlements:
        mock_instance = MockEntitlements.return_value
        mock_instance.plan = 'guest'
        mock_instance.can_advanced_scan = False
        mock_instance.can_share_scan = False
        mock_instance.is_admin = False
        yield mock_instance

@pytest.fixture
def mock_db_env():
    with patch('api.auth.entitlements.SUPABASE_URL', 'http://mock-db'), \
         patch('api.auth.entitlements.SUPABASE_SECRET_KEY', 'mock-secret-key'):
        yield

def test_create_share_success(mock_entitlements_free, mock_db_env):
    app.dependency_overrides[get_current_user] = lambda: {'sub': 'user-123'}
    try:
        with patch('api.index.requests.get') as mock_get, \
             patch('api.index.requests.post') as mock_post:
            
            # First GET: scan exists and belongs to user
            mock_get.side_effect = [
                MagicMock(status_code=200, json=lambda: [{"id": "scan-123"}]),
                # Second GET: active share does not exist
                MagicMock(status_code=200, json=lambda: [])
            ]
            
            mock_post.return_value = MagicMock(status_code=201, json=lambda: [{"share_token": "mock-token", "created_at": "2023-01-01T00:00:00Z"}])
            
            response = client.post("/api/share/create", json={"scan_id": "scan-123"})
            assert response.status_code == 200
            assert response.json() == {"share_token": "mock-token", "created_at": "2023-01-01T00:00:00Z"}
    finally:
        app.dependency_overrides.clear()

def test_create_share_existing_active(mock_entitlements_free, mock_db_env):
    app.dependency_overrides[get_current_user] = lambda: {'sub': 'user-123'}
    try:
        with patch('api.index.requests.get') as mock_get:
            
            mock_get.side_effect = [
                MagicMock(status_code=200, json=lambda: [{"id": "scan-123"}]),
                MagicMock(status_code=200, json=lambda: [{"share_token": "existing-token", "created_at": "2023-01-01"}])
            ]
            
            response = client.post("/api/share/create", json={"scan_id": "scan-123"})
            assert response.status_code == 200
            assert response.json() == {"share_token": "existing-token", "created_at": "2023-01-01"}
    finally:
        app.dependency_overrides.clear()

def test_create_share_not_owner(mock_entitlements_free, mock_db_env):
    app.dependency_overrides[get_current_user] = lambda: {'sub': 'user-123'}
    try:
        with patch('api.index.requests.get') as mock_get:
            
            # Scan does not belong to user (returns empty)
            mock_get.return_value = MagicMock(status_code=200, json=lambda: [])
            
            response = client.post("/api/share/create", json={"scan_id": "scan-123"})
            assert response.status_code == 404
            assert "access denied" in response.json()["error"]
    finally:
        app.dependency_overrides.clear()

def test_create_share_guest_blocked(mock_entitlements_guest):
    app.dependency_overrides[get_current_user] = lambda: {}
    try:
        response = client.post("/api/share/create", json={"scan_id": "scan-123"})
        assert response.status_code == 403
    finally:
        app.dependency_overrides.clear()

def test_revoke_share_success(mock_entitlements_free, mock_db_env):
    app.dependency_overrides[get_current_user] = lambda: {'sub': 'user-123'}
    try:
        with patch('api.index.requests.patch') as mock_patch:
            mock_patch.return_value = MagicMock(status_code=200, json=lambda: [])
            
            response = client.post("/api/share/revoke", json={"share_token": "mock-token"})
            assert response.status_code == 200
            assert response.json()["status"] == "success"
    finally:
        app.dependency_overrides.clear()

def test_get_shared_report_success(mock_db_env):
    with patch('api.index.requests.get') as mock_get:
        mock_get.side_effect = [
            # First GET: valid share token
            MagicMock(status_code=200, json=lambda: [{"scan_id": "scan-123"}]),
            # Second GET: resolve scan
            MagicMock(status_code=200, json=lambda: [{"target_url": "example.com", "score": 95, "report_data": {}, "created_at": "2023-01-01", "owner_user_id": "private-uuid", "internal_secret": "hidden"}])
        ]
        
        response = client.get("/api/share/mock-token")
        assert response.status_code == 200
        
        # Ensure constrained public projection
        data = response.json()
        assert "target_url" in data
        assert "score" in data
        assert "report_data" in data
        assert "created_at" in data
        assert "owner_user_id" not in data
        assert "internal_secret" not in data

def test_get_shared_report_revoked_or_invalid(mock_db_env):
    with patch('api.index.requests.get') as mock_get:
        # Invalid or revoked token returns empty
        mock_get.return_value = MagicMock(status_code=200, json=lambda: [])
        
        response = client.get("/api/share/invalid-token")
        assert response.status_code == 404
