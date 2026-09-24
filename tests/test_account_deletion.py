import unittest
from fastapi.testclient import TestClient
import os
import requests
from unittest.mock import patch, MagicMock
from api.index import app
from api.auth.entitlements import require_current_user

class TestAccountDeletion(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    @patch("api.index.requests.delete")
    @patch("api.index.os.environ.get")
    def test_delete_account_success(self, mock_env, mock_delete):
        def mock_env_get(key, default=""):
            if key == "SUPABASE_URL": return "https://mock.supabase.co"
            if key == "SUPABASE_SECRET_KEY": return "mock-secret"
            return default
        mock_env.side_effect = mock_env_get

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_delete.return_value = mock_resp

        app.dependency_overrides[require_current_user] = lambda: {"sub": "user123"}

        response = self.client.delete("/api/account")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "success", "message": "Account and associated data deleted"})

        mock_delete.assert_called_once_with(
            "https://mock.supabase.co/auth/v1/admin/users/user123",
            headers={
                "apikey": "mock-secret",
                "Authorization": "Bearer mock-secret",
                "Content-Type": "application/json"
            },
            timeout=10
        )
        app.dependency_overrides.clear()

    def test_delete_account_unauthenticated(self):
        # Without override, it should fail
        response = self.client.delete("/api/account")
        self.assertEqual(response.status_code, 401)
