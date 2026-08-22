import pytest
from unittest.mock import patch, MagicMock

from api.auth.entitlements import get_free_quota_key, check_free_quota, consume_free_quota, reset_free_quota, get_monday_utc_boundaries

def test_free_quota_key_consistency():
    # Verify the helper returns the exact expected format
    key = get_free_quota_key("user123", 1000)
    assert key == "free_quota:user123:1000"

@patch("api.auth.entitlements.os.environ.get")
@patch("api.auth.entitlements.requests.get")
@patch("api.auth.entitlements.requests.post")
@patch("api.auth.entitlements.get_monday_utc_boundaries")
def test_quota_functions_use_centralized_key(mock_bounds, mock_post, mock_get, mock_env):
    mock_bounds.return_value = (1000, 2000)
    mock_env.return_value = "mock"
    
    mock_get.return_value = MagicMock(status_code=200, json=lambda: {"result": "0"})
    mock_post.return_value = MagicMock(status_code=200, json=lambda: {"result": 1})
    
    # 1. Check
    check_free_quota("user123")
    mock_get.assert_called_with("mock/get/free_quota:user123:1000", headers={"Authorization": "Bearer mock"}, timeout=1.0)
    
    # 2. Consume
    consume_free_quota("user123")
    args, kwargs = mock_post.call_args
    payload = kwargs["json"]
    assert "free_quota:user123:1000" in payload
    
    # 3. Reset
    reset_free_quota("user123")
    mock_get.assert_called_with("mock/del/free_quota:user123:1000", headers={"Authorization": "Bearer mock"}, timeout=1.5)
