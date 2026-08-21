from fastapi.testclient import TestClient
from api.index import app
from unittest.mock import patch

client = TestClient(app)

@patch("api.index.acquire_scan_lease", return_value="mock-lease")
@patch("api.index.release_scan_lease")
@patch("api.index.check_rate_limit", return_value=True)
@patch("api.index.scan_url")
@patch("api.index.Entitlements")
@patch("api.index.check_free_quota", return_value={"quota_remaining": 5})
@patch("api.index.consume_free_quota", return_value=True)
def test_report_mode_propagation(mock_consume, mock_check, mock_entitlements, mock_scan_url, mock_rate_limit, mock_release, mock_acquire):
    mock_ent_instance = mock_entitlements.return_value
    mock_ent_instance.plan = "free"
    mock_ent_instance.can_advanced_scan = True
    # Mock the return value of the underlying scan_url (which doesn't know about report_mode)
    mock_scan_url.return_value = {"status": "success", "score": 100}

    # Test 1: Default (Passive + Simple)
    response = client.post("/api/scan", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["report_mode"] == "simple"
    mock_scan_url.assert_called_with("https://example.com", False, "passive")

    # Test 2: Passive + Technical
    response = client.post("/api/scan", json={
        "url": "https://example.com",
        "scan_mode": "passive",
        "report_mode": "technical"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["report_mode"] == "technical"
    mock_scan_url.assert_called_with("https://example.com", False, "passive")

    # Test 3: Active + Simple
    response = client.post("/api/scan", json={
        "url": "https://example.com",
        "scan_mode": "active",
        "report_mode": "simple"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["report_mode"] == "simple"
    mock_scan_url.assert_called_with("https://example.com", False, "active")

    # Test 4: Active + Technical
    response = client.post("/api/scan", json={
        "url": "https://example.com",
        "scan_mode": "active",
        "report_mode": "technical"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["report_mode"] == "technical"
    mock_scan_url.assert_called_with("https://example.com", False, "active")

def test_invalid_report_mode():
    response = client.post("/api/scan", json={
        "url": "https://example.com",
        "report_mode": "invalid"
    })
    # Pydantic validation error returns 422 Unprocessable Entity
    assert response.status_code == 422
