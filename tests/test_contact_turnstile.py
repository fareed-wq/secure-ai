from fastapi.testclient import TestClient
from api.index import app
from unittest.mock import patch, MagicMock
import os
import json

client = TestClient(app)

def test_contact_missing_turnstile_secret(monkeypatch):
    monkeypatch.delenv("TURNSTILE_SECRET_KEY", raising=False)
    response = client.post("/api/contact", json={
        "form_type": "unified",
        "topic": "General Question",
        "email": "test@example.com",
        "message": "Hello",
        "url": "",
        "turnstileToken": "valid_token"
    })
    assert response.status_code == 503

@patch('urllib3.PoolManager.request')
def test_contact_valid_turnstile(mock_request, monkeypatch):
    monkeypatch.setenv("TURNSTILE_SECRET_KEY", "dummy_secret")
    monkeypatch.setenv("RESEND_API_KEY", "dummy_resend")

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.data = json.dumps({"success": True}).encode("utf-8")

    mock_resend_resp = MagicMock()
    mock_resend_resp.status = 200
    mock_resend_resp.data = b'{"id":"mock_id"}'

    mock_request.side_effect = [mock_resp, mock_resend_resp]

    response = client.post("/api/contact", json={
        "form_type": "unified",
        "topic": "General Question",
        "email": "test@example.com",
        "message": "Hello",
        "url": "",
        "turnstileToken": "valid_token"
    })

    assert response.status_code == 200
    assert response.json()["status"] == "success"

@patch('urllib3.PoolManager.request')
def test_contact_invalid_turnstile(mock_request, monkeypatch):
    monkeypatch.setenv("TURNSTILE_SECRET_KEY", "dummy_secret")

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.data = json.dumps({"success": False}).encode("utf-8")
    mock_request.return_value = mock_resp

    response = client.post("/api/contact", json={
        "form_type": "unified",
        "topic": "General Question",
        "email": "test@example.com",
        "message": "Hello",
        "url": "",
        "turnstileToken": "invalid_token"
    })

    assert response.status_code == 400
    assert "Verification failed" in response.json()["error"]
    mock_request.assert_called_once()  # Only Cloudflare was called, not Resend

@patch('urllib3.PoolManager.request')
def test_contact_turnstile_network_failure(mock_request, monkeypatch):
    import urllib3
    monkeypatch.setenv("TURNSTILE_SECRET_KEY", "dummy_secret")

    mock_request.side_effect = urllib3.exceptions.MaxRetryError(
        urllib3.connectionpool.HTTPSConnectionPool(host='challenges.cloudflare.com', port=443),
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        Exception("Connection refused")
    )

    response = client.post("/api/contact", json={
        "form_type": "unified",
        "topic": "General Question",
        "email": "test@example.com",
        "message": "Hello",
        "url": "",
        "turnstileToken": "valid_token"
    })

    assert response.status_code == 400
    assert "Verification failed" in response.json()["error"]
    mock_request.assert_called_once()  # Only Cloudflare was called, not Resend
