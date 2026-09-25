import pytest
from fastapi.testclient import TestClient
import json
import os
from unittest.mock import patch

# Mock TURNSTILE_SECRET_KEY before importing index/register
os.environ["TURNSTILE_SECRET_KEY"] = "test-secret"
os.environ["SUPABASE_URL"] = "http://test-supabase"
os.environ["SUPABASE_SECRET_KEY"] = "test-key"

from api.index import app
from api.auth.register import validate_password

client = TestClient(app)

def test_fastapi_loaded_successfully():
    # If this test runs, FastAPI imported successfully
    assert app is not None

def test_password_validation():
    # Length
    assert not validate_password("Short1!")
    assert not validate_password("a" * 73 + "A1!")
    # Complexity
    assert not validate_password("nouppercase1!")
    assert not validate_password("NOLOWERCASE1!")
    assert not validate_password("NoNumbersHere!")
    assert not validate_password("NoSpecialChar123")
    # Valid
    assert validate_password("ValidPassword123!")
    assert validate_password("Another!2Strong")

@patch('api.auth.register.requests.post')
@patch('api.auth.register.verify_turnstile')
def test_valid_registration(mock_turnstile, mock_post):
    mock_turnstile.return_value = True
    
    class MockResponse:
        def __init__(self, json_data, status_code, ok):
            self._json_data = json_data
            self.status_code = status_code
            self.ok = ok
            self.text = json.dumps(json_data)
            
        def json(self):
            return self._json_data
            
    mock_post.return_value = MockResponse({"id": "user-123", "email": "test@example.com"}, 201, True)
    
    payload = {
        "email": "test@example.com",
        "password": "ValidPassword123!",
        "phone": "+966555123456",
        "fullName": "Test User",
        "turnstileToken": "valid-token"
    }
    
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    
    # Verify Admin createUser payload
    call_args = mock_post.call_args[1]
    assert call_args["json"]["email"] == "test@example.com"
    assert call_args["json"].get("phone") is None
    assert call_args["json"]["email_confirm"] is False
    assert call_args["json"]["user_metadata"]["full_name"] == "Test User"

@patch('api.auth.register.verify_turnstile')
def test_invalid_captcha(mock_turnstile):
    mock_turnstile.return_value = False
    
    payload = {
        "email": "test@example.com",
        "password": "ValidPassword123!",
        "phone": "+966555123456",
        "fullName": "Test User",
        "turnstileToken": "invalid-token"
    }
    
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 400
    assert "Invalid CAPTCHA" in response.json()["detail"]

def test_missing_fields():
    payload = {
        "email": "test@example.com",
        # missing password, phone, fullName, turnstile
    }
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 422 # Pydantic validation error

@patch('api.auth.register.verify_turnstile')
def test_invalid_phone(mock_turnstile):
    mock_turnstile.return_value = True
    
    payload = {
        "email": "test@example.com",
        "password": "ValidPassword123!",
        "phone": "555-1234", # not E.164
        "fullName": "Test User",
        "turnstileToken": "valid-token"
    }
    
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 400
    assert "Invalid phone number" in response.json()["detail"]

@patch('api.auth.register.requests.post')
@patch('api.auth.register.verify_turnstile')
def test_duplicate_registration(mock_turnstile, mock_post):
    mock_turnstile.return_value = True
    
    class MockResponse:
        def __init__(self, json_data, status_code, ok):
            self._json_data = json_data
            self.status_code = status_code
            self.ok = ok
            self.text = json.dumps(json_data)
            
        def json(self):
            return self._json_data
            
    mock_post.return_value = MockResponse({"message": "User already exists"}, 400, False)
    
    payload = {
        "email": "test@example.com",
        "password": "ValidPassword123!",
        "phone": "+966555123456",
        "fullName": "Test User",
        "turnstileToken": "valid-token"
    }
    
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 400
    assert "User already registered" in response.json()["detail"]
