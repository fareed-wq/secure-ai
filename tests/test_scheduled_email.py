import os
import json
import pytest
import urllib3
from unittest.mock import patch, MagicMock

from api.utils.email_helper import send_email, EmailResult
from api.utils.pdf_generator import generate_pdf, MAX_EMAIL_PDF_BYTES, _resolve_scan_timestamp

# 1. Test Email Helper
@patch('api.utils.email_helper.urllib3.PoolManager')
@patch.dict(os.environ, {"RESEND_API_KEY": "test_key"})
def test_send_email_success(mock_pool_manager):
    mock_http = MagicMock()
    mock_pool_manager.return_value = mock_http
    
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_http.request.return_value = mock_resp
    
    result = send_email(
        to="test@example.com",
        subject="Test Subject",
        html="<p>Test</p>",
        attachments=[{"filename": "test.pdf", "content": "base64bytes"}],
        idempotency_key="idemp-123"
    )
    
    assert isinstance(result, EmailResult)
    assert result.success is True
    assert result.status_code == 200
    assert result.is_transient is False
    
    args, kwargs = mock_http.request.call_args
    assert kwargs['headers']['Authorization'] == 'Bearer test_key'
    assert kwargs['headers']['Idempotency-Key'] == 'idemp-123'
    assert kwargs['headers']['User-Agent'] == 'URLScanOnline/1.0'
    # Attachment preserved
    assert b'"filename": "test.pdf"' in kwargs['body']

@patch('api.utils.email_helper.urllib3.PoolManager')
@patch.dict(os.environ, {"RESEND_API_KEY": "test_key"})
def test_send_email_no_idempotency(mock_pool_manager):
    mock_http = MagicMock()
    mock_pool_manager.return_value = mock_http
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_http.request.return_value = mock_resp
    
    send_email(to="test@example.com", subject="Test", html="<p>Test</p>")
    args, kwargs = mock_http.request.call_args
    assert 'Idempotency-Key' not in kwargs['headers']

@patch('api.utils.email_helper.urllib3.PoolManager')
@patch.dict(os.environ, {"RESEND_API_KEY": "test_key"})
def test_send_email_3xx(mock_pool_manager):
    mock_http = MagicMock()
    mock_pool_manager.return_value = mock_http
    mock_resp = MagicMock()
    mock_resp.status = 301
    mock_http.request.return_value = mock_resp
    
    result = send_email(to="test@example.com", subject="Test", html="<p>Test</p>")
    assert result.success is False

@patch('api.utils.email_helper.urllib3.PoolManager')
@patch.dict(os.environ, {"RESEND_API_KEY": "test_key"})
def test_send_email_400_permanent(mock_pool_manager):
    mock_http = MagicMock()
    mock_pool_manager.return_value = mock_http
    mock_resp = MagicMock()
    mock_resp.status = 400
    mock_resp.data = json.dumps({"name": "validation_error"}).encode()
    mock_http.request.return_value = mock_resp
    
    result = send_email(to="test@example.com", subject="Test", html="<p>Test</p>")
    assert result.success is False
    assert result.is_transient is False
    assert result.error_category == "provider_permanent"

@patch('api.utils.email_helper.urllib3.PoolManager')
@patch.dict(os.environ, {"RESEND_API_KEY": "test_key"})
def test_send_email_409_concurrent(mock_pool_manager):
    mock_http = MagicMock()
    mock_pool_manager.return_value = mock_http
    mock_resp = MagicMock()
    mock_resp.status = 409
    mock_resp.data = json.dumps({"name": "concurrent_idempotent_requests"}).encode()
    mock_http.request.return_value = mock_resp
    
    result = send_email(to="test@example.com", subject="Test", html="<p>Test</p>")
    assert result.success is False
    assert result.is_transient is True
    assert result.error_category == "concurrent_transient"

@patch('api.utils.email_helper.urllib3.PoolManager')
@patch.dict(os.environ, {"RESEND_API_KEY": "test_key"})
def test_send_email_409_invalid(mock_pool_manager):
    mock_http = MagicMock()
    mock_pool_manager.return_value = mock_http
    mock_resp = MagicMock()
    mock_resp.status = 409
    mock_resp.data = json.dumps({"name": "invalid_idempotent_request"}).encode()
    mock_http.request.return_value = mock_resp
    
    result = send_email(to="test@example.com", subject="Test", html="<p>Test</p>")
    assert result.success is False
    assert result.is_transient is False
    assert result.error_category == "invalid_idempotent_request"

@patch('api.utils.email_helper.urllib3.PoolManager')
@patch.dict(os.environ, {"RESEND_API_KEY": "test_key"})
def test_send_email_429_rate_limit(mock_pool_manager):
    mock_http = MagicMock()
    mock_pool_manager.return_value = mock_http
    mock_resp = MagicMock()
    mock_resp.status = 429
    mock_resp.data = json.dumps({"name": "rate_limit_exceeded"}).encode()
    mock_http.request.return_value = mock_resp
    
    result = send_email(to="test@example.com", subject="Test", html="<p>Test</p>")
    assert result.success is False
    assert result.is_transient is True
    assert result.error_category == "rate_limit_exceeded"

@patch('api.utils.email_helper.urllib3.PoolManager')
@patch.dict(os.environ, {"RESEND_API_KEY": "test_key"})
def test_send_email_429_quota(mock_pool_manager):
    mock_http = MagicMock()
    mock_pool_manager.return_value = mock_http
    mock_resp = MagicMock()
    mock_resp.status = 429
    mock_resp.data = json.dumps({"name": "daily_quota_exceeded"}).encode()
    mock_http.request.return_value = mock_resp
    
    result = send_email(to="test@example.com", subject="Test", html="<p>Test</p>")
    assert result.success is False
    assert result.is_transient is False
    assert result.error_category == "quota_exceeded"

@patch('api.utils.email_helper.urllib3.PoolManager')
@patch.dict(os.environ, {"RESEND_API_KEY": "test_key"})
def test_send_email_429_quota_monthly(mock_pool_manager):
    mock_http = MagicMock()
    mock_pool_manager.return_value = mock_http
    mock_resp = MagicMock()
    mock_resp.status = 429
    mock_resp.data = json.dumps({"name": "monthly_quota_exceeded"}).encode()
    mock_http.request.return_value = mock_resp
    
    result = send_email(to="test@example.com", subject="Test", html="<p>Test</p>")
    assert result.success is False
    assert result.is_transient is False
    assert result.error_category == "quota_exceeded"

@patch('api.utils.email_helper.urllib3.PoolManager')
@patch.dict(os.environ, {"RESEND_API_KEY": "test_key"})
def test_send_email_429_unknown(mock_pool_manager):
    mock_http = MagicMock()
    mock_pool_manager.return_value = mock_http
    mock_resp = MagicMock()
    mock_resp.status = 429
    mock_resp.data = json.dumps({"name": "some_future_throttling"}).encode()
    mock_http.request.return_value = mock_resp
    
    result = send_email(to="test@example.com", subject="Test", html="<p>Test</p>")
    assert result.success is False
    assert result.is_transient is True
    assert result.error_category == "provider_transient"

@patch('api.utils.email_helper.urllib3.PoolManager')
@patch.dict(os.environ, {"RESEND_API_KEY": "test_key"})
def test_send_email_5xx(mock_pool_manager):
    mock_http = MagicMock()
    mock_pool_manager.return_value = mock_http
    mock_resp = MagicMock()
    mock_resp.status = 502
    mock_http.request.return_value = mock_resp
    
    result = send_email(to="test@example.com", subject="Test", html="<p>Test</p>")
    assert result.success is False
    assert result.is_transient is True
    assert result.error_category == "provider_transient"

@patch('api.utils.email_helper.urllib3.PoolManager')
@patch.dict(os.environ, {"RESEND_API_KEY": "test_key"})
def test_send_email_timeout(mock_pool_manager):
    mock_http = MagicMock()
    mock_pool_manager.return_value = mock_http
    mock_http.request.side_effect = urllib3.exceptions.TimeoutError("timeout")
    
    result = send_email(to="test@example.com", subject="Test", html="<p>Test</p>")
    assert result.success is False
    assert result.is_transient is True
    assert result.error_category == "network_timeout"

@patch.dict(os.environ, clear=True)
def test_send_email_no_key():
    result = send_email(to="test@example.com", subject="Test", html="<p>Test</p>")
    assert result.success is False
    assert result.error_category == "configuration_missing"

# 2. Test PDF Generator
def test_generate_pdf_basic():
    assert MAX_EMAIL_PDF_BYTES == 10 * 1024 * 1024
    report_data = {
        "target_url": "https://example.com",
        "score": 85,
        "scan_mode": "passive",
        "findings": []
    }
    pdf_bytes = generate_pdf(report_data, scan_created_at="2023-01-01T00:00:00Z")
    assert pdf_bytes is not None
    assert len(pdf_bytes) > 0
    assert pdf_bytes.startswith(b'%PDF-')
    assert len(pdf_bytes) <= MAX_EMAIL_PDF_BYTES

def test_generate_pdf_advanced():
    report_data = {
        "target_url": "https://example.com",
        "score": 85,
        "scan_mode": "active",
        "findings": []
    }
    pdf_bytes = generate_pdf(report_data, scan_created_at="2023-01-01T00:00:00Z")
    assert pdf_bytes is not None
    assert pdf_bytes.startswith(b'%PDF-')

def test_generate_pdf_escapes_html():
    report_data = {
        "target_url": "<bad>url",
        "score": 50,
        "findings": [
            {
                "name": "Bad <script>",
                "severity": "Critical",
                "description": "& whatever",
                "remediation": "nothing"
            }
        ]
    }
    pdf_bytes = generate_pdf(report_data)
    assert pdf_bytes.startswith(b'%PDF-')

def test_resolve_scan_timestamp():
    # 1. scan_created_at supplied
    assert _resolve_scan_timestamp({}, "2024-01-01") == "2024-01-01"
    # 2. report_data.scan_start supplied
    assert _resolve_scan_timestamp({"scan_start": "2024-02-01"}, None) == "2024-02-01"
    # 3. both supplied -> scan_created_at wins
    assert _resolve_scan_timestamp({"scan_start": "2024-02-01"}, "2024-01-01") == "2024-01-01"
    # 4. neither supplied
    assert _resolve_scan_timestamp({}, None) == "N/A"

# 3. Test Migration file syntax loosely
def test_migration_file_exists():
    migrations = os.listdir("supabase/migrations")
    email_mig = [m for m in migrations if "scheduled_email_reports" in m]
    assert len(email_mig) == 1
    
    with open(f"supabase/migrations/{email_mig[0]}", 'r') as f:
        content = f.read()
        
    assert "email_report_enabled boolean NOT NULL DEFAULT false" in content
    assert "email_status text NOT NULL DEFAULT 'not_requested'" in content
    assert "ON DELETE SET NULL" in content
    assert "DROP NOT NULL" in content