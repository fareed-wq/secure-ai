from api.auth.entitlements import ScheduledEligibility
import os
os.environ['SUPABASE_URL'] = 'http://mock'
os.environ['SUPABASE_SECRET_KEY'] = 'token'

import json
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from api.index import app
from api.scheduling.email_worker import handle_scheduled_email

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_env():
    with patch.dict(os.environ, {
        "QSTASH_CURRENT_SIGNING_KEY": "test_current",
        "QSTASH_NEXT_SIGNING_KEY": "test_next",
        "APP_BASE_URL": "http://localhost:3000",
        "SUPABASE_URL": "http://mock"
    }):
        yield

# 1. TEST CREATE/API (Mocking requests.post/get for the db calls)
@patch('api.scheduling.router.requests.get')
@patch('api.scheduling.router.requests.post')
@patch('api.scheduling.router._get_qstash_client')
def test_create_schedule_email_opt_in(mock_qs, mock_post, mock_get):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = []

    mock_post.return_value.status_code = 201
    mock_post.return_value.json.return_value = [{"id": "660e8400-e29b-41d4-a716-446655440000"}]

    payload_basic = {
        "target_url": "https://example.com",
        "authorization_acknowledged": True,
        "frequency": "daily",
        "time_of_day": "09:00:00",
        "timezone": "UTC"
    }


    import api.scheduling.router
    app.dependency_overrides[api.scheduling.router.require_scheduled_scans_access] = lambda: {"sub": "880e8400-e29b-41d4-a716-446655440000"}

    resp = client.post("/api/schedules/", json=payload_basic)
    assert resp.status_code == 200
    args, kwargs = mock_post.call_args
    assert kwargs["json"]["email_report_enabled"] is False

    payload_basic["email_report_enabled"] = True
    resp = client.post("/api/schedules/", json=payload_basic)
    assert resp.status_code == 200
    args, kwargs = mock_post.call_args
    assert kwargs["json"]["email_report_enabled"] is True


@patch('api.scheduling.router.requests.get')
@patch('api.scheduling.router.requests.post')
@patch('api.scheduling.router._get_qstash_client')
def test_create_schedule_advanced_email_opt_in(mock_qs, mock_post, mock_get):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = []

    mock_post.return_value.status_code = 201
    mock_post.return_value.json.return_value = [{"id": "660e8400-e29b-41d4-a716-446655440000"}]

    payload_advanced = {
        "target_url": "https://example.com",
        "authorization_acknowledged": True,
        "advanced_authorization_acknowledged": True,
        "scan_mode": "active",
        "email_report_enabled": True,
        "frequency": "daily",
        "time_of_day": "09:00:00",
        "timezone": "UTC"
    }


    import api.scheduling.router
    app.dependency_overrides[api.scheduling.router.require_scheduled_scans_access] = lambda: {"sub": "880e8400-e29b-41d4-a716-446655440000"}

    try:
        resp = client.post("/api/schedules/", json=payload_advanced)
        assert resp.status_code == 200
        args, kwargs = mock_post.call_args
        assert kwargs["json"]["email_report_enabled"] is True
        assert kwargs["json"]["scan_mode"] == "active"

        assert "email" not in kwargs["json"]
        assert "recipient" not in kwargs["json"]
        assert "cc" not in kwargs["json"]
        assert "bcc" not in kwargs["json"]
    finally:
        app.dependency_overrides.clear()


@patch('api.scheduling.worker.get_next_run_at')
@patch('api.scheduling.worker.requests.get')
@patch('api.scheduling.worker.requests.post')
@patch('api.scheduling.worker.requests.patch')
@patch('api.scheduling.worker.scan_url')
@patch('api.scheduling.worker.is_scheduled_scans_eligible', return_value=ScheduledEligibility.ELIGIBLE)
@patch('api.scheduling.worker.QSTASH_CURRENT_SIGNING_KEY', 'x')
@patch('api.scheduling.router.QSTASH_TOKEN', 'token')
@patch('api.scheduling.router.APP_BASE_URL', 'http://mock')
@patch('api.scheduling.worker.QSTASH_NEXT_SIGNING_KEY', 'x')
def test_scan_worker_publish_arguments(mock_elig, mock_scan, mock_patch, mock_post, mock_get, mock_next_run):
    from datetime import datetime
    mock_next_run.return_value = datetime.utcnow()
    mock_scan.return_value = {"score": 90, "url": "https://example.com"}

    def mock_get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "scan_schedules" in url:
            resp.json.return_value = [{
                "id": "660e8400-e29b-41d4-a716-446655440000",
                "user_id": "880e8400-e29b-41d4-a716-446655440000",
                "target_url": "https://example.com",
                "is_enabled": True,
                "email_report_enabled": True,
                "frequency": "daily",
                "time_of_day": "09:00:00",
                "timezone": "UTC"
            }]
        return resp
    mock_get.side_effect = mock_get_side_effect

    def mock_post_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 201
        if "scheduled_scan_runs" in url:
            resp.json.return_value = [{"id": "550e8400-e29b-41d4-a716-446655440000"}]
        elif "scans" in url:
            resp.json.return_value = [{"id": "770e8400-e29b-41d4-a716-446655440000"}]
        return resp
    mock_post.side_effect = mock_post_side_effect
    mock_patch.return_value.status_code = 200
    mock_patch.return_value.json.return_value = [{'id': '660e8400-e29b-41d4-a716-446655440000'}]

    import api.scheduling.worker as worker_module
    old_base_url = worker_module.APP_BASE_URL
    worker_module.APP_BASE_URL = "http://mock"
    try:
        with patch('qstash.Receiver.verify'):
            with patch('api.scheduling.router.QStashClient') as mock_qs_cls:
                mock_qs_client = MagicMock()
                mock_qs_cls.return_value = mock_qs_client

                resp = client.post("/api/internal/scheduled-scan",
                                   json={"schedule_id": "660e8400-e29b-41d4-a716-446655440000"},
                                   headers={"Upstash-Signature": "valid", "Upstash-Message-Id": "msg-123"})

                assert resp.status_code == 200
                mock_qs_client.message.publish_json.assert_called_once_with(
                    url="http://mock/api/internal/scheduled-report-email",
                    body={"run_id": "550e8400-e29b-41d4-a716-446655440000"},
                    retries=3
                )

                args, kwargs = mock_qs_client.message.publish_json.call_args
                assert set(kwargs["body"].keys()) == {"run_id"}
    finally:
        worker_module.APP_BASE_URL = old_base_url


@patch('api.scheduling.worker.get_next_run_at')
@patch('api.scheduling.worker.requests.get')
@patch('api.scheduling.worker.requests.post')
@patch('api.scheduling.worker.requests.patch')
@patch('api.scheduling.worker.scan_url')
@patch('api.scheduling.worker.is_scheduled_scans_eligible', return_value=ScheduledEligibility.ELIGIBLE)
@patch('api.scheduling.worker.QSTASH_CURRENT_SIGNING_KEY', 'x')
@patch('api.scheduling.router.QSTASH_TOKEN', 'token')
@patch('api.scheduling.router.APP_BASE_URL', 'http://mock')
@patch('api.scheduling.worker.QSTASH_NEXT_SIGNING_KEY', 'x')
def test_scan_worker_snapshot_opt_in(mock_elig, mock_scan, mock_patch, mock_post, mock_get, mock_next_run):

    from datetime import datetime
    mock_next_run.return_value = datetime.utcnow()
    mock_scan.return_value = {"score": 90, "url": "https://example.com"}

    def mock_get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "scan_schedules" in url:
            resp.json.return_value = [{
                "id": "660e8400-e29b-41d4-a716-446655440000",
                "user_id": "880e8400-e29b-41d4-a716-446655440000",
                "target_url": "https://example.com",
                "is_enabled": True,
                "email_report_enabled": True,
                "frequency": "daily",
                "time_of_day": "09:00:00",
                "timezone": "UTC"
            }]
        return resp
    mock_get.side_effect = mock_get_side_effect

    def mock_post_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 201
        if "scheduled_scan_runs" in url:
            resp.json.return_value = [{"id": "550e8400-e29b-41d4-a716-446655440000"}]
        elif "scans" in url:
            resp.json.return_value = [{"id": "770e8400-e29b-41d4-a716-446655440000"}]
        return resp
    mock_post.side_effect = mock_post_side_effect
    mock_patch.return_value.status_code = 200
    mock_patch.return_value.json.return_value = [{'id': '660e8400-e29b-41d4-a716-446655440000'}]

    with patch('qstash.Receiver.verify'):
        with patch('api.scheduling.router.QStashClient') as mock_qs_cls:
            mock_qs_client = MagicMock()
            mock_qs_cls.return_value = mock_qs_client

            resp = client.post("/api/internal/scheduled-scan",
                               json={"schedule_id": "660e8400-e29b-41d4-a716-446655440000"},
                               headers={"Upstash-Signature": "valid", "Upstash-Message-Id": "msg-123"})

            assert resp.status_code == 200
            mock_qs_client.message.publish_json.assert_called_once()

            patch_calls = mock_patch.call_args_list
            run_patch = None
            for call in patch_calls:
                if "scheduled_scan_runs" in call[0][0]:
                    run_patch = call[1]["json"]
            assert run_patch["email_status"] == "pending"

@patch('api.scheduling.worker.get_next_run_at')
@patch('api.scheduling.worker.requests.get')
@patch('api.scheduling.worker.requests.post')
@patch('api.scheduling.worker.requests.patch')
@patch('api.scheduling.worker.scan_url')
@patch('api.scheduling.worker.is_scheduled_scans_eligible', return_value=ScheduledEligibility.ELIGIBLE)
@patch('api.scheduling.worker.QSTASH_CURRENT_SIGNING_KEY', 'x')
@patch('api.scheduling.router.QSTASH_TOKEN', 'token')
@patch('api.scheduling.router.APP_BASE_URL', 'http://mock')
@patch('api.scheduling.worker.QSTASH_NEXT_SIGNING_KEY', 'x')
def test_scan_worker_snapshot_opt_out(mock_elig, mock_scan, mock_patch, mock_post, mock_get, mock_next_run):

    from datetime import datetime
    mock_next_run.return_value = datetime.utcnow()
    mock_scan.return_value = {"score": 90, "url": "https://example.com"}

    def mock_get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "scan_schedules" in url:
            resp.json.return_value = [{
                "id": "660e8400-e29b-41d4-a716-446655440000",
                "user_id": "880e8400-e29b-41d4-a716-446655440000",
                "target_url": "https://example.com",
                "is_enabled": True,
                "email_report_enabled": False,
                "frequency": "daily",
                "time_of_day": "09:00:00",
                "timezone": "UTC"
            }]
        return resp
    mock_get.side_effect = mock_get_side_effect

    def mock_post_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 201
        if "scheduled_scan_runs" in url:
            resp.json.return_value = [{"id": "550e8400-e29b-41d4-a716-446655440000"}]
        elif "scans" in url:
            resp.json.return_value = [{"id": "770e8400-e29b-41d4-a716-446655440000"}]
        return resp
    mock_post.side_effect = mock_post_side_effect
    mock_patch.return_value.status_code = 200
    mock_patch.return_value.json.return_value = [{'id': '660e8400-e29b-41d4-a716-446655440000'}]

    with patch('qstash.Receiver.verify'):
        with patch('api.scheduling.router.QStashClient') as mock_qs_cls:
            mock_qs_client = MagicMock()
            mock_qs_cls.return_value = mock_qs_client

            resp = client.post("/api/internal/scheduled-scan",
                               json={"schedule_id": "660e8400-e29b-41d4-a716-446655440000"},
                               headers={"Upstash-Signature": "valid", "Upstash-Message-Id": "msg-123"})

            assert resp.status_code == 200
            mock_qs_client.message.publish_json.assert_not_called()

            patch_calls = mock_patch.call_args_list
            run_patch = None
            for call in patch_calls:
                if "scheduled_scan_runs" in call[0][0]:
                    run_patch = call[1]["json"]
            assert run_patch.get('email_status') == "not_requested"


@patch('api.scheduling.email_worker.generate_pdf')
@patch('api.scheduling.email_worker.send_email')
def test_email_worker_success(mock_send_email, mock_generate_pdf):
    from api.utils.email_helper import EmailResult
    import base64
    mock_send_email.return_value = EmailResult(success=True, status_code=200)
    mock_generate_pdf.return_value = b"%PDF-1.4"

    def mock_get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "auth/v1/admin/users" in url:
            resp.json.return_value = {
                "email": "test@example.com",
                "email_confirmed_at": "2023-01-01",
                "banned_until": ""
            }
        elif "scheduled_scan_runs" in url:
            resp.json.return_value = [{
                "user_id": "880e8400-e29b-41d4-a716-446655440000",
                "scan_id": "770e8400-e29b-41d4-a716-446655440000",
                "email_status": "pending"
            }]
        elif "scans" in url:
            resp.json.return_value = [{
                "user_id": "880e8400-e29b-41d4-a716-446655440000",
                "target_url": "https://example.com",
                "created_at": "2023-01-01T00:00:00Z",
                "report_data": {"findings": []}
            }]
        return resp

    with patch('api.scheduling.email_worker.requests.get', side_effect=mock_get_side_effect):
        with patch('api.scheduling.email_worker.requests.patch') as mock_patch:
            mock_patch.return_value.status_code = 200
            mock_patch.return_value.json.return_value = [{"id": "550e8400-e29b-41d4-a716-446655440000"}]
            with patch('qstash.Receiver.verify'):
                resp = client.post("/api/internal/scheduled-report-email",
                                   json={"run_id": "550e8400-e29b-41d4-a716-446655440000"},
                                   headers={"Upstash-Signature": "valid"})

                assert resp.status_code == 200
                assert resp.json()["status"] == "sent"

                # Check assertions
                mock_generate_pdf.assert_called_once_with({"findings": []}, scan_created_at="2023-01-01T00:00:00Z")
                mock_send_email.assert_called_once()
                args, kwargs = mock_send_email.call_args
                assert kwargs["to"] == "test@example.com"
                assert kwargs["from_email"] == "URLScanOnline Reports <contact@urlscanonline.com>"
                assert kwargs["idempotency_key"] == "scheduled-report-550e8400-e29b-41d4-a716-446655440000"

                atts = kwargs["attachments"]
                assert len(atts) == 1
                assert atts[0]["content"] == base64.b64encode(b"%PDF-1.4").decode('utf-8')
                assert atts[0]["filename"].endswith(".pdf")
                assert not any(c in atts[0]["filename"] for c in [":", "/", "?", "&"])

@patch('qstash.Receiver.verify')
def test_email_worker_bad_signature(mock_verify):
    mock_verify.side_effect = Exception('bad signature')
    resp = client.post("/api/internal/scheduled-report-email",
                       json={"run_id": "550e8400-e29b-41d4-a716-446655440000"},
                       headers={"Upstash-Signature": "invalid"})
    assert resp.status_code == 401




def test_email_worker_missing_run_id():
    resp = client.post("/api/internal/scheduled-report-email", json={}, headers={"Upstash-Signature": "valid"})
    assert resp.status_code == 400
    assert resp.json()['error'] == 'missing_run_id'

def test_email_worker_malformed_run_id():
    resp = client.post("/api/internal/scheduled-report-email", json={"run_id": "not-a-uuid"}, headers={"Upstash-Signature": "valid"})
    assert resp.status_code == 400
    assert resp.json()['error'] == 'invalid_run_id'

@patch('qstash.Receiver.verify')
def test_email_worker_missing_run_id(mock_verify):
    resp = client.post("/api/internal/scheduled-report-email", json={}, headers={"Upstash-Signature": "valid"})
    assert resp.status_code == 400
    assert resp.json()['error'] == 'missing_run_id'

@patch('qstash.Receiver.verify')
def test_email_worker_malformed_run_id(mock_verify):
    resp = client.post("/api/internal/scheduled-report-email", json={"run_id": "not-a-uuid"}, headers={"Upstash-Signature": "valid"})
    assert resp.status_code == 400
    assert resp.json()['error'] == 'invalid_run_id'


@patch('api.scheduling.worker.get_next_run_at')
@patch('api.scheduling.worker.requests.get')
@patch('api.scheduling.worker.requests.post')
@patch('api.scheduling.worker.requests.patch')
@patch('api.scheduling.worker.scan_url')
@patch('api.scheduling.worker.is_scheduled_scans_eligible', return_value=ScheduledEligibility.ELIGIBLE)
@patch('api.scheduling.worker.QSTASH_CURRENT_SIGNING_KEY', 'x')
@patch('api.scheduling.router.QSTASH_TOKEN', 'token')
@patch('api.scheduling.router.APP_BASE_URL', 'http://mock')
@patch('api.scheduling.worker.QSTASH_NEXT_SIGNING_KEY', 'x')
def test_scan_worker_enqueue_failure(mock_elig, mock_scan, mock_patch, mock_post, mock_get, mock_next_run):

    from datetime import datetime
    mock_next_run.return_value = datetime.utcnow()
    mock_scan.return_value = {"score": 90, "url": "https://example.com"}

    def mock_get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "scan_schedules" in url:
            resp.json.return_value = [{
                "id": "660e8400-e29b-41d4-a716-446655440000",
                "user_id": "880e8400-e29b-41d4-a716-446655440000",
                "target_url": "https://example.com",
                "is_enabled": True,
                "email_report_enabled": True,
                "frequency": "daily",
                "time_of_day": "09:00:00",
                "timezone": "UTC"
            }]
        return resp
    mock_get.side_effect = mock_get_side_effect

    def mock_post_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 201
        if "scheduled_scan_runs" in url:
            resp.json.return_value = [{"id": "550e8400-e29b-41d4-a716-446655440000"}]
        elif "scans" in url:
            resp.json.return_value = [{"id": "770e8400-e29b-41d4-a716-446655440000"}]
        return resp
    mock_post.side_effect = mock_post_side_effect
    mock_patch.return_value.status_code = 200
    mock_patch.return_value.json.return_value = [{'id': '660e8400-e29b-41d4-a716-446655440000'}]
    with patch('qstash.Receiver.verify'):
        with patch('api.scheduling.router.QStashClient') as mock_qs_cls:
            mock_qs_client = MagicMock()
            mock_qs_client.message.publish_json.side_effect = Exception("network error")
            mock_qs_cls.return_value = mock_qs_client

            resp = client.post("/api/internal/scheduled-scan",
                               json={"schedule_id": "660e8400-e29b-41d4-a716-446655440000"},
                               headers={"Upstash-Signature": "valid", "Upstash-Message-Id": "msg-123"})

            assert resp.status_code == 200

            patch_calls = mock_patch.call_args_list
            run_patch = None
            for call in patch_calls:
                if "scheduled_scan_runs" in call[0][0]:
                    run_patch = call[1]["json"]
            assert run_patch["email_status"] == "failed"
            assert run_patch["email_error_code"] == "enqueue_failed"
            assert run_patch["email_lease_until"] is None
            assert run_patch["status"] == "completed"








from unittest.mock import patch
@patch('qstash.Receiver.verify')
def test_email_worker_invalid_type_run_id(mock_verify):
    from fastapi.testclient import TestClient
    from api.index import app
    client = TestClient(app)
    resp = client.post("/api/internal/scheduled-report-email", json={"run_id": {"bad": "value"}}, headers={"Upstash-Signature": "valid"})
    assert resp.status_code == 400

def test_email_worker_missing_signature():
    from fastapi.testclient import TestClient
    from api.index import app
    client = TestClient(app)
    resp = client.post("/api/internal/scheduled-report-email", json={"run_id": "550e8400-e29b-41d4-a716-446655440000"})
    assert resp.status_code == 400

@patch('api.scheduling.email_worker.generate_pdf')
@patch('api.scheduling.email_worker.send_email')
def test_email_worker_active_lease(mock_send_email, mock_generate_pdf):
    def mock_get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "auth/v1/admin/users" in url:
            resp.json.return_value = {"email": "test@example.com", "email_confirmed_at": "2023-01-01"}
        elif "scheduled_scan_runs" in url:
            resp.json.return_value = [{"user_id": "880e8400-e29b-41d4-a716-446655440000", "scan_id": "770e8400-e29b-41d4-a716-446655440000", "email_status": "pending"}]
        elif "scans" in url:
            resp.json.return_value = [{"user_id": "880e8400-e29b-41d4-a716-446655440000", "target_url": "https://example.com", "created_at": "2023-01-01T00:00:00Z", "report_data": {"findings": []}}]
        return resp

    with patch('api.scheduling.email_worker.requests.get', side_effect=mock_get_side_effect):
        with patch('api.scheduling.email_worker.requests.patch') as mock_patch:
            # Conditional patch returns [] simulating active lease
            mock_patch.return_value.status_code = 200
            mock_patch.return_value.json.return_value = []
            with patch('qstash.Receiver.verify'):
                resp = client.post("/api/internal/scheduled-report-email",
                                   json={"run_id": "550e8400-e29b-41d4-a716-446655440000"},
                                   headers={"Upstash-Signature": "valid"})

                assert resp.status_code == 503
                assert resp.json().get("reason") == "lease_active"
                mock_send_email.assert_not_called()
                mock_generate_pdf.assert_not_called()

import pytest
@pytest.mark.parametrize("terminal_state", ["sent", "failed", "not_requested"])
@patch('api.scheduling.email_worker.generate_pdf')
@patch('api.scheduling.email_worker.send_email')
def test_email_worker_terminal_states(mock_send_email, mock_generate_pdf, terminal_state):
    def mock_get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "scheduled_scan_runs" in url:
            resp.json.return_value = [{"user_id": "880e8400-e29b-41d4-a716-446655440000", "scan_id": "770e8400-e29b-41d4-a716-446655440000", "email_status": terminal_state}]
        return resp

    with patch('api.scheduling.email_worker.requests.get', side_effect=mock_get_side_effect):
        with patch('qstash.Receiver.verify'):
            resp = client.post("/api/internal/scheduled-report-email",
                               json={"run_id": "550e8400-e29b-41d4-a716-446655440000"},
                               headers={"Upstash-Signature": "valid"})

            assert resp.status_code == 200
            assert resp.json().get("status") == "skipped"
            mock_send_email.assert_not_called()
            mock_generate_pdf.assert_not_called()

@patch('api.scheduling.email_worker.generate_pdf')
@patch('api.scheduling.email_worker.send_email')
def test_email_worker_stale_lease(mock_send_email, mock_generate_pdf):
    from api.utils.email_helper import EmailResult
    mock_send_email.return_value = EmailResult(success=True, status_code=200)
    mock_generate_pdf.return_value = b"%PDF-1.4"
    def mock_get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "auth/v1/admin/users" in url:
            resp.json.return_value = {"email": "test@example.com", "email_confirmed_at": "2023-01-01"}
        elif "scheduled_scan_runs" in url:
            # Simulate stale lease
            resp.json.return_value = [{"user_id": "880e8400-e29b-41d4-a716-446655440000", "scan_id": "770e8400-e29b-41d4-a716-446655440000", "email_status": "sending", "email_lease_until": "2023-01-01T00:00:00Z"}]
        elif "scans" in url:
            resp.json.return_value = [{"user_id": "880e8400-e29b-41d4-a716-446655440000", "target_url": "https://example.com", "created_at": "2023-01-01T00:00:00Z", "report_data": {"findings": []}}]
        return resp

    with patch('api.scheduling.email_worker.requests.get', side_effect=mock_get_side_effect):
        with patch('api.scheduling.email_worker.requests.patch') as mock_patch:
            mock_patch.return_value.status_code = 200
            mock_patch.return_value.json.return_value = [{"id": "550e8400-e29b-41d4-a716-446655440000"}]
            with patch('qstash.Receiver.verify'):
                resp = client.post("/api/internal/scheduled-report-email",
                                   json={"run_id": "550e8400-e29b-41d4-a716-446655440000"},
                                   headers={"Upstash-Signature": "valid"})
                assert resp.status_code == 200
                assert resp.json().get("status") == "sent"

# 5. OWNERSHIP TEST
@patch('api.scheduling.email_worker.generate_pdf')
@patch('api.scheduling.email_worker.send_email')
def test_email_worker_user_mismatch_blocks(mock_send_email, mock_generate_pdf):
    def mock_get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "auth/v1/admin/users" in url:
            resp.json.return_value = {"email": "test@example.com", "email_confirmed_at": "2023-01-01"}
        elif "scheduled_scan_runs" in url:
            resp.json.return_value = [{"user_id": "USER_A", "scan_id": "770e8400-e29b-41d4-a716-446655440000", "email_status": "pending"}]
        elif "scans" in url:
            resp.json.return_value = [{"user_id": "USER_B", "target_url": "https://example.com", "created_at": "2023-01-01T00:00:00Z", "report_data": {"findings": []}}]
        return resp

    with patch('api.scheduling.email_worker.requests.get', side_effect=mock_get_side_effect):
        with patch('api.scheduling.email_worker.requests.patch') as mock_patch:
            mock_patch.return_value.status_code = 200
            mock_patch.return_value.json.return_value = [{"id": "550e8400-e29b-41d4-a716-446655440000"}]
            with patch('qstash.Receiver.verify'):
                resp = client.post("/api/internal/scheduled-report-email",
                                   json={"run_id": "550e8400-e29b-41d4-a716-446655440000"},
                                   headers={"Upstash-Signature": "valid"})
                assert resp.status_code == 200
                mock_send_email.assert_not_called()
                mock_generate_pdf.assert_not_called()

@pytest.mark.parametrize("scenario,auth_code,auth_body,expected_status,expected_db_status", [
    ("404", 404, {}, 200, "failed"),
    ("unverified", 200, {"email": "test@example.com", "email_confirmed_at": None}, 200, "failed"),
    ("500", 500, {}, 503, "pending"),
    ("429", 429, {}, 503, "pending"),
    ("network", "network", {}, 503, "pending"),
])
@patch('api.scheduling.email_worker.generate_pdf')
@patch('api.scheduling.email_worker.send_email')
def test_email_worker_auth_lookup(mock_send_email, mock_generate_pdf, scenario, auth_code, auth_body, expected_status, expected_db_status):
    def mock_get_side_effect(url, **kwargs):
        if "auth/v1/admin/users" in url:
            if auth_code == "network":
                raise Exception("Network error")
            resp = MagicMock()
            resp.status_code = auth_code
            resp.json.return_value = auth_body
            return resp
        resp = MagicMock()
        resp.status_code = 200
        if "scheduled_scan_runs" in url:
            resp.json.return_value = [{"user_id": "880e8400-e29b-41d4-a716-446655440000", "scan_id": "770e8400-e29b-41d4-a716-446655440000", "email_status": "pending"}]
        elif "scans" in url:
            resp.json.return_value = [{"user_id": "880e8400-e29b-41d4-a716-446655440000", "target_url": "https://example.com", "created_at": "2023-01-01T00:00:00Z", "report_data": {"findings": []}}]
        return resp

    with patch('api.scheduling.email_worker.requests.get', side_effect=mock_get_side_effect):
        with patch('api.scheduling.email_worker.requests.patch') as mock_patch:
            mock_patch.return_value.status_code = 200
            mock_patch.return_value.json.return_value = [{"id": "550e8400-e29b-41d4-a716-446655440000"}]
            with patch('qstash.Receiver.verify'):
                resp = client.post("/api/internal/scheduled-report-email",
                                   json={"run_id": "550e8400-e29b-41d4-a716-446655440000"},
                                   headers={"Upstash-Signature": "valid"})
                assert resp.status_code == expected_status
                mock_send_email.assert_not_called()

                if expected_db_status == "failed":
                    patch_calls = mock_patch.call_args_list
                    failed_call = next((c for c in patch_calls if c[1]["json"].get("email_status") == "failed"), None)
                    assert failed_call is not None

@pytest.mark.parametrize("fail_type", ["exception", "too_large"])
@patch('api.scheduling.email_worker.generate_pdf')
@patch('api.scheduling.email_worker.send_email')
def test_email_worker_pdf_failures(mock_send_email, mock_generate_pdf, fail_type):
    if fail_type == "exception":
        mock_generate_pdf.side_effect = Exception("PDF error")
    else:
        from api.scheduling.email_worker import MAX_EMAIL_PDF_BYTES
        mock_generate_pdf.return_value = b"x" * (MAX_EMAIL_PDF_BYTES + 1)

    def mock_get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "auth/v1/admin/users" in url:
            resp.json.return_value = {"email": "test@example.com", "email_confirmed_at": "2023-01-01"}
        elif "scheduled_scan_runs" in url:
            resp.json.return_value = [{"user_id": "880e8400-e29b-41d4-a716-446655440000", "scan_id": "770e8400-e29b-41d4-a716-446655440000", "email_status": "pending"}]
        elif "scans" in url:
            resp.json.return_value = [{"user_id": "880e8400-e29b-41d4-a716-446655440000", "target_url": "https://example.com", "created_at": "2023-01-01T00:00:00Z", "report_data": {"findings": []}}]
        return resp

    with patch('api.scheduling.email_worker.requests.get', side_effect=mock_get_side_effect):
        with patch('api.scheduling.email_worker.requests.patch') as mock_patch:
            mock_patch.return_value.status_code = 200
            mock_patch.return_value.json.return_value = [{"id": "550e8400-e29b-41d4-a716-446655440000"}]
            with patch('qstash.Receiver.verify'):
                resp = client.post("/api/internal/scheduled-report-email",
                                   json={"run_id": "550e8400-e29b-41d4-a716-446655440000"},
                                   headers={"Upstash-Signature": "valid"})
                assert resp.status_code == 200
                mock_send_email.assert_not_called()
                patch_calls = mock_patch.call_args_list
                failed_call = next((c for c in patch_calls if c[1]["json"].get("email_status") == "failed"), None)
                assert failed_call is not None
                if fail_type == "exception":
                    assert failed_call[1]["json"]["email_error_code"] == "pdf_generation_failed"
                else:
                    assert failed_call[1]["json"]["email_error_code"] == "pdf_too_large"

@pytest.mark.parametrize("transient,expected_status,expected_db_status", [
    (False, 200, "failed"),
    (True, 503, "pending")
])
@patch('api.scheduling.email_worker.generate_pdf')
@patch('api.scheduling.email_worker.send_email')
def test_email_worker_provider_failure(mock_send_email, mock_generate_pdf, transient, expected_status, expected_db_status):
    from api.utils.email_helper import EmailResult
    mock_send_email.return_value = EmailResult(success=False, is_transient=transient, error_category="err")
    mock_generate_pdf.return_value = b"%PDF-1.4"

    def mock_get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "auth/v1/admin/users" in url:
            resp.json.return_value = {"email": "test@example.com", "email_confirmed_at": "2023-01-01"}
        elif "scheduled_scan_runs" in url:
            resp.json.return_value = [{"user_id": "880e8400-e29b-41d4-a716-446655440000", "scan_id": "770e8400-e29b-41d4-a716-446655440000", "email_status": "pending"}]
        elif "scans" in url:
            resp.json.return_value = [{"user_id": "880e8400-e29b-41d4-a716-446655440000", "target_url": "https://example.com", "created_at": "2023-01-01T00:00:00Z", "report_data": {"findings": []}}]
        return resp

    with patch('api.scheduling.email_worker.requests.get', side_effect=mock_get_side_effect):
        with patch('api.scheduling.email_worker.requests.patch') as mock_patch:
            mock_patch.return_value.status_code = 200
            mock_patch.return_value.json.return_value = [{"id": "550e8400-e29b-41d4-a716-446655440000"}]
            with patch('qstash.Receiver.verify'):
                resp = client.post("/api/internal/scheduled-report-email",
                                   json={"run_id": "550e8400-e29b-41d4-a716-446655440000"},
                                   headers={"Upstash-Signature": "valid"})
                assert resp.status_code == expected_status
                patch_calls = mock_patch.call_args_list
                status_call = next((c for c in patch_calls if c[1]["json"].get("email_status") == expected_db_status), None)
                assert status_call is not None



@patch('api.scheduling.email_worker.generate_pdf')
@patch('api.scheduling.email_worker.send_email')
def test_email_worker_explicit_projection(mock_send_email, mock_generate_pdf):
    from api.utils.email_helper import EmailResult
    mock_send_email.return_value = EmailResult(success=True, status_code=200)
    mock_generate_pdf.return_value = b"%PDF-1.4"

    def mock_get_side_effect(url, **kwargs):
        if "scheduled_scan_runs" in url:
            assert "select=id,user_id,scan_id,schedule_id,status,email_status,email_lease_until" in url
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = [{
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "user_id": "880e8400-e29b-41d4-a716-446655440000",
                "scan_id": "770e8400-e29b-41d4-a716-446655440000",
                "schedule_id": "660e8400-e29b-41d4-a716-446655440000",
                "status": "completed",
                "email_status": "pending",
                "email_lease_until": None
            }]
            return resp
        elif "auth/v1/admin/users" in url:
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"email": "test@example.com", "email_confirmed_at": "2023-01-01"}
            return resp
        elif "scans" in url:
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = [{"user_id": "880e8400-e29b-41d4-a716-446655440000", "target_url": "https://example.com", "created_at": "2023-01-01T00:00:00Z", "report_data": {"findings": []}}]
            return resp
        resp = MagicMock()
        resp.status_code = 200
        return resp

    with patch('api.scheduling.email_worker.requests.get', side_effect=mock_get_side_effect):
        with patch('api.scheduling.email_worker.requests.patch') as mock_patch:
            mock_patch.return_value.status_code = 200
            mock_patch.return_value.json.return_value = [{"id": "550e8400-e29b-41d4-a716-446655440000"}]
            with patch('qstash.Receiver.verify'):
                resp = client.post("/api/internal/scheduled-report-email",
                                   json={"run_id": "550e8400-e29b-41d4-a716-446655440000"},
                                   headers={"Upstash-Signature": "valid"})

                assert resp.status_code == 200
                assert resp.json().get("status") == "sent"


@patch('api.scheduling.email_worker.generate_pdf')
@patch('api.scheduling.email_worker.send_email')
@pytest.mark.parametrize("status_code, response_json, expected_status, expected_reason", [
    (400, {"error": "bad request"}, 503, "db_claim_error"),
    (500, {"error": "internal error"}, 503, "db_claim_error"),
    (200, [], 503, "lease_active"),
    (200, [{"id": "550e8400-e29b-41d4-a716-446655440000"}], 200, "sent")
])
def test_email_worker_claim_patch_responses(mock_send_email, mock_generate_pdf, status_code, response_json, expected_status, expected_reason):
    from api.utils.email_helper import EmailResult
    mock_send_email.return_value = EmailResult(success=True, status_code=200)
    mock_generate_pdf.return_value = b"%PDF-1.4"

    def mock_get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "auth/v1/admin/users" in url:
            resp.json.return_value = {"email": "test@example.com", "email_confirmed_at": "2023-01-01"}
        elif "scheduled_scan_runs" in url:
            resp.json.return_value = [{
                "user_id": "880e8400-e29b-41d4-a716-446655440000",
                "scan_id": "770e8400-e29b-41d4-a716-446655440000",
                "email_status": "pending"
            }]
        elif "scans" in url:
            resp.json.return_value = [{
                "user_id": "880e8400-e29b-41d4-a716-446655440000",
                "target_url": "https://example.com",
                "created_at": "2023-01-01T00:00:00Z",
                "report_data": {"findings": []}
            }]
        return resp

    with patch('api.scheduling.email_worker.requests.get', side_effect=mock_get_side_effect):
        with patch('api.scheduling.email_worker.requests.patch') as mock_patch:
            mock_patch.return_value.status_code = status_code
            mock_patch.return_value.json.return_value = response_json
            with patch('qstash.Receiver.verify'):
                resp = client.post("/api/internal/scheduled-report-email",
                                   json={"run_id": "550e8400-e29b-41d4-a716-446655440000"},
                                   headers={"Upstash-Signature": "valid"})

                assert resp.status_code == expected_status
                if expected_status == 503:
                    assert resp.json()["reason"] == expected_reason
                else:
                    assert resp.json()["status"] == expected_reason

@patch('api.scheduling.email_worker.requests.patch')
@patch('api.scheduling.email_worker.requests.get')
def test_email_worker_claim_network_exception(mock_get, mock_patch):
    def mock_get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "scans" in url:
            resp.json.return_value = [{
                "user_id": "880e8400-e29b-41d4-a716-446655440000",
                "target_url": "https://example.com",
                "created_at": "2023-01-01T00:00:00Z",
                "report_data": {"findings": []}
            }]
        else:
            resp.json.return_value = [{
                "user_id": "880e8400-e29b-41d4-a716-446655440000",
                "scan_id": "770e8400-e29b-41d4-a716-446655440000",
                "email_status": "pending"
            }]
        return resp
    mock_get.side_effect = mock_get_side_effect

    mock_patch.side_effect = Exception("Network timeout")

    with patch('qstash.Receiver.verify'):
        resp = client.post("/api/internal/scheduled-report-email",
                           json={"run_id": "550e8400-e29b-41d4-a716-446655440000"},
                           headers={"Upstash-Signature": "valid"})

        assert resp.status_code == 503
        assert resp.json()["reason"] == "db_claim_exception"

# ==========================
# RUN LOOKUP REGRESSION TESTS
# ==========================

@patch('api.scheduling.email_worker.requests.get')
@patch('api.scheduling.email_worker.requests.patch')
@patch('api.scheduling.email_worker.generate_pdf')
@patch('api.scheduling.email_worker.send_email')
def test_email_worker_run_lookup_empty_retry(mock_send, mock_pdf, mock_patch, mock_get):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = []

    with patch('qstash.Receiver.verify'):
        resp = client.post("/api/internal/scheduled-report-email", json={"run_id": "550e8400-e29b-41d4-a716-446655440000"}, headers={"Upstash-Signature": "sig"})

    assert resp.status_code == 503
    assert resp.json()["reason"] == "run_lookup_pending"
    mock_pdf.assert_not_called()
    mock_send.assert_not_called()
    mock_patch.assert_not_called()

    # Assert exact URL called
    called_url = mock_get.call_args[0][0]
    assert "rest/v1/scheduled_scan_runs?id=eq.550e8400-e29b-41d4-a716-446655440000&select=id,user_id,scan_id,schedule_id,status,email_status,email_lease_until" in called_url


@patch('api.scheduling.email_worker.requests.get')
@patch('api.scheduling.email_worker.requests.patch')
@patch('api.scheduling.email_worker.generate_pdf')
@patch('api.scheduling.email_worker.send_email')
def test_email_worker_run_lookup_500_retry(mock_send, mock_pdf, mock_patch, mock_get):
    mock_get.return_value.status_code = 500

    with patch('qstash.Receiver.verify'):
        resp = client.post("/api/internal/scheduled-report-email", json={"run_id": "550e8400-e29b-41d4-a716-446655440000"}, headers={"Upstash-Signature": "sig"})

    assert resp.status_code == 503
    assert resp.json()["reason"] == "run_lookup_transient"
    mock_pdf.assert_not_called()
    mock_send.assert_not_called()
    mock_patch.assert_not_called()


@patch('api.scheduling.email_worker.requests.get')
@patch('api.scheduling.email_worker.requests.patch')
@patch('api.scheduling.email_worker.generate_pdf')
@patch('api.scheduling.email_worker.send_email')
def test_email_worker_run_lookup_429_retry(mock_send, mock_pdf, mock_patch, mock_get):
    mock_get.return_value.status_code = 429

    with patch('qstash.Receiver.verify'):
        resp = client.post("/api/internal/scheduled-report-email", json={"run_id": "550e8400-e29b-41d4-a716-446655440000"}, headers={"Upstash-Signature": "sig"})

    assert resp.status_code == 503
    assert resp.json()["reason"] == "run_lookup_transient"
    mock_pdf.assert_not_called()
    mock_send.assert_not_called()
    mock_patch.assert_not_called()


@patch('api.scheduling.email_worker.requests.get')
@patch('api.scheduling.email_worker.requests.patch')
@patch('api.scheduling.email_worker.generate_pdf')
@patch('api.scheduling.email_worker.send_email')
def test_email_worker_run_lookup_network_retry(mock_send, mock_pdf, mock_patch, mock_get):
    mock_get.side_effect = Exception("network failure")

    with patch('qstash.Receiver.verify'):
        resp = client.post("/api/internal/scheduled-report-email", json={"run_id": "550e8400-e29b-41d4-a716-446655440000"}, headers={"Upstash-Signature": "sig"})

    assert resp.status_code == 503
    assert resp.json()["reason"] == "run_lookup_transient"
    mock_pdf.assert_not_called()
    mock_send.assert_not_called()
    mock_patch.assert_not_called()

@patch('api.scheduling.email_worker.requests.get')
@patch('api.scheduling.email_worker.requests.patch')
@patch('api.scheduling.email_worker.generate_pdf')
@patch('api.scheduling.email_worker.send_email')
def test_email_worker_run_lookup_success(mock_send, mock_pdf, mock_patch, mock_get):
    def mock_get_side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "scheduled_scan_runs" in url:
            resp.json.return_value = [{
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "user_id": "880e8400-e29b-41d4-a716-446655440000",
                "scan_id": "770e8400-e29b-41d4-a716-446655440000",
                "email_status": "pending"
            }]
        elif "scans" in url:
            resp.json.return_value = [{
                "report_data": {"test": "data"}
            }]
        else:
            resp.json.return_value = []
        return resp

    mock_get.side_effect = mock_get_side_effect

    with patch('qstash.Receiver.verify'):
        resp = client.post("/api/internal/scheduled-report-email", json={"run_id": "550e8400-e29b-41d4-a716-446655440000"}, headers={"Upstash-Signature": "sig"})

    # It should bypass the run_lookup blocks and fail later or continue.
    # Here it might fail at Auth fetch or something else, but definitely not 503 from lookup
    assert resp.json()["reason"] not in ["run_lookup_pending", "run_lookup_transient"]

    called_url = mock_get.call_args_list[0][0][0]
    assert "rest/v1/scheduled_scan_runs?id=eq.550e8400-e29b-41d4-a716-446655440000&select=id,user_id,scan_id,schedule_id,status,email_status,email_lease_until" in called_url
