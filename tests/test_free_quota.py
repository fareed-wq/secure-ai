import pytest
import time
from fastapi.testclient import TestClient
from api.index import app
from unittest.mock import patch

client = TestClient(app)

@pytest.fixture
def mock_entitlements_free():
    with patch('api.index.Entitlements') as MockEntitlements:
        mock_instance = MockEntitlements.return_value
        mock_instance.plan = 'free'
        mock_instance.can_advanced_scan = True
        mock_instance.is_unlimited = False
        yield mock_instance

@pytest.fixture
def mock_rate_limit():
    with patch('api.index.check_rate_limit', return_value=True) as m:
        yield m

@pytest.fixture
def mock_global_lease():
    with patch('api.index.acquire_scan_lease', return_value='fake-lease-id') as m:
        yield m

@pytest.fixture
def mock_validation():
    with patch('api.scanner.orchestrator.validate_scan_target', return_value=None) as m:
        yield m

@pytest.fixture
def mock_consume_free_quota():
    with patch('api.index.consume_free_quota', return_value=True) as m:
        yield m

@pytest.fixture
def mock_check_free_quota():
    with patch('api.index.check_free_quota', return_value={'quota_remaining': 5}) as m:
        yield m

@pytest.fixture
def mock_scan_url():
    with patch('api.index.scan_url', return_value={'status': 'completed'}) as m:
        yield m

def test_free_quota_success_basic(mock_entitlements_free, mock_rate_limit, mock_global_lease, mock_validation, mock_consume_free_quota, mock_check_free_quota, mock_scan_url):
    response = client.post('/api/scan', json={'url': 'https://example.com', 'scan_mode': 'passive', 'report_mode': 'simple'})
    assert response.status_code == 200

def test_free_quota_success_advanced(mock_entitlements_free, mock_rate_limit, mock_global_lease, mock_validation, mock_consume_free_quota, mock_check_free_quota, mock_scan_url):
    response = client.post('/api/scan', json={'url': 'https://example.com', 'scan_mode': 'advanced', 'report_mode': 'simple'})
    assert response.status_code == 200

def test_free_quota_sixth_scan_blocked(mock_entitlements_free, mock_rate_limit, mock_global_lease, mock_validation, mock_consume_free_quota, mock_scan_url):
    with patch('api.index.check_free_quota', return_value={'quota_remaining': 0}):
        response = client.post('/api/scan', json={'url': 'https://example.com', 'scan_mode': 'passive', 'report_mode': 'simple'})
        assert response.status_code == 429
        assert '5 free scans' in response.json()['error']
        mock_consume_free_quota.assert_not_called()
        mock_scan_url.assert_not_called()

def test_free_validation_failure_no_quota_consumed(mock_entitlements_free, mock_rate_limit, mock_global_lease, mock_consume_free_quota, mock_check_free_quota, mock_scan_url):
    with patch('api.scanner.orchestrator.validate_scan_target', return_value={'status': 'failed', 'error': 'Invalid host'}):
        response = client.post('/api/scan', json={'url': 'https://internal.local', 'scan_mode': 'passive', 'report_mode': 'simple'})
        assert response.status_code == 200
        assert response.json()['error'] == 'Invalid host'
        mock_consume_free_quota.assert_not_called()
        mock_scan_url.assert_not_called()


from api.auth.entitlements import Entitlements

def test_entitlements_guest_blocked():
    ent = Entitlements({'sub': None})
    assert ent.plan == 'guest'
    assert ent.can_basic_scan == True
    assert ent.can_advanced_scan == False
    assert ent.can_save_scan == False
    assert ent.can_share_scan == False
    assert ent.can_export_report == False
    assert ent.can_download_pdf == False
    assert ent.can_view_scan_history == False

def test_entitlements_free_allowed():
    ent = Entitlements({'sub': 'test-uuid'})
    assert ent.plan == 'free'
    assert ent.can_basic_scan == True
    assert ent.can_advanced_scan == True
    assert ent.can_save_scan == True
    assert ent.can_share_scan == True
    assert ent.can_export_report == True
    assert ent.can_download_pdf == True
    assert ent.can_view_scan_history == True

def test_redis_fail_closed_free():
    with patch('os.environ.get', return_value=None):
        from api.auth.entitlements import check_free_quota, consume_free_quota
        # Missing redis credentials should fail closed
        res = check_free_quota('user123')
        assert res['quota_remaining'] == 0
        assert consume_free_quota('user123') == False

