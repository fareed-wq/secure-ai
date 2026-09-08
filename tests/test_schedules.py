import os
import unittest
from datetime import datetime, time, timedelta
import zoneinfo
from unittest.mock import patch, MagicMock
import json

from fastapi.testclient import TestClient

from api.scheduling.time_utils import get_next_run_at, is_valid_timezone
from api.auth.entitlements import is_scheduled_scans_eligible

# Import full modules
import api.scheduling.router
import api.scheduling.worker
import api.index

client = TestClient(api.index.app)

class TestSchedules(unittest.TestCase):
    # ==========================
    # TESTS 1-4: AUTH & ENTITLEMENT
    # ==========================
    @patch('api.auth.entitlements.get_user_role', return_value='admin')
    @patch('api.auth.entitlements.get_user_plan_and_status', return_value=('free', 'active'))
    def test_auth_admin_create_allowed(self, mock_plan, mock_role):
        self.assertTrue(is_scheduled_scans_eligible("admin_user_id"))
        
        
    @patch('api.auth.entitlements.get_user_role', return_value='user')
    @patch('api.auth.entitlements.get_user_plan_and_status', return_value=('professional', 'active'))
    def test_auth_paid_metadata_alone_blocked(self, mock_plan, mock_role):
        self.assertFalse(is_scheduled_scans_eligible("paid_user_id"))
         # V1 policy is admin ONLY

    @patch('api.auth.entitlements.get_user_role', return_value='admin')
    @patch('api.auth.entitlements.get_user_plan_and_status', return_value=('free', 'suspended'))
    def test_auth_suspended_admin_blocked(self, mock_plan, mock_role):
        self.assertFalse(is_scheduled_scans_eligible('suspended_admin'))

    def test_auth_guest_create_401(self):
        resp = client.post("/api/schedules", json={
            "target_url": "https://example.com", "frequency": "daily", "time_of_day": "09:00:00",
            "timezone": "UTC", "authorization_acknowledged": True
        })
        self.assertIn(resp.status_code, (401, 403))

    @patch('api.auth.entitlements.Entitlements.can_use_scheduled_scans', new_callable=unittest.mock.PropertyMock)
    @patch('api.auth.entitlements.get_current_user')
    def test_auth_non_admin_create_403(self, mock_user, mock_can_use):
        mock_user.return_value = {"sub": "123"}
        mock_can_use.return_value = False
        # Override dependency
        api.index.app.dependency_overrides[api.auth.entitlements.require_current_user] = lambda: {"sub": "123"}
        resp = client.post("/api/schedules", json={
            "target_url": "https://example.com", "frequency": "daily", "time_of_day": "09:00:00",
            "timezone": "UTC", "authorization_acknowledged": True
        })
        self.assertEqual(resp.status_code, 403)
        api.index.app.dependency_overrides.clear()

    # ==========================
    # TESTS 5-8: QSTASH CREATE
    # ==========================
    @patch('api.auth.entitlements.get_user_role', return_value='admin')
    @patch('api.scheduling.router.get_db_headers', return_value={})
    @patch('api.scheduling.router.QStashClient')
    @patch('api.scheduling.router.requests.get')
    @patch('api.scheduling.router.requests.post')
    @patch('api.scheduling.router.QSTASH_TOKEN', 'token')
    def test_qstash_create(self, mock_post, mock_get, MockQStash, mock_headers, mock_role):
        # Mocks
        api.index.app.dependency_overrides[api.auth.entitlements.require_current_user] = lambda: {"sub": "123"}
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = [] # no duplicates, count < 3
        mock_post.return_value.status_code = 201
        mock_post.return_value.json.return_value = [{"id": "db-id-123"}]
        
        mock_client = MagicMock()
        MockQStash.return_value = mock_client
        mock_client.schedule.create.return_value = "msg-id"
        
        # Test
        resp = client.post("/api/schedules", json={
            "target_url": "https://example.com", "frequency": "daily", "time_of_day": "09:00:00",
            "timezone": "UTC", "authorization_acknowledged": True
        })
        self.assertEqual(resp.status_code, 200)
        
        # Verify deterministic schedule ID (Test 6) & Retries=0 (Test 5) & body contains only schedule_id (Test 7)
        mock_client.schedule.create.assert_called_once()
        kwargs = mock_client.schedule.create.call_args.kwargs
        self.assertEqual(kwargs['retries'], 0)
        self.assertTrue(kwargs['schedule_id'].startswith("urlscan-"))
        
        body_dict = json.loads(kwargs['body'])
        self.assertIn("schedule_id", body_dict)
        self.assertEqual(len(body_dict), 1)

        api.index.app.dependency_overrides.clear()

    @patch('api.auth.entitlements.get_user_role', return_value='admin')
    @patch('api.scheduling.router.get_db_headers', return_value={})
    @patch('api.scheduling.router.QStashClient')
    @patch('api.scheduling.router.requests.get')
    @patch('api.scheduling.router.requests.post')
    @patch('api.scheduling.router.QSTASH_TOKEN', 'token')
    def test_qstash_create_failure_orphan(self, mock_post, mock_get, MockQStash, mock_headers, mock_role):
        api.index.app.dependency_overrides[api.auth.entitlements.require_current_user] = lambda: {"sub": "123", "role": "admin"}
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = []
        # DB fails
        mock_post.return_value.status_code = 500
        
        mock_client = MagicMock()
        MockQStash.return_value = mock_client
        mock_client.schedule.create.return_value = "msg-id"
        
        resp = client.post("/api/schedules", json={
            "target_url": "https://example.com", "frequency": "daily", "time_of_day": "09:00:00",
            "timezone": "UTC", "authorization_acknowledged": True
        })
        self.assertEqual(resp.status_code, 500)
        # Test 8: rollback QStash
        mock_client.schedule.delete.assert_called_once()

        api.index.app.dependency_overrides.clear()

    # ==========================
    # TESTS 9-10: SIGNATURE
    # ==========================
    @patch('api.scheduling.worker.QSTASH_CURRENT_SIGNING_KEY', 'x')
    @patch('api.scheduling.worker.QSTASH_NEXT_SIGNING_KEY', 'x')
    def test_missing_signature_rejected(self): # Test 9
        resp = client.post("/api/internal/scheduled-scan", data=b'{"schedule_id": "123"}')
        self.assertEqual(resp.status_code, 401)
        
    @patch('api.scheduling.worker.QSTASH_CURRENT_SIGNING_KEY', 'x')
    @patch('api.scheduling.worker.QSTASH_NEXT_SIGNING_KEY', 'x')
    @patch('api.scheduling.worker.Receiver')
    def test_invalid_signature_rejected(self, MockReceiver): # Test 10
        mock_rec = MagicMock()
        mock_rec.verify.side_effect = Exception("invalid")
        MockReceiver.return_value = mock_rec
        
        resp = client.post("/api/internal/scheduled-scan", data=b'{"schedule_id": "123"}', headers={"Upstash-Signature": "bad"})
        self.assertEqual(resp.status_code, 403)

    # ==========================
    # TESTS 11-16: WORKER BEHAVIORS
    # ==========================
    def _mock_worker_deps(self, mock_get, mock_patch, mock_post, sched_overrides=None):
        base_sched = {
            "id": "sched-123", "user_id": "u-123", "qstash_schedule_id": "q-sched", 
            "is_enabled": True, "target_url": "https://example.com", "frequency": "daily", "time_of_day": "09:00", "timezone": "UTC"
        }
        if sched_overrides: base_sched.update(sched_overrides)
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = [base_sched]
        mock_patch.return_value.status_code = 200
        mock_patch.return_value.json.return_value = [{"id": "sched-123"}]
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = [{"id": "run-123"}]

    @patch('api.scheduling.worker.requests.post')
    @patch('api.scheduling.worker.requests.patch')
    @patch('api.scheduling.worker.requests.get')
    @patch('api.scheduling.worker.Receiver')
    @patch('api.scheduling.worker.QSTASH_CURRENT_SIGNING_KEY', 'x')
    @patch('api.scheduling.worker.QSTASH_NEXT_SIGNING_KEY', 'x')
    def test_worker_disabled_schedule(self, mock_rec, mock_get, mock_patch, mock_post): # Test 11
        self._mock_worker_deps(mock_get, mock_patch, mock_post, {"is_enabled": False})
        resp = client.post("/api/internal/scheduled-scan", data=b'{"schedule_id": "sched-123"}', headers={"Upstash-Signature": "sig"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["reason"], "disabled")
        mock_post.assert_not_called()

    @patch('api.scheduling.worker.requests.post')
    @patch('api.scheduling.worker.requests.patch')
    @patch('api.scheduling.worker.requests.get')
    @patch('api.scheduling.worker.Receiver')
    @patch('api.scheduling.worker.QSTASH_CURRENT_SIGNING_KEY', 'x')
    @patch('api.scheduling.worker.QSTASH_NEXT_SIGNING_KEY', 'x')
    def test_worker_header_mismatch(self, mock_rec, mock_get, mock_patch, mock_post): # Test 12
        self._mock_worker_deps(mock_get, mock_patch, mock_post)
        resp = client.post("/api/internal/scheduled-scan", data=b'{"schedule_id": "sched-123"}', headers={"Upstash-Signature": "sig", "Upstash-Schedule-Id": "wrong"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["reason"], "schedule_id_mismatch")

    @patch('api.scheduling.worker.validate_scan_target', return_value={"error": "bad"})
    @patch('api.scheduling.worker.is_scheduled_scans_eligible', return_value=True)
    @patch('api.scheduling.worker.requests.post')
    @patch('api.scheduling.worker.requests.patch')
    @patch('api.scheduling.worker.requests.get')
    @patch('api.scheduling.worker.Receiver')
    @patch('api.scheduling.worker.QSTASH_CURRENT_SIGNING_KEY', 'x')
    @patch('api.scheduling.worker.QSTASH_NEXT_SIGNING_KEY', 'x')
    def test_worker_target_revalidation_failure(self, mock_rec, mock_get, mock_patch, mock_post, mock_elig, mock_val): # Test 13
        self._mock_worker_deps(mock_get, mock_patch, mock_post)
        resp = client.post("/api/internal/scheduled-scan", data=b'{"schedule_id": "sched-123"}', headers={"Upstash-Signature": "sig"})
        self.assertEqual(resp.json()["reason"], "target_invalid")

    @patch('api.scheduling.worker.is_scheduled_scans_eligible', return_value=False)
    @patch('api.scheduling.worker.requests.post')
    @patch('api.scheduling.worker.requests.patch')
    @patch('api.scheduling.worker.requests.get')
    @patch('api.scheduling.worker.Receiver')
    @patch('api.scheduling.worker.QSTASH_CURRENT_SIGNING_KEY', 'x')
    @patch('api.scheduling.worker.QSTASH_NEXT_SIGNING_KEY', 'x')
    def test_worker_entitlement_lost(self, mock_rec, mock_get, mock_patch, mock_post, mock_elig): # Test 14
        self._mock_worker_deps(mock_get, mock_patch, mock_post)
        resp = client.post("/api/internal/scheduled-scan", data=b'{"schedule_id": "sched-123"}', headers={"Upstash-Signature": "sig"})
        self.assertEqual(resp.json()["reason"], "entitlement_lost")
        
    @patch('api.scheduling.worker.scan_url', return_value={"score": 100})
    @patch('api.scheduling.worker.validate_scan_target', return_value=None)
    @patch('api.scheduling.worker.is_scheduled_scans_eligible', return_value=True)
    @patch('api.scheduling.worker.requests.post')
    @patch('api.scheduling.worker.requests.patch')
    @patch('api.scheduling.worker.requests.get')
    @patch('api.scheduling.worker.Receiver')
    @patch('api.scheduling.worker.QSTASH_CURRENT_SIGNING_KEY', 'x')
    @patch('api.scheduling.worker.QSTASH_NEXT_SIGNING_KEY', 'x')
    def test_worker_success(self, mock_rec, mock_get, mock_patch, mock_post, mock_elig, mock_val, mock_scan): # Test 15
        self._mock_worker_deps(mock_get, mock_patch, mock_post)
        resp = client.post("/api/internal/scheduled-scan", data=b'{"schedule_id": "sched-123"}', headers={"Upstash-Signature": "sig"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "completed")
        mock_scan.assert_called_once_with("https://example.com", False, "passive")

    @patch('api.scheduling.worker.scan_url', side_effect=Exception("Crash"))
    @patch('api.scheduling.worker.validate_scan_target', return_value=None)
    @patch('api.scheduling.worker.is_scheduled_scans_eligible', return_value=True)
    @patch('api.scheduling.worker.requests.post')
    @patch('api.scheduling.worker.requests.patch')
    @patch('api.scheduling.worker.requests.get')
    @patch('api.scheduling.worker.Receiver')
    @patch('api.scheduling.worker.QSTASH_CURRENT_SIGNING_KEY', 'x')
    @patch('api.scheduling.worker.QSTASH_NEXT_SIGNING_KEY', 'x')
    def test_worker_scanner_failure(self, mock_rec, mock_get, mock_patch, mock_post, mock_elig, mock_val, mock_scan): # Test 16
        self._mock_worker_deps(mock_get, mock_patch, mock_post)
        resp = client.post("/api/internal/scheduled-scan", data=b'{"schedule_id": "sched-123"}', headers={"Upstash-Signature": "sig"})
        self.assertEqual(resp.json()["status"], "failed")

    # ==========================
    # TESTS 17-18: IDEMPOTENCY & CONCURRENCY
    # ==========================
    @patch('api.scheduling.worker.validate_scan_target', return_value=None)
    @patch('api.scheduling.worker.is_scheduled_scans_eligible', return_value=True)
    @patch('api.scheduling.worker.requests.post')
    @patch('api.scheduling.worker.requests.patch')
    @patch('api.scheduling.worker.requests.get')
    @patch('api.scheduling.worker.Receiver')
    @patch('api.scheduling.worker.QSTASH_CURRENT_SIGNING_KEY', 'x')
    @patch('api.scheduling.worker.QSTASH_NEXT_SIGNING_KEY', 'x')
    def test_worker_duplicate_delivery(self, mock_rec, mock_get, mock_patch, mock_post, mock_elig, mock_val): # Test 17
        self._mock_worker_deps(mock_get, mock_patch, mock_post)
        mock_post.return_value.status_code = 409 # Simulate unique violation on scheduled_scan_runs
        resp = client.post("/api/internal/scheduled-scan", data=b'{"schedule_id": "sched-123"}', headers={"Upstash-Signature": "sig"})
        self.assertEqual(resp.json()["reason"], "already_processed")
        
    @patch('api.scheduling.worker.validate_scan_target', return_value=None)
    @patch('api.scheduling.worker.is_scheduled_scans_eligible', return_value=True)
    @patch('api.scheduling.worker.requests.post')
    @patch('api.scheduling.worker.requests.patch')
    @patch('api.scheduling.worker.requests.get')
    @patch('api.scheduling.worker.Receiver')
    @patch('api.scheduling.worker.QSTASH_CURRENT_SIGNING_KEY', 'x')
    @patch('api.scheduling.worker.QSTASH_NEXT_SIGNING_KEY', 'x')
    def test_worker_concurrent_lease(self, mock_rec, mock_get, mock_patch, mock_post, mock_elig, mock_val): # Test 18
        self._mock_worker_deps(mock_get, mock_patch, mock_post)
        mock_patch.return_value.status_code = 200
        mock_patch.return_value.json.return_value = [] # claim returns empty
        resp = client.post("/api/internal/scheduled-scan", data=b'{"schedule_id": "sched-123"}', headers={"Upstash-Signature": "sig"})
        self.assertEqual(resp.json()["reason"], "lease_active")

    # ==========================
    # TESTS 19-24: QSTASH MANAGEMENT
    # ==========================
    @patch('api.auth.entitlements.get_user_role', return_value='admin')
    @patch('api.scheduling.router.get_db_headers', return_value={})
    @patch('api.scheduling.router.QStashClient')
    @patch('api.scheduling.router.requests.get')
    @patch('api.scheduling.router.requests.patch')
    @patch('api.scheduling.router.QSTASH_TOKEN', 'token')
    def test_pause_failure(self, mock_patch, mock_get, MockQStash, mock_headers, mock_role): # Test 19
        api.index.app.dependency_overrides[api.auth.entitlements.require_current_user] = lambda: {"sub": "123", "role": "admin"}
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = [{"id": "1", "qstash_schedule_id": "qs1"}]
        MockQStash.return_value.schedule.pause.side_effect = Exception("Fail")
        resp = client.post("/api/schedules/1/pause")
        self.assertEqual(resp.status_code, 500)
        mock_patch.assert_not_called()
        api.index.app.dependency_overrides.clear()

    @patch('api.auth.entitlements.get_user_role', return_value='admin')
    @patch('api.scheduling.router.get_db_headers', return_value={})
    @patch('api.scheduling.router.QStashClient')
    @patch('api.scheduling.router.requests.get')
    @patch('api.scheduling.router.requests.patch')
    @patch('api.scheduling.router.QSTASH_TOKEN', 'token')
    def test_pause_success(self, mock_patch, mock_get, MockQStash, mock_headers, mock_role): # Test 20
        api.index.app.dependency_overrides[api.auth.entitlements.require_current_user] = lambda: {"sub": "123", "role": "admin"}
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = [{"id": "1", "qstash_schedule_id": "qs1"}]
        resp = client.post("/api/schedules/1/pause")
        self.assertEqual(resp.status_code, 200)
        mock_patch.assert_called_once()
        api.index.app.dependency_overrides.clear()
        
    @patch('api.auth.entitlements.get_user_role', return_value='admin')
    @patch('api.scheduling.router.get_db_headers', return_value={})
    @patch('api.scheduling.router.QStashClient')
    @patch('api.scheduling.router.validate_scan_target', return_value=None)
    @patch('api.scheduling.router.requests.get')
    @patch('api.scheduling.router.requests.patch')
    @patch('api.scheduling.router.QSTASH_TOKEN', 'token')
    def test_resume_failure(self, mock_patch, mock_get, mock_val, MockQStash, mock_headers, mock_role): # Test 21
        api.index.app.dependency_overrides[api.auth.entitlements.require_current_user] = lambda: {"sub": "123", "role": "admin"}
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = [{"id": "1", "qstash_schedule_id": "qs1", "target_url": "u", "frequency": "daily", "time_of_day": "09:00", "timezone": "UTC"}]
        MockQStash.return_value.schedule.resume.side_effect = Exception("Fail")
        resp = client.post("/api/schedules/1/resume")
        self.assertEqual(resp.status_code, 500)
        mock_patch.assert_not_called()
        api.index.app.dependency_overrides.clear()
        
    @patch('api.auth.entitlements.get_user_role', return_value='admin')
    @patch('api.scheduling.router.get_db_headers', return_value={})
    @patch('api.scheduling.router.QStashClient')
    @patch('api.scheduling.router.validate_scan_target', return_value=None)
    @patch('api.scheduling.router.requests.get')
    @patch('api.scheduling.router.requests.patch')
    @patch('api.scheduling.router.QSTASH_TOKEN', 'token')
    def test_resume_success(self, mock_patch, mock_get, mock_val, MockQStash, mock_headers, mock_role): # Test 22
        api.index.app.dependency_overrides[api.auth.entitlements.require_current_user] = lambda: {"sub": "123", "role": "admin"}
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = [{"id": "1", "qstash_schedule_id": "qs1", "target_url": "u", "frequency": "daily", "time_of_day": "09:00", "timezone": "UTC"}]
        resp = client.post("/api/schedules/1/resume")
        self.assertEqual(resp.status_code, 200)
        mock_patch.assert_called_once()
        api.index.app.dependency_overrides.clear()
        
    @patch('api.auth.entitlements.get_user_role', return_value='admin')
    @patch('api.scheduling.router.get_db_headers', return_value={})
    @patch('api.scheduling.router.QStashClient')
    @patch('api.scheduling.router.requests.get')
    @patch('api.scheduling.router.requests.delete')
    @patch('api.scheduling.router.QSTASH_TOKEN', 'token')
    def test_delete_failure_retains_db(self, mock_delete, mock_get, MockQStash, mock_headers, mock_role): # Test 23
        api.index.app.dependency_overrides[api.auth.entitlements.require_current_user] = lambda: {"sub": "123", "role": "admin"}
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = [{"id": "1", "qstash_schedule_id": "qs1"}]
        MockQStash.return_value.schedule.delete.side_effect = Exception("Service Unavailable")
        
        resp = client.delete("/api/schedules/1")
        self.assertEqual(resp.status_code, 500)
        mock_delete.assert_not_called()
        api.index.app.dependency_overrides.clear()

    @patch('api.auth.entitlements.get_user_role', return_value='admin')
    @patch('api.scheduling.router.get_db_headers', return_value={})
    @patch('api.scheduling.router.QStashClient')
    @patch('api.scheduling.router.requests.get')
    @patch('api.scheduling.router.requests.delete')
    @patch('api.scheduling.router.QSTASH_TOKEN', 'token')
    def test_delete_404_removes_db(self, mock_delete, mock_get, MockQStash, mock_headers, mock_role): # Test 24
        api.index.app.dependency_overrides[api.auth.entitlements.require_current_user] = lambda: {"sub": "123", "role": "admin"}
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = [{"id": "1", "qstash_schedule_id": "qs1"}]
        MockQStash.return_value.schedule.delete.side_effect = Exception("404 not found")
        
        resp = client.delete("/api/schedules/1")
        self.assertEqual(resp.status_code, 200)
        mock_delete.assert_called_once()
        api.index.app.dependency_overrides.clear()


    @patch('api.scheduling.router.uuid.uuid4', return_value='00000000-0000-0000-0000-000000000000')
    @patch('api.scheduling.router.get_db_headers', return_value={})
    @patch('api.scheduling.router.requests.get')
    @patch('api.scheduling.router.requests.post')
    @patch('api.scheduling.router.QSTASH_TOKEN', 'token')
    @patch('api.scheduling.router.QStashClient')
    @patch('api.auth.entitlements.get_user_role', return_value='admin')
    @patch('api.auth.entitlements.get_user_plan_and_status', return_value=('free', 'active'))
    @patch('api.auth.entitlements.verify_jwt', return_value={"sub": "123", "role": "authenticated"})
    def test_qstash_create_exact_arguments(self, mock_jwt, mock_plan, mock_role, MockQStash, mock_post, mock_get, mock_headers, mock_uuid):
        import api.index
        api.index.app.dependency_overrides[api.auth.entitlements.get_current_user] = lambda: {"sub": "123"}
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = []
        mock_post.return_value.status_code = 201
        mock_post.return_value.json.return_value = [{"id": "00000000-0000-0000-0000-000000000000", "qstash_schedule_id": "urlscan-00000000-0000-0000-0000-000000000000"}]

        mock_client = unittest.mock.MagicMock()
        MockQStash.return_value = mock_client
        mock_client.schedule.create.return_value = "msg-id"

        resp = client.post("/api/schedules", headers={"Authorization": "Bearer fake"}, json={
            "target_url": "https://example.com", "frequency": "daily", "time_of_day": "00:50:00",
            "timezone": "Asia/Riyadh", "authorization_acknowledged": True
        })
        
        self.assertEqual(resp.status_code, 200)
        
        mock_client.schedule.create.assert_called_once()
        _, kwargs = mock_client.schedule.create.call_args
        self.assertEqual(kwargs['destination'], "https://www.urlscanonline.com/api/internal/scheduled-scan")
        self.assertEqual(kwargs['cron'], "CRON_TZ=Asia/Riyadh 50 0 * * *")
        import json
        self.assertEqual(kwargs['body'], json.dumps({"schedule_id": "00000000-0000-0000-0000-000000000000"}))
        self.assertEqual(kwargs['headers'], {"Content-Type": "application/json"})
        self.assertEqual(kwargs['retries'], 0)
        self.assertTrue(kwargs['schedule_id'].startswith("urlscan-"))
        
        api.index.app.dependency_overrides.clear()


    @patch('api.scheduling.router.QStashClient')
    def test_qstash_client_init(self, MockQStash):
        from api.scheduling.router import _get_qstash_client
        
        # Test with QSTASH_URL present
        with patch.dict(os.environ, {"QSTASH_URL": "https://qstash-eu-central-1.upstash.io"}):
            _get_qstash_client()
            MockQStash.assert_called_with(unittest.mock.ANY, base_url="https://qstash-eu-central-1.upstash.io")
            
        MockQStash.reset_mock()
        
        # Test with QSTASH_URL absent
        with patch.dict(os.environ, {}, clear=False):
            if "QSTASH_URL" in os.environ:
                del os.environ["QSTASH_URL"]
            _get_qstash_client()
            MockQStash.assert_called_with(unittest.mock.ANY)

if __name__ == '__main__':
    unittest.main()
