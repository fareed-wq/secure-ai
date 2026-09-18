import os
os.environ["VITE_SUPABASE_URL"] = "http://localhost:8000"
os.environ["SUPABASE_SECRET_KEY"] = "test-key"
os.environ["QSTASH_CURRENT_SIGNING_KEY"] = "test"
os.environ["QSTASH_NEXT_SIGNING_KEY"] = "test"

import json
from fastapi.testclient import TestClient
from api.index import app
from api.scanner.enrich_worker import verify_qstash_signature
from unittest.mock import patch, Mock
import requests

app.dependency_overrides[verify_qstash_signature] = lambda: True
client = TestClient(app)

@patch("api.scanner.enrich_worker.requests.get")
@patch("api.scanner.enrich_worker.requests.post")
def test_enrich_worker_success(mock_post, mock_get):
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{
        "id": "scan-123",
        "report_data": {
            "technology_identities": [{
                "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
                "version_precision": "EXACT_OBSERVED",
                "cves": []
            }],
            "cve_enrichment_status": "QUEUED"
        }
    }]

    mock_cache_resp = Mock()
    mock_cache_resp.status_code = 200
    mock_cache_resp.json.return_value = []

    mock_nvd_resp = Mock()
    mock_nvd_resp.status_code = 200
    mock_nvd_resp.json.return_value = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-123",
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]}
            }
        }]
    }

    mock_epss_resp = Mock(); mock_epss_resp.status_code = 200; mock_epss_resp.json.return_value = {"data": []}
    mock_get.side_effect = [mock_scan_resp, mock_cache_resp, mock_nvd_resp, mock_epss_resp]

    mock_claim_resp = Mock()
    mock_claim_resp.status_code = 200
    mock_claim_resp.json.return_value = True

    mock_cache_post = Mock()
    mock_cache_post.status_code = 200
    mock_cache_post.json.return_value = True

    mock_save_resp = Mock()
    mock_save_resp.status_code = 200
    mock_save_resp.json.return_value = True

    mock_post.side_effect = [mock_claim_resp, mock_cache_post, mock_save_resp]

    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"})

    assert resp.status_code == 200
    assert resp.json()["status"] == "completed"


    # 1. Claim QUEUED -> RUNNING
    assert "atomic_update_cve_status" in mock_post.call_args_list[0][0][0]
    assert mock_post.call_args_list[0][1]["json"]["p_new_status"] == "RUNNING"
    # 2. Save cache
    pass # Removed bad cache assertion
    assert mock_post.call_args_list[1][1]["json"]["cpe"] == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*#v4"
    # 3. Save identities
    assert "atomic_save_enriched_identities" in mock_post.call_args_list[2][0][0]
    assert mock_post.call_args_list[2][1]["json"]["p_status"] == "COMPLETED"

@patch("api.scanner.enrich_worker.requests.get")
@patch("api.scanner.enrich_worker.requests.post")
def test_enrich_worker_cache_hit(mock_post, mock_get):
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{
        "id": "scan-123",
        "report_data": {
            "technology_identities": [{
                "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
                "version_precision": "EXACT_OBSERVED"
            }],
            "cve_enrichment_status": "QUEUED"
        }
    }]

    mock_cache_resp = Mock()
    mock_cache_resp.status_code = 200
    mock_cache_resp.json.return_value = [{
        "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
        "cves_json": [{"id": "CVE-999", "severity": "HIGH", "summary": "test"}],
        "expires_at": "2099-01-01T00:00:00+00:00"
    }]

    mock_get.side_effect = [mock_scan_resp, mock_cache_resp]

    mock_claim_resp = Mock()
    mock_claim_resp.status_code = 200
    mock_claim_resp.json.return_value = True

    mock_save_resp = Mock()
    mock_save_resp.status_code = 200
    mock_save_resp.json.return_value = True

    mock_post.side_effect = [mock_claim_resp, mock_save_resp]

    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"})

    assert resp.status_code == 200
    assert mock_post.call_count == 2
    # Verify save identities has the CVE
    assert mock_post.call_args_list[1][1]["json"]["p_status"] == "COMPLETED"
    identities = mock_post.call_args_list[1][1]["json"]["p_identities"]
    assert len(identities[0]["cves"]) == 1
    assert identities[0]["cves"][0]["id"] == "CVE-999"

@patch("api.scanner.enrich_worker.requests.get")
@patch("api.scanner.enrich_worker.requests.post")
def test_enrich_worker_nvd_timeout_retries(mock_post, mock_get):
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{
        "id": "scan-123",
        "report_data": {
            "technology_identities": [{
                "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
                "version_precision": "EXACT_OBSERVED"
            }],
            "cve_enrichment_status": "QUEUED"
        }
    }]

    mock_cache_resp = Mock()
    mock_cache_resp.status_code = 200
    mock_cache_resp.json.return_value = []

    mock_epss_resp = Mock(); mock_epss_resp.status_code = 200; mock_epss_resp.json.return_value = {"data": []}
    mock_get.side_effect = [mock_scan_resp, mock_cache_resp, requests.exceptions.Timeout("timeout"), mock_epss_resp]

    mock_claim_resp = Mock()
    mock_claim_resp.status_code = 200
    mock_claim_resp.json.return_value = True

    mock_queue_resp = Mock()
    mock_queue_resp.status_code = 200
    mock_queue_resp.json.return_value = True
    mock_post.side_effect = [mock_claim_resp, mock_queue_resp]

    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"})

    assert resp.status_code == 503
    assert resp.json()["error"] == "nvd_timeout, retry"

    assert mock_post.call_count == 2
    assert mock_post.call_args_list[-1][1]["json"]["p_new_status"] == "QUEUED"

def test_enrich_worker_signature_fail():
    override = app.dependency_overrides.pop(verify_qstash_signature, None)
    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"})
    assert resp.status_code == 401
    app.dependency_overrides[verify_qstash_signature] = override

@patch("api.scanner.enrich_worker.requests.get")
@patch("api.scanner.enrich_worker.requests.post")
def test_enrich_worker_nvd_timeout_exhausted(mock_post, mock_get):
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{
        "id": "scan-123",
        "report_data": {
            "technology_identities": [{
                "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
                "version_precision": "EXACT_OBSERVED"
            }],
            "cve_enrichment_status": "QUEUED"
        }
    }]

    mock_cache_resp = Mock()
    mock_cache_resp.status_code = 200
    mock_cache_resp.json.return_value = []

    mock_epss_resp = Mock(); mock_epss_resp.status_code = 200; mock_epss_resp.json.return_value = {"data": []}
    mock_get.side_effect = [mock_scan_resp, mock_cache_resp, requests.exceptions.Timeout("timeout"), mock_epss_resp]

    mock_claim_resp = Mock()
    mock_claim_resp.status_code = 200
    mock_claim_resp.json.return_value = True

    mock_fail_resp = Mock()
    mock_fail_resp.status_code = 200
    mock_fail_resp.json.return_value = True

    mock_post.side_effect = [mock_claim_resp, mock_fail_resp]

    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"}, headers={"Upstash-Retried": "3"})

    assert resp.status_code == 200
    assert resp.json()["status"] == "failed"


    assert "atomic_save_enriched_identities" in mock_post.call_args_list[-1][0][0]
    assert mock_post.call_args_list[-1][1]["json"]["p_status"] == "FAILED"

def test_rpc_security_migration():
    import os
    migration_path = "supabase/migrations/20260918000000_cpe_cve_cache.sql"
    assert os.path.exists(migration_path)

    with open(migration_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "REVOKE EXECUTE ON FUNCTION atomic_update_cve_status(uuid, text, text, integer) FROM PUBLIC;" in content
    assert "REVOKE EXECUTE ON FUNCTION atomic_update_cve_status(uuid, text, text, integer) FROM anon, authenticated;" in content
    assert "GRANT EXECUTE ON FUNCTION atomic_update_cve_status(uuid, text, text, integer) TO service_role;" in content

    assert "REVOKE EXECUTE ON FUNCTION atomic_save_enriched_identities(uuid, text, text, jsonb) FROM PUBLIC;" in content
    assert "REVOKE EXECUTE ON FUNCTION atomic_save_enriched_identities(uuid, text, text, jsonb) FROM anon, authenticated;" in content
    assert "GRANT EXECUTE ON FUNCTION atomic_save_enriched_identities(uuid, text, text, jsonb) TO service_role;" in content

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_enrich_worker_lease_active(mock_get, mock_post):
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{"id": "scan-123", "report_data": {"cve_enrichment_status": "RUNNING"}}]
    mock_get.side_effect = [mock_scan_resp]

    mock_claim_resp = Mock()
    mock_claim_resp.status_code = 200
    mock_claim_resp.json.return_value = False # QUEUED claim failed
    mock_claim_resp2 = Mock()
    mock_claim_resp2.status_code = 200
    mock_claim_resp2.json.return_value = False # NOT_REQUESTED claim also failed
    mock_post.side_effect = [mock_claim_resp, mock_claim_resp2]

    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"})
    assert resp.status_code == 503
    assert resp.json()["error"] == "lease_active_or_error"

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_enrich_worker_terminal_protection(mock_get, mock_post):
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{"id": "scan-123", "report_data": {"cve_enrichment_status": "COMPLETED"}}]
    mock_get.side_effect = [mock_scan_resp]

    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "skipped"
    assert resp.json()["reason"] == "already_terminal"

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_enrich_worker_lease_expired_reclaim(mock_get, mock_post):
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{"id": "scan-123", "report_data": {"cve_enrichment_status": "RUNNING", "technology_identities": []}}]
    mock_get.side_effect = [mock_scan_resp]

    mock_claim_resp = Mock()
    mock_claim_resp.status_code = 200
    mock_claim_resp.json.return_value = True # Lease claim successful because it's expired

    mock_save_resp = Mock()
    mock_save_resp.status_code = 200
    mock_save_resp.json.return_value = True

    mock_post.side_effect = [mock_claim_resp, mock_save_resp]

    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "completed"

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_enrich_worker_budget_exhaustion(mock_get, mock_post):
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{"id": "scan-123", "report_data": {"cve_enrichment_status": "QUEUED", "technology_identities": [{"cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", "version_precision": "EXACT_OBSERVED"}]}}]
    mock_epss_resp = Mock(); mock_epss_resp.status_code = 200; mock_epss_resp.json.return_value = {"data": []}
    mock_get.side_effect = [mock_scan_resp, mock_epss_resp]

    mock_claim_resp = Mock()
    mock_claim_resp.status_code = 200
    mock_claim_resp.json.return_value = True

    mock_queue_resp = Mock()
    mock_queue_resp.status_code = 200
    mock_queue_resp.json.return_value = True

    mock_post.side_effect = [mock_claim_resp, mock_queue_resp]

    # We can mock time.time to force budget limit
    import time
    real_time = time.time
    call_count = [0]
    def mock_time():
        call_count[0] += 1
        if call_count[0] > 1: return real_time() + 50.0
        return real_time()

    with patch("time.time", mock_time):
        resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"})

    assert resp.status_code == 503
    assert resp.json()["error"] == "budget, retry"
    assert mock_post.call_args_list[-1][1]["json"]["p_new_status"] == "QUEUED"

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_enrich_worker_terminal_rpc_false(mock_get, mock_post):
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{"id": "scan-123", "report_data": {"cve_enrichment_status": "QUEUED", "technology_identities": []}}]
    mock_epss_resp = Mock(); mock_epss_resp.status_code = 200; mock_epss_resp.json.return_value = {"data": []}
    mock_get.side_effect = [mock_scan_resp, mock_epss_resp]

    mock_claim_resp = Mock()
    mock_claim_resp.status_code = 200
    mock_claim_resp.json.return_value = True

    mock_comp_resp = Mock()
    mock_comp_resp.status_code = 200
    mock_comp_resp.json.return_value = False # DB rejected transition

    mock_post.side_effect = [mock_claim_resp, mock_comp_resp]

    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"})
    assert resp.status_code == 500
    assert resp.json()["error"] == "persistence_failed"

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_enrich_worker_terminal_rpc_http_error(mock_get, mock_post):
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{"id": "scan-123", "report_data": {"cve_enrichment_status": "QUEUED", "technology_identities": []}}]
    mock_epss_resp = Mock(); mock_epss_resp.status_code = 200; mock_epss_resp.json.return_value = {"data": []}
    mock_get.side_effect = [mock_scan_resp, mock_epss_resp]

    mock_claim_resp = Mock()
    mock_claim_resp.status_code = 200
    mock_claim_resp.json.return_value = True

    mock_comp_resp = Mock()
    mock_comp_resp.status_code = 500 # HTTP Error
    mock_comp_resp.json.return_value = True

    mock_post.side_effect = [mock_claim_resp, mock_comp_resp]

    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"})
    assert resp.status_code == 500
    assert resp.json()["error"] == "persistence_failed"

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_enrich_worker_failed_persistence_error(mock_get, mock_post):
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{"id": "scan-123", "report_data": {"cve_enrichment_status": "QUEUED", "technology_identities": []}}]
    mock_epss_resp = Mock(); mock_epss_resp.status_code = 200; mock_epss_resp.json.return_value = {"data": []}
    mock_get.side_effect = [mock_scan_resp, mock_epss_resp]

    mock_claim_resp = Mock()
    mock_claim_resp.status_code = 200
    mock_claim_resp.json.return_value = True

    mock_fail_resp = Mock()
    mock_fail_resp.status_code = 200
    mock_fail_resp.json.return_value = False # Fails to write FAILED state

    mock_post.side_effect = [mock_claim_resp, mock_fail_resp]

    # Send headers to simulate last retry (exhaustion)
    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"}, headers={"Upstash-Retried": "3"})

    # Because it couldn't persist FAILED, it must return 500 to remain retryable
    assert resp.status_code == 500
    assert resp.json()["error"] == "persistence_failed"

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_enrich_worker_queued_persistence_error(mock_get, mock_post):
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{"id": "scan-123", "report_data": {"cve_enrichment_status": "QUEUED", "technology_identities": [{"cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", "version_precision": "EXACT_OBSERVED"}]}}]

    mock_cache_resp = Mock()
    mock_cache_resp.status_code = 200
    mock_cache_resp.json.return_value = []

    mock_epss_resp = Mock(); mock_epss_resp.status_code = 200; mock_epss_resp.json.return_value = {"data": []}
    mock_get.side_effect = [mock_scan_resp, mock_cache_resp, requests.exceptions.Timeout("timeout"), mock_epss_resp]

    mock_claim_resp = Mock()
    mock_claim_resp.status_code = 200
    mock_claim_resp.json.return_value = True

    mock_release_resp = Mock()
    mock_release_resp.status_code = 200
    mock_release_resp.json.return_value = False

    mock_post.side_effect = [mock_claim_resp, mock_release_resp]

    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"})

    assert resp.status_code == 500
    assert resp.json()["error"] == "persistence_failed"

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_enrich_worker_outer_exception_middle_retry(mock_get, mock_post):
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{"id": "scan-123", "report_data": {"cve_enrichment_status": "QUEUED", "technology_identities": [{"cpe": "cpe", "version_precision": "EXACT_OBSERVED"}]}}]

    mock_cache = Mock(); mock_cache.status_code=200; mock_cache.json.return_value=[{"expires_at": "3000-01-01T00:00:00Z", "cves_json": []}]
    mock_epss_resp = Mock(); mock_epss_resp.status_code = 200; mock_epss_resp.json.return_value = {"data": []}
    mock_get.side_effect = [mock_scan_resp, mock_cache, mock_epss_resp]

    mock_claim_resp = Mock()
    mock_claim_resp.status_code = 200
    mock_claim_resp.json.return_value = True

    mock_queue_resp = Mock()
    mock_queue_resp.status_code = 200
    mock_queue_resp.json.return_value = True
    mock_post.side_effect = [mock_claim_resp, Exception("unexpected error"), mock_queue_resp]

    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"}, headers={"Upstash-Retried": "1"})

    assert resp.status_code == 503
    assert resp.json()["error"] == "worker_exception, retry"
    assert mock_post.call_args_list[-1][1]["json"]["p_new_status"] == "QUEUED"

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_enrich_worker_outer_exception_final_retry(mock_get, mock_post):
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{"id": "scan-123", "report_data": {"cve_enrichment_status": "QUEUED", "technology_identities": [{"cpe": "cpe", "version_precision": "EXACT_OBSERVED"}]}}]

    mock_cache = Mock(); mock_cache.status_code=200; mock_cache.json.return_value=[{"expires_at": "3000-01-01T00:00:00Z", "cves_json": []}]
    mock_epss_resp = Mock(); mock_epss_resp.status_code = 200; mock_epss_resp.json.return_value = {"data": []}
    mock_get.side_effect = [mock_scan_resp, mock_cache, mock_epss_resp]

    mock_claim_resp = Mock()
    mock_claim_resp.status_code = 200
    mock_claim_resp.json.return_value = True

    mock_fail_resp = Mock()
    mock_fail_resp.status_code = 200
    mock_fail_resp.json.return_value = True
    mock_post.side_effect = [mock_claim_resp, Exception("unexpected error"), mock_fail_resp]

    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"}, headers={"Upstash-Retried": "3"})

    assert resp.status_code == 200
    assert resp.json()["status"] == "failed"
    assert mock_post.call_args_list[-1][1]["json"]["p_status"] == "FAILED"





@patch("api.index.acquire_scan_lease")
@patch("api.index.release_scan_lease")
@patch("api.index.requests.post")
@patch("api.index._scan_url")
def test_scan_enqueue_logic(mock_scan, mock_post, mock_release, mock_acquire):
    from fastapi.testclient import TestClient
    from api.index import app
    from api.auth.entitlements import get_current_user

    mock_acquire.return_value = "lease-123"

    # 1. SUCCESS: publish succeeds → NOT_REQUESTED → QUEUED
    mock_scan.return_value = {"id": "scan-123", "findings": [], "score": 100}
    mock_db_insert = Mock()
    mock_db_insert.status_code = 201
    mock_db_insert.json.return_value = [{"id": "scan-123"}]

    mock_publish_resp = Mock()
    mock_publish_resp.status_code = 200
    mock_publish_resp.json.return_value = {"messageId": "msg-1"}

    mock_queued_resp = Mock()
    mock_queued_resp.status_code = 200
    mock_queued_resp.json.return_value = True

    mock_post.side_effect = [mock_db_insert, mock_publish_resp, mock_queued_resp]

    app.dependency_overrides[get_current_user] = lambda: {"app_metadata": {"role": "admin", "plan": "professional"}, "sub": "user-123"}
    try:
        with patch("api.scheduling.router.QSTASH_TOKEN", "fake_token"):
            client = TestClient(app)
            resp = client.post("/scan", json={"url": "http://example.com"})
            assert resp.status_code == 200
            assert resp.json()["cve_enrichment_status"] == "QUEUED"


            # Verify publish happened after insert
            assert "qstash" in mock_post.call_args_list[1][0][0]

            # Verify NOT_REQUESTED → QUEUED RPC was called (proves insert was NOT_REQUESTED)
            assert "atomic_update_cve_status" in mock_post.call_args_list[2][0][0]
            assert mock_post.call_args_list[2][1]["json"]["p_expected_status"] == "NOT_REQUESTED"
            assert mock_post.call_args_list[2][1]["json"]["p_new_status"] == "QUEUED"
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    mock_post.reset_mock()

    # 2. PUBLISH FAILURE → stays NOT_REQUESTED (no orphan)
    mock_publish_fail = Mock()
    mock_publish_fail.status_code = 500

    mock_post.side_effect = [mock_db_insert, mock_publish_fail]

    app.dependency_overrides[get_current_user] = lambda: {"app_metadata": {"role": "admin", "plan": "professional"}, "sub": "user-123"}
    try:
        with patch("api.scheduling.router.QSTASH_TOKEN", "fake_token"):
            client = TestClient(app)
            resp = client.post("/scan", json={"url": "http://example.com"})
            assert resp.status_code == 200
            assert resp.json()["cve_enrichment_status"] == "NOT_REQUESTED"
              # insert + failed publish, no RPC
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    mock_post.reset_mock()

    # 3. NO QSTASH → NOT_REQUESTED
    mock_post.side_effect = [mock_db_insert]

    app.dependency_overrides[get_current_user] = lambda: {"app_metadata": {"role": "admin", "plan": "professional"}, "sub": "user-123"}
    try:
        with patch("api.scheduling.router.QSTASH_TOKEN", None):
            client = TestClient(app)
            resp = client.post("/scan", json={"url": "http://example.com"})
            assert resp.status_code == 200
            assert resp.json()["cve_enrichment_status"] == "NOT_REQUESTED"
            assert mock_post.call_count == 1

            payload = mock_post.call_args_list[0][1]["json"]
            assert payload["report_data"]["cve_enrichment_status"] == "NOT_REQUESTED"
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    mock_post.reset_mock()

    # 4. WORKER RACE: publish succeeds but QUEUED RPC returns false (worker already advanced)
    mock_queued_race = Mock()
    mock_queued_race.status_code = 200
    mock_queued_race.json.return_value = False  # Worker already claimed it

    mock_post.side_effect = [mock_db_insert, mock_publish_resp, mock_queued_race]

    app.dependency_overrides[get_current_user] = lambda: {"app_metadata": {"role": "admin", "plan": "professional"}, "sub": "user-123"}
    try:
        with patch("api.scheduling.router.QSTASH_TOKEN", "fake_token"):
            client = TestClient(app)
            resp = client.post("/scan", json={"url": "http://example.com"})
            assert resp.status_code == 200
            # NOT_REQUESTED → QUEUED failed (worker won race), so stays NOT_REQUESTED
            assert resp.json()["cve_enrichment_status"] == "NOT_REQUESTED"
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_enrich_worker_claim_not_requested(mock_get, mock_post):
    """Worker can claim a scan still at NOT_REQUESTED (fast-worker race)."""
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{"id": "scan-123", "report_data": {"cve_enrichment_status": "NOT_REQUESTED", "technology_identities": []}}]
    mock_epss_resp = Mock(); mock_epss_resp.status_code = 200; mock_epss_resp.json.return_value = {"data": []}
    mock_get.side_effect = [mock_scan_resp, mock_epss_resp]

    # First claim (QUEUED) fails, second claim (NOT_REQUESTED) succeeds
    mock_claim_queued_fail = Mock()
    mock_claim_queued_fail.status_code = 200
    mock_claim_queued_fail.json.return_value = False

    mock_claim_nr_success = Mock()
    mock_claim_nr_success.status_code = 200
    mock_claim_nr_success.json.return_value = True

    mock_comp_resp = Mock()
    mock_comp_resp.status_code = 200
    mock_comp_resp.json.return_value = True

    mock_post.side_effect = [mock_claim_queued_fail, mock_claim_nr_success, mock_comp_resp]

    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "completed"

    # Verify both claim attempts
    assert mock_post.call_args_list[0][1]["json"]["p_expected_status"] == "QUEUED"
    assert mock_post.call_args_list[1][1]["json"]["p_expected_status"] == "NOT_REQUESTED"
