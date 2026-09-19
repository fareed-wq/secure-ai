import os

from api.scanner.enrich_worker import verify_qstash_signature
from api.index import app

import pytest
import copy
from unittest.mock import patch, Mock
from fastapi.testclient import TestClient

client = TestClient(app)

@pytest.fixture(autouse=True)
def _isolate_module_env(monkeypatch):
    monkeypatch.setenv("VITE_SUPABASE_URL", "http://localhost:8000")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "mock_key")
    monkeypatch.setenv("QSTASH_CURRENT_SIGNING_KEY", "mock_qstash")
    monkeypatch.setenv("QSTASH_NEXT_SIGNING_KEY", "mock_qstash")
    monkeypatch.setattr("api.scanner.enrich_worker.SUPABASE_URL", "http://localhost:8000", raising=False)
    monkeypatch.setattr("api.auth.entitlements.SUPABASE_URL", "http://localhost:8000", raising=False)
    monkeypatch.setattr("api.scanner.enrich_worker.SUPABASE_SECRET_KEY", "test-key" if "test" in "mock_key" else "mock_key", raising=False)
    monkeypatch.setattr("api.auth.entitlements.SUPABASE_SECRET_KEY", "test-key", raising=False)
    monkeypatch.setattr("api.scanner.enrich_worker.QSTASH_CURRENT_SIGNING_KEY", "mock_qstash", raising=False)
    monkeypatch.setattr("api.scanner.enrich_worker.QSTASH_NEXT_SIGNING_KEY", "mock_qstash", raising=False)
    from api.auth.entitlements import get_current_user
    from api.scanner.enrich_worker import verify_qstash_signature
    app.dependency_overrides[get_current_user] = lambda: {"app_metadata": {"role": "admin", "plan": "professional"}, "sub": "user-123"}
    app.dependency_overrides[verify_qstash_signature] = lambda: True


def run_enrichment(identities, nvd_mock_responses, epss_batches, mock_get, mock_post, is_last_retry=False):
    report_data = {"technology_identities": identities, "cve_enrichment_status": "QUEUED"}
        
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{"id": "scan-123", "report_data": report_data}]
    
    mock_cache_resp = Mock()
    mock_cache_resp.status_code = 200
    mock_cache_resp.json.return_value = []
    
    side_effects = [mock_scan_resp]
    for nvd_resp in nvd_mock_responses:
        side_effects.append(mock_cache_resp)
        side_effects.append(nvd_resp)
        
    for epss_resp in epss_batches:
        side_effects.append(epss_resp)
        
    mock_get.side_effect = side_effects
    
    mock_claim_resp = Mock()
    mock_claim_resp.status_code = 200
    mock_claim_resp.json.return_value = True
    
    # Needs a ton of mock_claim_resp and mock_post for cache saves + final save
    mock_post.side_effect = [mock_claim_resp] * 200 
    
    headers = {"Upstash-Retried": "3"} if is_last_retry else {}
    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"}, headers=headers)
    
    return resp, mock_post.call_args_list, mock_get.call_args_list

def get_epss_resp(data, status_code=200):
    m = Mock()
    m.status_code = status_code
    if status_code == 200:
        m.json.return_value = {"data": data}
    return m

def get_nvd_resp(vulns):
    m = Mock()
    m.status_code = 200
    m.json.return_value = {"vulnerabilities": vulns}
    return m

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_epss_parsing(mock_get, mock_post):
    identities = [
        {"cpe_candidate": "cpe1", "version_precision": "EXACT_OBSERVED"},
        {"cpe_candidate": "cpe2", "version_precision": "EXACT_OBSERVED"},
        {"cpe_candidate": "cpe3", "version_precision": "EXACT_OBSERVED"},
    ]
    vulns1 = [{"cve": {"id": f"CVE-{i}" }} for i in range(1, 6)]
    vulns2 = [{"cve": {"id": f"CVE-{i}" }} for i in range(6, 11)]
    vulns3 = [{"cve": {"id": f"CVE-{i}" }} for i in range(11, 16)]

    epss_data = [
        {"cve": "CVE-1", "epss": "0.74231", "percentile": "0.9812", "date": "2026-09-18"},
        {"cve": "CVE-2", "epss": "0.0", "percentile": "0.0", "created": "2026-09-19"},
        {"cve": "CVE-3", "epss": "1.0", "percentile": "1.0", "date": "2026-09-20"},
        {"cve": "CVE-4", "epss": "NaN", "percentile": "0.5", "date": "2026-09-21"}, 
        {"cve": "CVE-5", "epss": "0.5", "percentile": "1.5", "date": "2026-09-21"}, 
        {"cve": "CVE-6", "epss": "0.5", "percentile": "0.5"}, # missing date
        {"cve": "CVE-7", "epss": "0.5", "percentile": "0.5", "date": "2026-02-30"}, # invalid date
        {"cve": "CVE-8", "epss": "0.5", "percentile": "0.5", "date": "2026/09/18"}, # malformed date format
        {"cve": "CVE-9", "epss": True, "percentile": "0.5", "date": "2026-09-18"}, # bool score
        {"cve": "CVE-10", "epss": "0.5", "percentile": False, "date": "2026-09-18"}, # bool perc
        {"cve": "CVE-11", "epss": "-0.1", "percentile": "0.5", "date": "2026-09-18"}, # out of range
        {"cve": "CVE-12", "epss": "Infinity", "percentile": "0.5", "date": "2026-09-18"}, # Infinity
        {"cve": "CVE-13", "epss": "0.5", "percentile": "0.5", "date": "2026-09-18"},
        {"cve": "CVE-13", "epss": "0.9", "percentile": "0.9", "date": "2026-09-23"}, # duplicate response
        # 14, 15 are missing entirely
    ]
    resp, post_calls, get_calls = run_enrichment(identities, [get_nvd_resp(vulns1), get_nvd_resp(vulns2), get_nvd_resp(vulns3)], [get_epss_resp(epss_data)], mock_get, mock_post)
    assert resp.status_code == 200
    
    save_call = next(call for call in post_calls if "atomic_save_enriched_identities" in call[0][0])
    p_ids = save_call[1]["json"]["p_identities"]
    cves = p_ids[0]["cves"] + p_ids[1]["cves"] + p_ids[2]["cves"]
    
    def get_epss(cve_id):
        return next(c for c in cves if c["id"] == cve_id)["epss"]
        
    assert get_epss("CVE-1")["score"] == 0.74231
    assert get_epss("CVE-2")["score"] == 0.0
    assert get_epss("CVE-2")["score_date"] == "2026-09-19" # created fallback
    assert get_epss("CVE-3")["score"] == 1.0
    assert get_epss("CVE-4") is None # NaN
    assert get_epss("CVE-5") is None # bounds
    assert get_epss("CVE-6") is None # missing date
    assert get_epss("CVE-7") is None # invalid calendar date
    assert get_epss("CVE-8") is None # invalid format
    assert get_epss("CVE-9") is None # boolean
    assert get_epss("CVE-10") is None # boolean
    assert get_epss("CVE-11") is None # out of bounds
    assert get_epss("CVE-12") is None # Infinity
    assert get_epss("CVE-13")["score"] == 0.5 # duplicate test, uses first valid record
    assert get_epss("CVE-14") is None # absent
    assert get_epss("CVE-15") is None # absent

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_global_batching(mock_get, mock_post):
    identities = [{"cpe_candidate": f"cpe{i}", "version_precision": "EXACT_OBSERVED"} for i in range(100)]
    
    nvd_mocks = []
    cve_counter = 0
    for i in range(100):
        # 5 CVEs per identity = 500 total unique CVEs
        vulns = [{"cve": {"id": f"CVE-2024-{cve_counter+j:05d}"}} for j in range(5)]
        nvd_mocks.append(get_nvd_resp(vulns))
        cve_counter += 5
        
    epss_mocks = [get_epss_resp([]) for _ in range(10)]
    
    resp, post_calls, get_calls = run_enrichment(identities, nvd_mocks, epss_mocks, mock_get, mock_post)
    assert resp.status_code == 200
    
    epss_queries = [call[0][0] for call in get_calls if "api.first.org" in call[0][0]]
    assert len(epss_queries) >= 3
    
    for url in epss_queries:
        assert len(url.split("?cve=")[1]) <= 1800
        
    save_call = next(call for call in post_calls if "atomic_save_enriched_identities" in call[0][0])
    p_ids = save_call[1]["json"]["p_identities"]
    assert len(p_ids) == 100
    for i in range(100):
        assert len(p_ids[i]["cves"]) == 5

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_terminal_failure(mock_get, mock_post):
    identities = [{"cpe_candidate": "cpe", "version_precision": "EXACT_OBSERVED"}]
    nvd_mocks = [get_nvd_resp([{"cve": {"id": "CVE-1"}}])]
    
    # transient
    resp, _, _ = run_enrichment(identities, nvd_mocks, [get_epss_resp([], 500)], mock_get, mock_post)
    assert resp.status_code == 503
    
    # terminal
    resp2, post_calls, get_calls = run_enrichment(identities, nvd_mocks, [get_epss_resp([], 500)], mock_get, mock_post, is_last_retry=True)
    assert resp2.status_code == 200
    
    # #v4 cache must NOT be saved!
    cache_saves = [call for call in post_calls if "cpe_cve_cache" in call[0][0]]
    assert len(cache_saves) == 0
    
    save_call = next(call for call in post_calls if "atomic_save_enriched_identities" in call[0][0])
    payload = save_call[1]["json"]
    assert payload["p_status"] == "COMPLETED"
    assert len(payload["p_identities"][0]["cves"]) == 1
    assert payload["p_identities"][0]["cves"][0]["epss"] is None
    assert payload["p_identities"][0]["vulnerability_state"] == "MATCHED"

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_cache_v4(mock_get, mock_post):
    identities = [{"cpe_candidate": "cpe", "version_precision": "EXACT_OBSERVED"}]
    nvd_mocks = [get_nvd_resp([{"cve": {"id": "CVE-1"}}])]
    
    resp, post_calls, get_calls = run_enrichment(identities, nvd_mocks, [get_epss_resp([])], mock_get, mock_post)
    assert resp.status_code == 200
    
    cache_queries = [call[0][0] for call in get_calls if "cpe_cve_cache" in call[0][0]]
    assert "%23v4" in cache_queries[0]
    
    cache_saves = [call[1]["json"] for call in post_calls if "cpe_cve_cache" in call[0][0]]
    assert len(cache_saves) == 1
    assert cache_saves[0]["cpe"].endswith("#v4")
    # And check that epss is present in the cache payload
    assert "epss" in cache_saves[0]["cves_json"][0]

