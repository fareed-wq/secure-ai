import os
os.environ["VITE_SUPABASE_URL"] = "http://localhost:8000"
os.environ["SUPABASE_SECRET_KEY"] = "mock_key"
os.environ["QSTASH_CURRENT_SIGNING_KEY"] = "mock_qstash"
os.environ["QSTASH_NEXT_SIGNING_KEY"] = "mock_qstash"

from api.scanner.enrich_worker import verify_qstash_signature
from api.index import app
app.dependency_overrides[verify_qstash_signature] = lambda: True

import pytest
import copy
from unittest.mock import patch, Mock
from datetime import datetime, timezone
from fastapi.testclient import TestClient

client = TestClient(app)

def run_enrichment(identities, nvd_vulns, mock_get, mock_post, cache_returns=None, report_data_extra=None):
    report_data = {"technology_identities": identities, "cve_enrichment_status": "QUEUED"}
    if report_data_extra:
        report_data.update(report_data_extra)
        
    mock_scan_resp = Mock()
    mock_scan_resp.status_code = 200
    mock_scan_resp.json.return_value = [{"id": "scan-123", "report_data": report_data}]
    
    mock_cache_resp = Mock()
    mock_cache_resp.status_code = 200
    mock_cache_resp.json.return_value = cache_returns if cache_returns is not None else []
    
    mock_nvd_resp = Mock()
    mock_nvd_resp.status_code = 200
    mock_nvd_resp.json.return_value = {"vulnerabilities": nvd_vulns}
    
    mock_epss = Mock(status_code=200); mock_epss.json.return_value = {"data": []}; mock_get.side_effect = [mock_scan_resp, mock_cache_resp, mock_nvd_resp, mock_epss, mock_epss, mock_epss, mock_epss]
    
    mock_claim_resp = Mock()
    mock_claim_resp.status_code = 200
    mock_claim_resp.json.return_value = True
    mock_post.side_effect = [mock_claim_resp, mock_claim_resp, mock_claim_resp]
    
    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"})
    assert resp.status_code == 200, resp.json()
    
    save_call = None
    for call in mock_post.call_args_list:
        if "atomic_save_enriched_identities" in call[0][0]:
            save_call = call[1]["json"]
    return save_call["p_identities"] if save_call else None


@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_cvss_40(mock_get, mock_post):
    identities = [{"cpe_candidate": "cpe", "version_precision": "EXACT_OBSERVED"}]
    vulns = [{"cve": {"id": "CVE-1", "metrics": {"cvssMetricV40": [{"source": "nvd", "type": "Primary", "cvssData": {"version": "4.0", "baseScore": 9.0, "baseSeverity": "CRITICAL", "baseScore": 9.8, "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}]}}}]
    saved = run_enrichment(identities, vulns, mock_get, mock_post)
    cve = saved[0]["cves"][0]
    assert len(cve["cvss_assessments"]) == 1
    assert cve["cvss_assessments"][0]["version"] == "4.0"
    assert cve["cvss_assessments"][0]["base_score"] == 9.8
    assert cve["cvss_assessments"][0]["base_severity"] == "CRITICAL"
    assert cve["cvss_assessments"][0]["vector_string"] == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_cvss_31_and_30(mock_get, mock_post):
    identities = [{"cpe_candidate": "cpe", "version_precision": "EXACT_OBSERVED"}]
    vulns = [{"cve": {"id": "CVE-1", "metrics": {
        "cvssMetricV31": [{"source": "nvd", "type": "Primary", "cvssData": {"version": "3.1", "baseScore": 8.0, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}}],
        "cvssMetricV30": [{"source": "cna", "type": "Secondary", "cvssData": {"version": "3.0", "baseScore": 7.5, "baseSeverity": "HIGH"}}]
    }}}]
    saved = run_enrichment(identities, vulns, mock_get, mock_post)
    cve = saved[0]["cves"][0]
    assert len(cve["cvss_assessments"]) == 2
    versions = [a["version"] for a in cve["cvss_assessments"]]
    assert "3.1" in versions and "3.0" in versions
    v31_assessment = next(a for a in cve["cvss_assessments"] if a["version"] == "3.1")
    assert v31_assessment["vector_string"] == "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_cvss_20_historical(mock_get, mock_post):
    identities = [{"cpe_candidate": "cpe", "version_precision": "EXACT_OBSERVED"}]
    vulns = [{"cve": {"id": "CVE-1", "metrics": {"cvssMetricV2": [{"source": "nvd", "type": "Primary", "baseSeverity": "MEDIUM", "cvssData": {"version": "2.0", "baseScore": 5.0}}]}}}]
    saved = run_enrichment(identities, vulns, mock_get, mock_post)
    cve = saved[0]["cves"][0]
    assert len(cve["cvss_assessments"]) == 1
    assert cve["cvss_assessments"][0]["version"] == "2.0"
    assert cve["cvss_assessments"][0]["base_severity"] == "MEDIUM"

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_cvss_conflicting(mock_get, mock_post):
    identities = [{"cpe_candidate": "cpe", "version_precision": "EXACT_OBSERVED"}]
    vulns = [{"cve": {"id": "CVE-1", "metrics": {"cvssMetricV31": [
        {"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL", "baseScore": 9.8}},
        {"source": "cna@example.com", "type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 4.3, "baseSeverity": "MEDIUM"}}
    ]}}}]
    saved = run_enrichment(identities, vulns, mock_get, mock_post)
    cve = saved[0]["cves"][0]
    assert len(cve["cvss_assessments"]) == 2
    sources = [a["source"] for a in cve["cvss_assessments"]]
    assert "nvd@nist.gov" in sources and "cna@example.com" in sources
    types = [a["type"] for a in cve["cvss_assessments"]]
    assert "Primary" in types and "Secondary" in types

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_cvss_cna_only(mock_get, mock_post):
    identities = [{"cpe_candidate": "cpe", "version_precision": "EXACT_OBSERVED"}]
    vulns = [{"cve": {"id": "CVE-1", "metrics": {"cvssMetricV31": [
        {"source": "cna@example.com", "type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 6.5, "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"}}
    ]}}}]
    saved = run_enrichment(identities, vulns, mock_get, mock_post)
    cve = saved[0]["cves"][0]
    
    assert len(cve["cvss_assessments"]) == 1
    assessment = cve["cvss_assessments"][0]
    assert assessment["source"] == "cna@example.com"
    assert assessment["type"] == "Secondary"
    assert assessment["version"] == "3.1"
    assert assessment["base_score"] == 6.5
    assert assessment["base_severity"] == "MEDIUM"
    assert assessment["vector_string"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_cvss_absent(mock_get, mock_post):
    identities = [{"cpe_candidate": "cpe", "version_precision": "EXACT_OBSERVED"}]
    vulns = [{"cve": {"id": "CVE-1", "metrics": {}}}]
    saved = run_enrichment(identities, vulns, mock_get, mock_post)
    assert saved[0]["cves"][0]["cvss_assessments"] == []

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_cwe_multiple_and_absent(mock_get, mock_post):
    identities = [{"cpe_candidate": "cpe", "version_precision": "EXACT_OBSERVED"}]
    vulns = [
        {"cve": {"id": "CVE-1", "weaknesses": [{"source": "nvd", "type": "Primary", "description": [{"value": "CWE-79"}]}, {"source": "cna", "type": "Secondary", "description": [{"value": "CWE-89"}]}]}},
        {"cve": {"id": "CVE-2", "weaknesses": []}}
    ]
    saved = run_enrichment(identities, vulns, mock_get, mock_post)
    cves = saved[0]["cves"]
    assert len(cves[0]["cwes"]) == 2
    assert cves[0]["cwes"][0]["cwe_id"] == "CWE-79"
    assert cves[0]["cwes"][1]["cwe_id"] == "CWE-89"
    assert len(cves[1]["cwes"]) == 0

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_malformed_metadata_preserves_cve(mock_get, mock_post):
    identities = [{"cpe_candidate": "cpe", "version_precision": "EXACT_OBSERVED"}]
    vulns = [{"cve": {
        "id": "CVE-1",
        "metrics": {"cvssMetricV31": [{"source": "nvd"}]},
        "weaknesses": [{"description": "not a list"}]
    }}]
    saved = run_enrichment(identities, vulns, mock_get, mock_post)
    cve = saved[0]["cves"][0]
    assert cve["id"] == "CVE-1"
    assert len(cve["cvss_assessments"]) == 0
    assert len(cve["cwes"]) == 0

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_provenance_preservation(mock_get, mock_post):
    identities = [{"cpe_candidate": "cpe", "version_precision": "EXACT_OBSERVED"}]
    vulns = [{"cve": {
        "id": "CVE-1",
        "sourceIdentifier": "cna@example.com",
        "published": "2023-01-01T00:00Z",
        "lastModified": "2023-01-10T00:00Z"
    }}]
    saved = run_enrichment(identities, vulns, mock_get, mock_post)
    metadata = saved[0]["cves"][0]["metadata"]
    assert metadata["source_identifier"] == "cna@example.com"
    assert metadata["published_at"] == "2023-01-01T00:00Z"
    assert metadata["last_modified_at"] == "2023-01-10T00:00Z"
    assert "fetched_at" in metadata

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_cache_version_boundary(mock_get, mock_post):
    identities = [{"cpe_candidate": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", "version_precision": "EXACT_OBSERVED"}]
    
    def mock_get_side_effect(*args, **kwargs):
        url = args[0]
        if "scans?id=eq" in url:
            return Mock(status_code=200, json=lambda: [{"id": "scan-123", "report_data": {"technology_identities": identities, "cve_enrichment_status": "QUEUED"}}])
        elif "cpe_cve_cache" in url:
            if "%23v3" in url:
                # Legacy cache: <cpe>#v3 -> old Phase 5A CVE payload
                return Mock(status_code=200, json=lambda: [{"cves_json": [{"id": "CVE-1", "summary": "old payload without cvss_assessments"}]}])
            elif "%23v4" in url:
                # Phase 5B cache: <cpe>#v4 -> no entry
                return Mock(status_code=200, json=lambda: [])
        elif "nvd.nist.gov" in url:
            return Mock(status_code=200, json=lambda: {"vulnerabilities": [{"cve": {"id": "CVE-1", "metrics": {"cvssMetricV40": [{"cvssData": {"version": "4.0", "baseSeverity": "CRITICAL", "baseScore": 9.8}}]}}}]})
        return Mock(status_code=200, json=lambda: {"data": []})
        
    mock_get.side_effect = mock_get_side_effect
    
    mock_claim_resp = Mock()
    mock_claim_resp.status_code = 200
    mock_claim_resp.json.return_value = True
    mock_post.side_effect = [mock_claim_resp, mock_claim_resp, mock_claim_resp]
    
    client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"})
    
    cache_queries = [call[0][0] for call in mock_get.call_args_list if "cpe_cve_cache" in call[0][0]]
    assert len(cache_queries) == 1
    cache_query_url = cache_queries[0]
    
    assert "%23v4" in cache_query_url
    assert "%23v3" not in cache_query_url
    
    nvd_queries = [call[0][0] for call in mock_get.call_args_list if "nvd.nist.gov" in call[0][0]]
    assert len(nvd_queries) == 1
    
    cache_save_payload = mock_post.call_args_list[1][1]["json"]
    assert cache_save_payload["cpe"].endswith("#v4")

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_phase5a_immutability(mock_get, mock_post):
    identities = [{
        "cpe_candidate": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
        "cpe_match_confidence": "HIGH",
        "vulnerability_state": "NOT_EVALUATED",
        "vulnerability_state_reason": None,
        "version_precision": "EXACT_OBSERVED",
        "sources": [{"source_type": "server_header"}]
    }]
    
    before_input = copy.deepcopy(identities[0])
    
    expected_vulnerability_state = "MATCHED"
    expected_vulnerability_state_reason = None
    expected_cpe_candidate = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    expected_cpe_match_confidence = "HIGH"
    expected_match_confidence = "MEDIUM" 
    expected_rationale_code = "SPOOFABLE_SOURCE"
    
    vulns = [{"cve": {"id": "CVE-1", "metrics": {"cvssMetricV40": [{"cvssData": {"version": "4.0", "baseSeverity": "CRITICAL", "baseScore": 9.8}}]}}}]
    saved = run_enrichment(identities, vulns, mock_get, mock_post)
    
    after_identity = saved[0]
    cve = after_identity["cves"][0]
    
    assert after_identity["vulnerability_state"] == expected_vulnerability_state
    assert after_identity["vulnerability_state_reason"] == expected_vulnerability_state_reason
    assert after_identity["cpe_candidate"] == expected_cpe_candidate
    assert after_identity["cpe_match_confidence"] == expected_cpe_match_confidence
    assert cve["match_confidence"] == expected_match_confidence
    assert cve["rationale_code"] == expected_rationale_code
    assert type(cve["rationale_text"]) is str and "spoofable" in cve["rationale_text"].lower()
    
    assert cve["cvss_assessments"][0]["version"] == "4.0"

@patch("api.scanner.enrich_worker.requests.post")
@patch("api.scanner.enrich_worker.requests.get")
def test_score_severity_firewall(mock_get, mock_post):
    identities = [{"cpe_candidate": "cpe", "version_precision": "EXACT_OBSERVED"}]
    vulns = [{"cve": {"id": "CVE-1", "metrics": {"cvssMetricV31": [{"cvssData": {"version": "3.1", "baseScore": 10.0, "baseSeverity": "CRITICAL", "baseScore": 9.8}}]}}}]
    
    report_data_extra = {
        "score": 100,
        "severity": "LOW",
        "grade": "A"
    }
    
    run_enrichment(identities, vulns, mock_get, mock_post, report_data_extra=report_data_extra)
    
    save_call = None
    for call in mock_post.call_args_list:
        if "atomic_save_enriched_identities" in call[0][0]:
            save_call = call[1]["json"]
            
    assert save_call is not None
    assert "p_score" not in save_call
    assert "p_severity" not in save_call
    assert "p_grade" not in save_call
    assert list(save_call.keys()) == ["p_scan_id", "p_expected_status", "p_status", "p_identities"]
    
    # LIMITATION: 
    # Because atomic_save_enriched_identities is a Postgres RPC executed in Supabase,
    # the Python worker has zero visibility into the resulting persisted report_data JSONB.
    # Therefore, asserting the final merged document safely without introducing new architecture
    # or querying the database post-RPC is impossible in a mocked unit test.
