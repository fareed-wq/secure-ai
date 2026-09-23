import pytest
import responses
import requests
import json
from unittest.mock import patch
from datetime import datetime, timezone, timedelta
from api.scanner.cve_sync import sync_cpe_cve_cache
from api.scanner.cve_mapper import get_cached_cves

@pytest.fixture
def mock_env():
    with patch.dict('os.environ', {'SUPABASE_URL': 'http://mock-supabase', 'SUPABASE_SECRET_KEY': 'mock-key'}):
        yield

@responses.activate
def test_sync_cpe_cve_cache_full_cvss_cwe(mock_env):
    cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    
    responses.add(
        responses.GET,
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={requests.utils.quote(cpe)}",
        json={
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-FULL",
                        "published": "2021-05-25T19:15:00Z",
                        "lastModified": "2021-06-03T19:15:00Z",
                        "descriptions": [{"lang": "en", "value": "Desc"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "source": "nvd@nist.gov",
                                    "type": "Primary",
                                    "cvssData": {
                                        "version": "3.1",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL"
                                    }
                                }
                            ]
                        },
                        "weaknesses": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "description": [{"lang": "en", "value": "CWE-79"}]
                            },
                            {
                                "source": "nvd@nist.gov",
                                "type": "Secondary",
                                "description": [{"lang": "en", "value": "CWE-89"}]
                            }
                        ]
                    }
                }
            ]
        },
        status=200
    )
    
    responses.add(
        responses.POST,
        "http://mock-supabase/rest/v1/cpe_cve_cache",
        json={},
        status=201
    )
    
    sess = requests.Session()
    result = sync_cpe_cve_cache(cpe, session=sess)
    
    assert result is True
    post_call = next(c for c in responses.calls if c.request.method == 'POST')
    data = json.loads(post_call.request.body.decode('utf-8'))
    
    cve_rec = data["cves_json"][0]
    assert cve_rec["id"] == "CVE-FULL"
    assert cve_rec["cvss_score"] == 9.8
    assert cve_rec["cvss_severity"] == "CRITICAL"
    assert cve_rec["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert cve_rec["cvss_version"] == "3.1"
    assert cve_rec["cvss_source"] == "nvd@nist.gov"
    assert cve_rec["cwes"] == ["CWE-79", "CWE-89"]

@responses.activate
def test_sync_cpe_cve_cache_multiple_cvss_versions(mock_env):
    cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    responses.add(
        responses.GET,
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={requests.utils.quote(cpe)}",
        json={
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-VERSIONS",
                        "published": "2021-05-25T19:15:00Z",
                        "metrics": {
                            "cvssMetricV2": [
                                {
                                    "source": "nvd@nist.gov",
                                    "type": "Primary",
                                    "cvssData": {"version": "2.0", "vectorString": "AV:N", "baseScore": 5.0},
                                    "baseSeverity": "MEDIUM"
                                }
                            ],
                            "cvssMetricV31": [
                                {
                                    "source": "cna@example.com",
                                    "type": "Secondary",
                                    "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1", "baseScore": 7.5, "baseSeverity": "HIGH"}
                                }
                            ]
                        }
                    }
                }
            ]
        },
        status=200
    )
    responses.add(responses.POST, "http://mock-supabase/rest/v1/cpe_cve_cache", json={}, status=201)
    
    sess = requests.Session()
    sync_cpe_cve_cache(cpe, session=sess)
    post_call = next(c for c in responses.calls if c.request.method == "POST")
    data = json.loads(post_call.request.body.decode('utf-8'))
    
    cve_rec = data["cves_json"][0]
    # We expect V3.1 to take precedence if we follow V4 > V3.1 > V3.0 > V2
    # but also the source/version should be preserved exactly.
    assert cve_rec["cvss_score"] == 7.5
    assert cve_rec["cvss_severity"] == "HIGH"
    assert cve_rec["cvss_version"] == "3.1"
    assert cve_rec["cvss_source"] == "cna@example.com"
    assert cve_rec["cwes"] == []

@responses.activate
def test_sync_cpe_cve_cache_no_enrichment(mock_env):
    cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    responses.add(
        responses.GET,
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={requests.utils.quote(cpe)}",
        json={
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-NONE",
                        "published": "2021-05-25T19:15:00Z",
                        # NO metrics, NO weaknesses
                    }
                }
            ]
        },
        status=200
    )
    responses.add(responses.POST, "http://mock-supabase/rest/v1/cpe_cve_cache", json={}, status=201)
    
    sess = requests.Session()
    sync_cpe_cve_cache(cpe, session=sess)
    post_call = next(c for c in responses.calls if c.request.method == "POST")
    data = json.loads(post_call.request.body.decode('utf-8'))
    
    cve_rec = data["cves_json"][0]
    assert "cvss_score" not in cve_rec or cve_rec["cvss_score"] is None
    assert "cvss_severity" not in cve_rec or cve_rec["cvss_severity"] is None
    assert cve_rec["cwes"] == []

@responses.activate
def test_sync_cpe_cve_cache_duplicate_cwe(mock_env):
    cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    responses.add(
        responses.GET,
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={requests.utils.quote(cpe)}",
        json={
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-CWE",
                        "published": "2021-05-25T19:15:00Z",
                        "weaknesses": [
                            {"description": [{"lang": "en", "value": "CWE-79"}]},
                            {"description": [{"lang": "en", "value": "CWE-79"}]}, # duplicate
                            {"description": [{"lang": "fr", "value": "CWE-999"}]}, # ignored (not en)
                            {"description": [{"lang": "en", "value": "CWE-20"}]}
                        ]
                    }
                }
            ]
        },
        status=200
    )
    responses.add(responses.POST, "http://mock-supabase/rest/v1/cpe_cve_cache", json={}, status=201)
    
    sess = requests.Session()
    sync_cpe_cve_cache(cpe, session=sess)
    post_call = next(c for c in responses.calls if c.request.method == "POST")
    data = json.loads(post_call.request.body.decode('utf-8'))
    
    cve_rec = data["cves_json"][0]
    # CWES must be deduplicated and sorted deterministically
    assert cve_rec["cwes"] == ["CWE-20", "CWE-79"]


@responses.activate
def test_enrich_worker_offline_behavior(mock_env, monkeypatch):
    # Test that enrich_cve_worker DOES NOT make live network requests to NVD
    from fastapi.testclient import TestClient
    from api.index import app
    from api.scanner.enrich_worker import verify_qstash_signature
    import api.scanner.enrich_worker as ew
    monkeypatch.setattr(ew, "SUPABASE_URL", "http://mock-supabase")
    monkeypatch.setattr(ew, "SUPABASE_SECRET_KEY", "mock-key")
    
    app.dependency_overrides[verify_qstash_signature] = lambda: True
    client = TestClient(app)
    
    cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    identities = [{
        "cpe_candidate": cpe,
        "cpe_authority": "AUTHORITATIVE",
        "version_precision": "EXACT_OBSERVED",
        "sources": [{"source_type": "server_header"}]
    }]
    
    responses.add(
        responses.GET,
        "http://mock-supabase/rest/v1/scans?id=eq.scan-123",
        json=[{"id": "scan-123", "report_data": {"technology_identities": identities, "cve_enrichment_status": "QUEUED"}}],
        status=200
    )
    
    responses.add(
        responses.POST,
        "http://mock-supabase/rest/v1/rpc/atomic_update_cve_status",
        json=True,
        status=200
    )
    
    import urllib.parse
    import re
    url_pattern = re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache\?cpe=eq\..*")
    
    responses.add(
        responses.GET,
        url_pattern,
        json=[{
            "cves_json": [{"id": "CVE-1", "summary": "Test", "cvss_score": 9.8, "cvss_severity": "CRITICAL", "cvss_version": "3.1", "cvss_source": "nvd@nist.gov", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        }],
        status=200
    )
    
    responses.add(
        responses.POST,
        "http://mock-supabase/rest/v1/rpc/atomic_save_enriched_identities",
        json=True,
        status=200
    )
    
    # We explicitly do NOT mock NVD. If it attempts to reach NVD, responses will throw ConnectionError
    resp = client.post("/api/internal/enrich-cve", json={"scan_id": "scan-123"})
    assert resp.status_code == 200
    
    # Verify save payload
    save_call = [c for c in responses.calls if "atomic_save_enriched_identities" in c.request.url][0]
    import json
    saved = json.loads(save_call.request.body.decode('utf-8'))["p_identities"]
    
    assert saved[0]["vulnerability_state"] == "MATCHED"
    assert saved[0]["cves"][0]["cvss_score"] == 9.8
    assert saved[0]["cves"][0]["cvss_severity"] == "CRITICAL"
    assert saved[0]["cves"][0]["cvss_version"] == "3.1"
    assert saved[0]["cves"][0]["cvss_source"] == "nvd@nist.gov"
    assert saved[0]["cves"][0]["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@responses.activate
def test_sync_cpe_cve_cache_missing_cvss_fields(mock_env):
    cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    responses.add(
        responses.GET,
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={requests.utils.quote(cpe)}",
        json={
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-MISSING",
                        "published": "2021-05-25T19:15:00Z",
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "source": "nvd@nist.gov",
                                    "type": "Primary",
                                    "cvssData": {
                                        # completely empty cvssData
                                    }
                                }
                            ]
                        }
                    }
                }
            ]
        },
        status=200
    )
    responses.add(responses.POST, "http://mock-supabase/rest/v1/cpe_cve_cache", json={}, status=201)
    
    sess = requests.Session()
    import api.scanner.cve_sync as cs
    cs.sync_cpe_cve_cache(cpe, session=sess)
    
    import json
    post_call = next(c for c in responses.calls if c.request.method == "POST")
    data = json.loads(post_call.request.body.decode('utf-8'))
    cve_rec = data["cves_json"][0]
    
    # Must explicitly be None, not 0.0 or "UNKNOWN" or ""
    assert cve_rec.get("cvss_score") is None
    assert cve_rec.get("cvss_severity") is None
    assert cve_rec.get("cvss_vector") is None
    assert cve_rec.get("cvss_version") == "3.1" # Defaulted to the version block we matched
    assert cve_rec.get("cvss_source") == "nvd@nist.gov"
