import pytest
import responses
import requests
from unittest.mock import patch
from datetime import datetime, timezone, timedelta
from api.scanner.cve_sync import sync_cpe_cve_cache
from api.scanner.cve_mapper import get_cached_cves

@pytest.fixture
def mock_env():
    with patch.dict('os.environ', {'SUPABASE_URL': 'http://mock-supabase', 'SUPABASE_SECRET_KEY': 'mock-key'}):
        yield

@responses.activate
def test_sync_cpe_cve_cache_success(mock_env):
    cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    
    # Mock NVD
    responses.add(
        responses.GET,
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={requests.utils.quote(cpe)}",
        json={
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-23017",
                        "published": "2021-05-25T19:15:00Z",
                        "lastModified": "2021-06-03T19:15:00Z",
                        "descriptions": [{"lang": "en", "value": "A security issue in nginx."}]
                    }
                }
            ]
        },
        status=200
    )
    
    # Mock Supabase Upsert
    responses.add(
        responses.POST,
        "http://mock-supabase/rest/v1/cpe_cve_cache",
        json={},
        status=201
    )
    
    sess = requests.Session()
    result = sync_cpe_cve_cache(cpe, session=sess)
    
    assert result is True
    
    
    # Check payload sent to Supabase
    post_call = next(c for c in responses.calls if c.request.method == "POST")
    payload = post_call.request.body
    import json
    data = json.loads(payload.decode('utf-8'))
    
    assert data["cpe"] == cpe
    assert len(data["cves_json"]) == 1
    
    cve_rec = data["cves_json"][0]
    assert cve_rec["id"] == "CVE-2021-23017"
    assert cve_rec["cpe"] == cpe
    assert cve_rec["summary"] == "A security issue in nginx."
    
    prov = cve_rec["provenance"]
    assert prov["source"] == "NVD"
    assert prov["source_timestamp"] == "2021-06-03T19:15:00Z"

@responses.activate
def test_sync_cpe_cve_cache_nvd_failure(mock_env):
    cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    
    responses.add(
        responses.GET,
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={requests.utils.quote(cpe)}",
        status=503
    )
    
    sess = requests.Session()
    result = sync_cpe_cve_cache(cpe, session=sess)
    
    # Should fail cleanly, preserving existing cache
    assert result is False
    nvd_calls = [call for call in responses.calls if "nvd.nist.gov" in call.request.url]
    assert len(nvd_calls) == 1
    cache_get = [call for call in responses.calls if "cpe_cve_cache" in call.request.url and call.request.method == "GET"]
    assert len(cache_get) == 1

@responses.activate
def test_sync_cpe_cve_cache_deduplication(mock_env):
    cpe = "cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*"
    
    # Mock NVD with duplicate CVE
    responses.add(
        responses.GET,
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={requests.utils.quote(cpe)}",
        json={
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-TEST-1",
                        "published": "2021-05-25T19:15:00Z"
                    }
                },
                {
                    "cve": {
                        "id": "CVE-TEST-1",
                        "published": "2021-05-25T19:15:00Z"
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
    
    post_call = next(c for c in responses.calls if c.request.method == "POST")
    import json
    data = json.loads(post_call.request.body.decode('utf-8'))
    
    # Should only have 1 CVE due to deduplication
    assert len(data["cves_json"]) == 1
    assert data["cves_json"][0]["id"] == "CVE-TEST-1"

@responses.activate
def test_get_cached_cves_success():
    cpe = "cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*"
    
    import urllib.parse
    import re
    # We use regex to match the URL because expires_at changes
    url_pattern = re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache\?cpe=eq\..*")
    
    responses.add(
        responses.GET,
        url_pattern,
        json=[{
            "cves_json": [{"id": "CVE-TEST-1", "summary": "Test"}]
        }],
        status=200
    )
    
    sess = requests.Session()
    result = get_cached_cves(cpe, "http://mock-supabase", "mock-key", session=sess)
    
    assert result is not None
    assert len(result) == 1
    assert result[0]["id"] == "CVE-TEST-1"

@responses.activate
def test_get_cached_cves_stale_or_missing():
    cpe = "cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*"
    
    import re
    url_pattern = re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache\?cpe=eq\..*")
    
    # Return empty list representing no active cache record
    responses.add(
        responses.GET,
        url_pattern,
        json=[],
        status=200
    )
    
    sess = requests.Session()
    result = get_cached_cves(cpe, "http://mock-supabase", "mock-key", session=sess)
    
    assert result is None
