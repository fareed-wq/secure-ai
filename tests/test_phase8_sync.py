import pytest
import responses
import re
import asyncio
from unittest.mock import patch, MagicMock
from api.scanner.cve_sync import sync_cpe_cve_cache
from api.scanner.cve_mapper import get_cached_cves
import json
import urllib.parse
from datetime import datetime, timezone, timedelta

@pytest.fixture
def mock_env(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "http://mock-supabase")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "test-key")
    monkeypatch.setenv("QSTASH_CURRENT_SIGNING_KEY", "test")
    monkeypatch.setenv("QSTASH_NEXT_SIGNING_KEY", "test")

@responses.activate
def test_13_normal_scan_no_external_calls(mock_env):
    # 13. normal scan still performs no external vulnerability-intelligence network calls
    # 11. shell-record creation only once
    cpe = "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*"
    encoded_cpe = urllib.parse.quote(cpe)

    responses.add(
        responses.GET,
        re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache.*"),
        json=[],
        status=200
    )
    responses.add(
        responses.POST,
        "http://mock-supabase/rest/v1/cpe_cve_cache",
        json={},
        status=201
    )

    res = get_cached_cves(cpe, "http://mock-supabase", "test")
    assert res is None

    # Assert no NVD calls
    for call in responses.calls:
        assert "nvd.nist.gov" not in call.request.url

    # Assert shell record inserted
    post_calls = [c for c in responses.calls if c.request.method == "POST"]
    assert len(post_calls) == 1
    req_body = json.loads(post_calls[0].request.body)
    assert req_body["cpe"] == cpe
    assert req_body["expires_at"] == "1970-01-01T00:00:00Z"

@responses.activate
def test_7_nvd_failure_preserves(mock_env):
    # 7. NVD failure preserves existing cache
    # 10. stale/current semantics (backoff bump)
    cpe = "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*"
    encoded_cpe = urllib.parse.quote(cpe)

    responses.add(
        responses.GET,
        re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache.*"),
        json=[{"cpe": cpe, "cves_json": [{"id": "CVE-old"}], "expires_at": "2020-01-01T00:00:00Z"}],
        status=200
    )
    responses.add(
        responses.GET,
        re.compile(r"https://services.nvd.nist.gov/rest/json/cves/2.0.*"),
        status=503
    )
    responses.add(
        responses.PATCH,
        re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache.*"),
        json={},
        status=200
    )

    res = sync_cpe_cve_cache(cpe)
    assert res is False

    patch_calls = [c for c in responses.calls if c.request.method == "PATCH"]
    post_calls = [c for c in responses.calls if c.request.method == "POST"]
    assert len(patch_calls) == 1
    assert len(post_calls) == 0

from api.scanner.enrich_worker import sync_intelligence_worker
from fastapi import Request, HTTPException

@responses.activate
def test_1_3_4_scheduled_sync(mock_env):
    # 1. authenticated scheduled trigger
    # 3. scheduled trigger invokes sync
    # 4. stale CPE selection bounded to 10
    responses.add(
        responses.GET,
        re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache\?expires_at=lt.*limit=10"),
        json=[
            {"cpe": "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*"},
            {"cpe": "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"}
        ],
        status=200
    )

    with patch("api.scanner.cve_sync.sync_cpe_cve_cache") as mock_sync, \
         patch("api.scanner.enrich_worker.SUPABASE_URL", "http://mock-supabase"), \
         patch("api.scanner.enrich_worker.SUPABASE_SECRET_KEY", "test-key"):
        mock_sync.return_value = True

        req = MagicMock(spec=Request)
        res = asyncio.run(sync_intelligence_worker(req, verified=True))

        assert res.status_code == 200
        body = json.loads(res.body)
        assert body["status"] == "completed"
        assert body["synced"] == 2
        assert mock_sync.call_count == 2

@responses.activate
def test_8_epss_failure_preserves(mock_env):
    # 8. FIRST EPSS failure preserves existing EPSS
    cpe = "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*"
    encoded_cpe = urllib.parse.quote(cpe)

    responses.add(
        responses.GET,
        re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache.*"),
        json=[{"cpe": cpe, "cves_json": [
            {
                "id": "CVE-2021-1234",
                "epss_info": {"status": "AVAILABLE", "epss": 0.5},
            }
        ], "expires_at": "2020-01-01T00:00:00Z", "updated_at": "2020-01-01T00:00:00Z"}],
        status=200
    )
    responses.add(
        responses.GET,
        re.compile(r"https://services.nvd.nist.gov/rest/json/cves/2.0.*"),
        json={
            "vulnerabilities": [{
                "cve": {"id": "CVE-2021-1234", "descriptions": [], "metrics": {}}
            }]
        },
        status=200
    )
    responses.add(
        responses.GET,
        re.compile(r"https://api.first.org/data/v1/epss.*"),
        status=503
    )
    responses.add(
        responses.PATCH,
        re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache.*"),
        json=[{"id": "patched"}],
        status=200
    )

    res = sync_cpe_cve_cache(cpe)
    assert res is True

    patch_calls = [c for c in responses.calls if c.request.method == "PATCH" and "updated_at=eq" in c.request.url]
    assert len(patch_calls) == 1
    req_body = json.loads(patch_calls[0].request.body)
    saved_cves = req_body["cves_json"]

    assert len(saved_cves) == 1
    cve = saved_cves[0]

    # EPSS failed (standalone API) so it MUST preserve old
    assert cve["epss_info"]["status"] == "AVAILABLE"
    assert cve["epss_info"]["epss"] == 0.5

@responses.activate
def test_12_concurrent_overwrite_protection(mock_env):
    # 12. concurrent/stale overwrite protection
    cpe = "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*"
    encoded_cpe = urllib.parse.quote(cpe)

    responses.add(
        responses.GET,
        re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache.*"),
        json=[{"cpe": cpe, "cves_json": [], "expires_at": "2020-01-01T00:00:00Z", "updated_at": "OLD_TIME"}],
        status=200
    )
    responses.add(
        responses.GET,
        re.compile(r"https://services.nvd.nist.gov/rest/json/cves/2.0.*"),
        json={"vulnerabilities": []},
        status=200
    )

    # 0 rows returned = concurrent update happened
    responses.add(
        responses.PATCH,
        re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache.*updated_at=eq\.OLD_TIME.*"),
        json=[],
        status=200
    )

    res = sync_cpe_cve_cache(cpe)
    assert res is True # Yields silently

@responses.activate
def test_duplicate_stale_cpe_elimination(mock_env):
    responses.add(
        responses.GET,
        re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache\?expires_at=lt.*limit=10"),
        json=[
            {"cpe": "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*"},
            {"cpe": "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*"}
        ],
        status=200
    )

    with patch("api.scanner.cve_sync.sync_cpe_cve_cache") as mock_sync, \
         patch("api.scanner.enrich_worker.SUPABASE_URL", "http://mock-supabase"), \
         patch("api.scanner.enrich_worker.SUPABASE_SECRET_KEY", "test-key"):
        mock_sync.return_value = True

        req = MagicMock(spec=Request)
        res = asyncio.run(sync_intelligence_worker(req, verified=True))

        body = json.loads(res.body)
        assert body["synced"] == 1
        assert mock_sync.call_count == 1

@responses.activate
def test_one_cpe_failure_does_not_corrupt_others(mock_env):
    responses.add(
        responses.GET,
        re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache\?expires_at=lt.*limit=10"),
        json=[
            {"cpe": "cpe:2.3:a:bad:cpe:1.0:*:*:*:*:*:*:*"},
            {"cpe": "cpe:2.3:a:good:cpe:1.0:*:*:*:*:*:*:*"}
        ],
        status=200
    )

    def side_effect(cpe, session):
        if "bad" in cpe: return False
        return True

    with patch("api.scanner.cve_sync.sync_cpe_cve_cache") as mock_sync, \
         patch("api.scanner.enrich_worker.SUPABASE_URL", "http://mock-supabase"), \
         patch("api.scanner.enrich_worker.SUPABASE_SECRET_KEY", "test-key"):
        mock_sync.side_effect = side_effect

        req = MagicMock(spec=Request)
        res = asyncio.run(sync_intelligence_worker(req, verified=True))

        body = json.loads(res.body)
        assert body["synced"] == 1
        assert body["failed"] == 1
        assert mock_sync.call_count == 2

@responses.activate
def test_successful_refresh_resets_freshness(mock_env):
    cpe = "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*"
    responses.add(
        responses.GET,
        re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache.*select=.*\*"),
        json=[],
        status=200
    )
    responses.add(
        responses.GET,
        re.compile(r"https://services.nvd.nist.gov/rest/json/cves/2.0.*"),
        json={"vulnerabilities": []},
        status=200
    )
    responses.add(
        responses.POST,
        re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache"),
        json={},
        status=201
    )

    res = sync_cpe_cve_cache(cpe)
    assert res is True

    post_calls = [c for c in responses.calls if c.request.method == "POST"]
    assert len(post_calls) == 1
    req_body = json.loads(post_calls[0].request.body)

    expires = datetime.fromisoformat(req_body["expires_at"].replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    diff = expires - now
    assert 6 <= diff.days <= 7
