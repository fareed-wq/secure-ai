import pytest
import responses
import requests
import json
from unittest.mock import patch
from datetime import datetime, timezone
from api.scanner.cve_sync import sync_cpe_cve_cache

@pytest.fixture
def mock_env():
    with patch.dict('os.environ', {'SUPABASE_URL': 'http://mock-supabase', 'SUPABASE_SECRET_KEY': 'mock-key'}):
        yield

@responses.activate
def test_sync_cpe_cve_cache_informational(mock_env):
    cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    
    # Mock NVD returning a CVE with KEV and SSVC
    responses.add(
        responses.GET,
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={requests.utils.quote(cpe)}",
        json={
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-INFORMATIONAL-1",
                        "published": "2021-05-25T19:15:00Z",
                        "cisaExploitAdd": "2021-11-03",
                        "cisaKnownRansomwareCampaignUse": "Known",
                        "metrics": {
                            "ssvc": [
                                {
                                    "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                                    "type": "Secondary",
                                    "ssvcData": {
                                        "version": "2.0.3",
                                        "timestamp": "2023-01-01T00:00:00Z",
                                        "options": [
                                            {"Exploitation": "active"},
                                            {"Automatable": "yes"},
                                            {"Technical Impact": "total"}
                                        ]
                                    }
                                }
                            ]
                        }
                    }
                },
                {
                    "cve": {
                        "id": "CVE-INFORMATIONAL-2",
                        "published": "2021-05-25T19:15:00Z",
                        # Missing KEV and SSVC
                    }
                }
            ]
        },
        status=200
    )
    
    # Mock EPSS bulk endpoint
    responses.add(
        responses.GET,
        "https://api.first.org/data/v1/epss?cve=CVE-INFORMATIONAL-1,CVE-INFORMATIONAL-2",
        json={
            "data": [
                {
                    "cve": "CVE-INFORMATIONAL-1",
                    "epss": "0.95",
                    "percentile": "0.99",
                    "date": "2023-01-01"
                }
                # CVE-INFORMATIONAL-2 missing EPSS
            ]
        },
        status=200
    )
    
    import re
    responses.add(
        responses.GET,
        re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache\?cpe=eq\..*"),
        json=[],
        status=200
    )
    import re
    responses.add(
        responses.GET,
        re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache\?cpe=eq\..*"),
        json=[],
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
    
    # Find the POST call
    post_call = None
    for call in responses.calls:
        if call.request.method == "POST":
            post_call = call
            break
            
    assert post_call is not None
    data = json.loads(post_call.request.body.decode('utf-8'))
    
    cves = data["cves_json"]
    assert len(cves) == 2
    
    cve1 = next(c for c in cves if c["id"] == "CVE-INFORMATIONAL-1")
    cve2 = next(c for c in cves if c["id"] == "CVE-INFORMATIONAL-2")
    
    # Verify KEV
    assert cve1["kev_info"]["status"] == "IN_KEV"
    assert cve1["kev_info"]["date_added"] == "2021-11-03"
    assert cve1["kev_info"]["known_ransomware_campaign_use"] == "Known"
    
    assert cve2["kev_info"]["status"] == "NOT_IN_KEV"
    assert cve2["kev_info"]["date_added"] is None
    
    # Verify SSVC
    assert cve1["ssvc_info"]["status"] == "AVAILABLE"
    assert cve1["ssvc_info"]["exploitation"] == "active"
    assert cve1["ssvc_info"]["automatable"] == "yes"
    assert cve1["ssvc_info"]["technicalImpact"] == "total"
    assert cve1["ssvc_info"]["version"] == "2.0.3"
    
    assert cve2["ssvc_info"]["status"] == "NOT_FOUND"
    
    # Verify EPSS
    assert cve1["epss_info"]["status"] == "AVAILABLE"
    assert cve1["epss_info"]["epss"] == 0.95
    assert cve1["epss_info"]["percentile"] == 0.99
    
    assert cve2["epss_info"]["status"] == "NOT_FOUND"

@responses.activate
def test_sync_cpe_cve_cache_epss_failure(mock_env):
    cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    
    # NVD succeeds
    responses.add(
        responses.GET,
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={requests.utils.quote(cpe)}",
        json={"vulnerabilities": [{"cve": {"id": "CVE-INFORMATIONAL-1"}}]},
        status=200
    )
    
    # EPSS fails
    responses.add(
        responses.GET,
        "https://api.first.org/data/v1/epss?cve=CVE-INFORMATIONAL-1",
        status=500
    )
    
    import re
    responses.add(
        responses.GET,
        re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache\?cpe=eq\..*"),
        json=[],
        status=200
    )
    import re
    responses.add(
        responses.GET,
        re.compile(r"http://mock-supabase/rest/v1/cpe_cve_cache\?cpe=eq\..*"),
        json=[],
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
    
    assert result is True # Still succeeds because EPSS failure shouldn't kill the whole sync
    
    post_call = next(call for call in responses.calls if call.request.method == "POST")
    data = json.loads(post_call.request.body.decode('utf-8'))
    
    cve1 = data["cves_json"][0]
    assert cve1["epss_info"]["status"] == "UNAVAILABLE" # Missing EPSS due to failure, but CVE remains

def test_enrich_worker_offline_behavior_phase5c():
    pass
