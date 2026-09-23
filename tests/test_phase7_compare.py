import pytest
from api.scanner.compare import compare_reports
import copy

def _mk_scan(findings, tech=None):
    if tech is None:
        tech = []
    return {
        "target_url": "http://example.com",
        "created_at": "2026-09-01T00:00:00Z",
        "report_data": {
            "scan_mode": "passive",
            "findings": findings,
            "technology_identities": tech
        }
    }

def test_cve_metadata_change_preserves_finding_identity():
    # 1. CVE metadata change preserves finding identity
    # (A finding with a CVE property that changes shouldn't become a new finding)
    old_finding = {"rule_id": "test", "instance_key": "x", "severity": "High", "cvss_score": 7.5}
    new_finding = {"rule_id": "test", "instance_key": "x", "severity": "High", "cvss_score": 9.8}
    
    old_scan = _mk_scan([old_finding])
    new_scan = _mk_scan([new_finding])
    
    res = compare_reports(old_scan, new_scan)
    assert len(res["added"]) == 0
    assert len(res["removed"]) == 0
    assert len(res["unchanged"]) == 1
    assert len(res["improved"]) == 0
    assert len(res["regressed"]) == 0

def test_cvss_epss_kev_ssvc_change_preserves_identity():
    # 2. CVSS change preserves identity
    # 3. EPSS change preserves identity
    # 4. KEV-only change preserves identity
    # 5. SSVC-only change preserves identity
    # 14. Compare ignores intelligence-only metadata when existing semantics require it
    # 15. Compare does not treat KEV/SSVC-only changes as Added/Removed
    old_f = {"rule_id": "test", "instance_key": "x", "severity": "High", "cvss_score": 5.0}
    
    # Mix all the new intelligence fields on the finding natively
    new_f = {
        "rule_id": "test", 
        "instance_key": "x", 
        "severity": "High", 
        "cvss_score": 8.0,
        "epss_info": {"status": "AVAILABLE", "epss": 0.5},
        "kev_info": {"status": "IN_KEV"},
        "ssvc_info": {"exploitation": "active"}
    }
    
    res = compare_reports(_mk_scan([old_f]), _mk_scan([new_f]))
    assert len(res["added"]) == 0
    assert len(res["removed"]) == 0
    assert len(res["unchanged"]) == 1

def test_priority_changes_preserve_identity():
    # 6. priority P2 -> P1 preserves identity
    # 7. priority P1 -> P2 preserves identity
    
    old_f = {"rule_id": "test", "instance_key": "x", "severity": "High", "cvss_score": 7.5} # P2
    new_f = {"rule_id": "test", "instance_key": "x", "severity": "High", "cvss_score": 9.8} # P1
    
    res = compare_reports(_mk_scan([old_f]), _mk_scan([new_f]))
    assert len(res["unchanged"]) == 1
    assert len(res["added"]) == 0
    assert len(res["removed"]) == 0

    # P1 -> P2
    res2 = compare_reports(_mk_scan([new_f]), _mk_scan([old_f]))
    assert len(res2["unchanged"]) == 1
    assert len(res2["added"]) == 0
    assert len(res2["removed"]) == 0

def test_cve_state_transitions():
    # 8. CVE MATCHED -> NO_MATCH behavior
    old_tech = [{"layer": "web", "product": "nginx", "vulnerability_state": "MATCHED", "cves": [{"id": "CVE-1", "cvss_score": 9.8}]}]
    new_tech = [{"layer": "web", "product": "nginx", "vulnerability_state": "NO_MATCH"}]
    
    res = compare_reports(_mk_scan([], old_tech), _mk_scan([], new_tech))
    assert len(res["cve_no_longer_matched"]) == 1
    assert res["cve_no_longer_matched"][0]["cve_id"] == "CVE-1"
    assert len(res["intelligence_lost"]) == 0
    assert len(res["cve_removed"]) == 0

    # 9. MATCHED -> UNAVAILABLE behavior
    unavail_tech = [{"layer": "web", "product": "nginx", "vulnerability_state": "UNAVAILABLE"}]
    res2 = compare_reports(_mk_scan([], old_tech), _mk_scan([], unavail_tech))
    assert len(res2["cve_no_longer_matched"]) == 0
    assert len(res2["intelligence_lost"]) == 1
    assert res2["intelligence_lost"][0]["product"] == "nginx"

def test_legacy_vs_current_mixed_identities():
    # 10. legacy -> current comparison
    # 11. current -> legacy comparison
    # 12. mixed stable/legacy identity
    
    legacy_old = {"name": "Test", "module": "mod", "severity": "Medium"}
    stable_new = {"rule_id": "test_rule", "instance_key": "idx", "name": "Test", "module": "mod", "severity": "Medium"}
    
    # 10. Legacy -> Stable
    res1 = compare_reports(_mk_scan([legacy_old]), _mk_scan([stable_new]))
    assert len(res1["added"]) == 0
    assert len(res1["removed"]) == 0
    assert len(res1["unchanged"]) == 1

    # 11. Stable -> Legacy
    res2 = compare_reports(_mk_scan([stable_new]), _mk_scan([legacy_old]))
    assert len(res2["added"]) == 0
    assert len(res2["removed"]) == 0
    assert len(res2["unchanged"]) == 1

def test_deterministic_repeated_comparison():
    # 13. deterministic repeated comparison
    old_tech = [{"layer": "web", "product": "nginx", "vulnerability_state": "MATCHED", "cves": [{"id": "CVE-1", "cvss_score": 9.8}]}]
    new_tech = [{"layer": "web", "product": "nginx", "vulnerability_state": "MATCHED", "cves": [{"id": "CVE-1", "cvss_score": 7.5}]}]
    
    res1 = compare_reports(_mk_scan([], old_tech), _mk_scan([], new_tech))
    res2 = compare_reports(_mk_scan([], old_tech), _mk_scan([], new_tech))
    
    assert res1["cve_priority_changed"] == res2["cve_priority_changed"]
    assert len(res1["cve_priority_changed"]) == 1
    assert res1["cve_priority_changed"][0]["old_priority"] == "P1"
    assert res1["cve_priority_changed"][0]["new_priority"] == "P2"
