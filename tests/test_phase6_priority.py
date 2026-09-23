import pytest
from api.scanner.priority import calculate_finding_priority, calculate_cve_priority

def test_calculate_finding_priority():
    # 1. High severity without CVE intelligence -> P2
    assert calculate_finding_priority({"severity": "High"}) == "P2"

    # 2. Medium without CVE intelligence -> P3
    assert calculate_finding_priority({"severity": "Medium"}) == "P3"

    # 3. Low without CVE intelligence -> P4
    assert calculate_finding_priority({"severity": "Low"}) == "P4"

    # 4. Informational/Passed -> P5
    assert calculate_finding_priority({"severity": "Informational"}) == "P5"
    assert calculate_finding_priority({"severity": "Passed"}) == "P5"

def test_calculate_cve_priority_p1():
    # 5. qualifying CVE intelligence -> exact intended P1 condition
    ident = {"vulnerability_state": "MATCHED"}

    # CVSS >= 9.0
    assert calculate_cve_priority(ident, {"cvss_score": 9.0}) == "P1"
    assert calculate_cve_priority(ident, {"cvss_score": 9.8}) == "P1"

    # EPSS >= 0.1
    assert calculate_cve_priority(ident, {"epss_info": {"status": "AVAILABLE", "epss": 0.1}}) == "P1"

def test_calculate_cve_priority_missing_cvss():
    # 6. CVE match with missing CVSS -> no fabricated priority input
    ident = {"vulnerability_state": "MATCHED"}
    assert calculate_cve_priority(ident, {"cvss_score": None}) == "UNSCORED"
    assert calculate_cve_priority(ident, {}) == "UNSCORED"

def test_calculate_cve_priority_cvss_no_epss():
    # 7. CVSS present but no EPSS -> deterministic result
    ident = {"vulnerability_state": "MATCHED"}
    assert calculate_cve_priority(ident, {"cvss_score": 7.5}) == "P2"
    assert calculate_cve_priority(ident, {"cvss_score": 4.5}) == "P3"
    assert calculate_cve_priority(ident, {"cvss_score": 0.0}) == "P5"

def test_calculate_cve_priority_epss():
    # 8. EPSS present -> deterministic result
    ident = {"vulnerability_state": "MATCHED"}
    assert calculate_cve_priority(ident, {"epss_info": {"status": "AVAILABLE", "epss": 0.05}}) == "P2"

def test_calculate_cve_priority_kev_ssvc_informational():
    # 9. KEV present -> deterministic intended result (KEV is informational, does not add points)
    ident = {"vulnerability_state": "MATCHED"}
    # Missing CVSS/EPSS but has KEV -> remains UNSCORED because KEV isn't in formula
    assert calculate_cve_priority(ident, {"kev_info": {"status": "IN_KEV"}}) == "UNSCORED"

    # 10. KEV absent -> does not falsely imply safe (still unscored or based on CVSS)
    assert calculate_cve_priority(ident, {"kev_info": {"status": "NOT_IN_KEV"}, "cvss_score": 5.0}) == "P3"

    # 11. SSVC present -> deterministic result (SSVC is informational)
    assert calculate_cve_priority(ident, {"ssvc_info": {"exploitation": "active"}, "cvss_score": 9.8}) == "P1"

    # 12. Missing SSVC -> no fabricated downgrade
    assert calculate_cve_priority(ident, {"ssvc_info": {"status": "NOT_FOUND"}, "cvss_score": 9.8}) == "P1"

def test_calculate_cve_priority_determinism():
    # 13. repeated identical input -> identical priority
    ident = {"vulnerability_state": "MATCHED"}
    cve = {"cvss_score": 8.0, "epss_info": {"status": "AVAILABLE", "epss": 0.05}}
    res1 = calculate_cve_priority(ident, cve)
    res2 = calculate_cve_priority(ident, cve)
    assert res1 == res2 == "P2"

    # 14. enrichment ordering does not change priority
    # (Dictionaries have arbitrary key order, but attribute access is stable)
    cve_rev = {"epss_info": {"status": "AVAILABLE", "epss": 0.05}, "cvss_score": 8.0}
    assert calculate_cve_priority(ident, cve_rev) == "P2"

def test_calculate_cve_priority_no_mutation():
    # 15. priority does not change severity
    # 16. priority does not change score
    ident = {"vulnerability_state": "MATCHED"}
    cve = {"cvss_score": 7.5, "cvss_severity": "HIGH"}
    assert calculate_cve_priority(ident, cve) == "P2"
    assert cve["cvss_severity"] == "HIGH"
    assert cve["cvss_score"] == 7.5

def test_calculate_cve_priority_legacy():
    # 18. historical/legacy findings without enrichment remain compatible
    ident = {"vulnerability_state": "MATCHED"}
    legacy_cve = {
        "cvss_assessments": [{"base_score": 9.5}],
        "epss": {"score": 0.05}
    }
    assert calculate_cve_priority(ident, legacy_cve) == "P1"

    legacy_cve2 = {
        "cvss_assessments": [{"base_score": 5.0}]
    }
    assert calculate_cve_priority(ident, legacy_cve2) == "P3"

def test_calculate_finding_priority_no_cve():
    # 17. no-CVE findings preserve existing priority behavior
    assert calculate_finding_priority({"severity": "High", "cves": []}) == "P2"

    # No Critical -> P1 mapping
    assert calculate_finding_priority({'severity': 'Critical'}) == 'UNSCORED'
