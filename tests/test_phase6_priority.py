import pytest
import subprocess
import json
import os
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

    # 6. Critical severity without CVE intelligence -> not P1 (UNSCORED)
    assert calculate_finding_priority({'severity': 'Critical'}) == 'UNSCORED'

    # Case B: High severity + CVE with CVSS 9.8 -> export priority P1
    assert calculate_finding_priority({"severity": "High", "cvss_score": 9.8}) == "P1"

    # Case C: High severity + CVE with EPSS 0.15 -> export priority P1
    assert calculate_finding_priority({"severity": "High", "epss_info": {"status": "AVAILABLE", "epss": 0.15}}) == "P1"

    # Case D: High severity + CVE with CVSS 7.5 -> documented non-P1 priority
    # Wait, the fallback is standard severity mapping for findings (so P2)
    assert calculate_finding_priority({"severity": "High", "cvss_score": 7.5}) == "P2"

def test_calculate_cve_priority_p1():
    # 5. CVE qualifying for P1 -> P1 consistently through all consumers
    ident = {"vulnerability_state": "MATCHED"}

    # CVSS >= 9.0
    assert calculate_cve_priority(ident, {"cvss_score": 9.0}) == "P1"
    assert calculate_cve_priority(ident, {"cvss_score": 9.8}) == "P1"

    # EPSS >= 0.1
    assert calculate_cve_priority(ident, {"epss_info": {"status": "AVAILABLE", "epss": 0.1}}) == "P1"

def test_calculate_cve_priority_missing_cvss():
    # 9. missing CVSS -> deterministic priority (no fabricated priority input)
    ident = {"vulnerability_state": "MATCHED"}
    assert calculate_cve_priority(ident, {"cvss_score": None}) == "UNSCORED"
    assert calculate_cve_priority(ident, {}) == "UNSCORED"

def test_calculate_cve_priority_cvss_no_epss():
    # 8. missing EPSS -> deterministic priority
    ident = {"vulnerability_state": "MATCHED"}
    assert calculate_cve_priority(ident, {"cvss_score": 7.5}) == "P2"
    assert calculate_cve_priority(ident, {"cvss_score": 4.5}) == "P3"
    assert calculate_cve_priority(ident, {"cvss_score": 0.0}) == "P5"

def test_calculate_cve_priority_epss():
    ident = {"vulnerability_state": "MATCHED"}
    assert calculate_cve_priority(ident, {"epss_info": {"status": "AVAILABLE", "epss": 0.05}}) == "P2"

def test_calculate_cve_priority_kev_ssvc_informational():
    # 10. KEV present -> priority unchanged unless existing rule explicitly uses it
    ident = {"vulnerability_state": "MATCHED"}
    assert calculate_cve_priority(ident, {"kev_info": {"status": "IN_KEV"}}) == "UNSCORED"
    assert calculate_cve_priority(ident, {"kev_info": {"status": "NOT_IN_KEV"}, "cvss_score": 5.0}) == "P3"

    # 11. SSVC present -> priority unchanged unless existing rule explicitly uses it
    assert calculate_cve_priority(ident, {"ssvc_info": {"exploitation": "active"}, "cvss_score": 9.8}) == "P1"
    assert calculate_cve_priority(ident, {"ssvc_info": {"status": "NOT_FOUND"}, "cvss_score": 9.8}) == "P1"

def test_calculate_cve_priority_determinism():
    # 12. repeated serialization/output produces identical priority
    ident = {"vulnerability_state": "MATCHED"}
    cve = {"cvss_score": 8.0, "epss_info": {"status": "AVAILABLE", "epss": 0.05}}
    res1 = calculate_cve_priority(ident, cve)
    res2 = calculate_cve_priority(ident, cve)
    assert res1 == res2 == "P2"

def test_calculate_cve_priority_no_mutation():
    # 13. priority changes do not affect finding identity (identity dict is untouched)
    # 14. priority changes do not affect severity (severity is untouched)
    # 15. priority changes do not affect scanner score (not mutated)
    ident = {"vulnerability_state": "MATCHED", "id": "123"}
    cve = {"cvss_score": 7.5, "cvss_severity": "HIGH"}
    assert calculate_cve_priority(ident, cve) == "P2"
    assert ident["vulnerability_state"] == "MATCHED"
    assert ident["id"] == "123"
    assert cve["cvss_severity"] == "HIGH"
    assert cve["cvss_score"] == 7.5

def test_calculate_cve_priority_legacy():
    # 7. legacy CVE payload -> same intended priority
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

def test_js_frontend_and_export_parity():
    # Validates frontend/export matches backend logic
    js_code = """
import { calculateFindingPriority, calculateCvePriority } from './src/utils/priority.js';
import fs from 'fs';

const findingHigh = { severity: 'High', name: 'Test' };
const findingCrit = { severity: 'Critical', name: 'Test' };
const findingP1Cvss = { severity: 'High', cvss_score: 9.8 };
const findingP1Epss = { severity: 'High', epss_info: {status: 'AVAILABLE', epss: 0.15} };
const findingSubP1 = { severity: 'High', cvss_score: 7.5 };

const resMap = {
    findingHigh: calculateFindingPriority(findingHigh),
    findingCrit: calculateFindingPriority(findingCrit),
    findingP1Cvss: calculateFindingPriority(findingP1Cvss),
    findingP1Epss: calculateFindingPriority(findingP1Epss),
    findingSubP1: calculateFindingPriority(findingSubP1),
};

const exportCode = fs.readFileSync('./src/lib/exportUtils.js', 'utf8');
const transformedCode = exportCode.replace(/export const/g, 'const').replace(/import.*?priority';/g, '');
const execute = new Function('calculateFindingPriority', transformedCode + `
  return {
    csv: generateCSV([{severity: 'High', name: 'HighFinding', cvss_score: 9.8}], {}),
    json: generateJSON([{severity: 'High', name: 'HighFinding', epss_info: {status: 'AVAILABLE', epss: 0.15}}], {})
  };
`);

const exportRes = execute(calculateFindingPriority);
resMap.csvExportP1 = exportRes.csv.includes('HighFinding,High,P1');
resMap.jsonExportP1 = JSON.parse(exportRes.json).findings[0].priority === 'P1';

console.log(JSON.stringify(resMap));
"""
    with open('test_harness.js', 'w') as f:
        f.write(js_code)

    res = subprocess.run(['node', 'test_harness.js'], capture_output=True, text=True)
    assert res.returncode == 0, f"JS execution failed: {res.stderr}"

    data = json.loads(res.stdout)
    assert data['findingHigh'] == 'P2'
    assert data['findingCrit'] == 'UNSCORED'
    assert data['findingP1Cvss'] == 'P1'
    assert data['findingP1Epss'] == 'P1'
    assert data['findingSubP1'] == 'P2'
    assert data['csvExportP1'] is True, "Export CSV should yield P1"
    assert data['jsonExportP1'] is True, "Export JSON should yield P1"

    os.remove('test_harness.js')
