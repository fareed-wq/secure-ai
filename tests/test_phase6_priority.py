from api.scanner.priority import calculate_finding_priority, calculate_cve_priority

def test_finding_priority():
    assert calculate_finding_priority({'severity': 'Critical'}) == 'P1'
    assert calculate_finding_priority({'severity': 'High'}) == 'P2'
    assert calculate_finding_priority({'severity': 'Medium'}) == 'P3'
    assert calculate_finding_priority({'severity': 'Low'}) == 'P4'
    assert calculate_finding_priority({'severity': 'Informational'}) == 'P5'
    assert calculate_finding_priority({'severity': 'Passed'}) == 'P5'
    assert calculate_finding_priority({'severity': 'Unknown'}) == 'UNSCORED'
    assert calculate_finding_priority({}) == 'UNSCORED'

def test_cve_priority_states():
    assert calculate_cve_priority({'vulnerability_state': 'UNAVAILABLE'}, {}) == 'UNSCORED'
    assert calculate_cve_priority({'vulnerability_state': 'NOT_EVALUATED'}, {}) == 'UNSCORED'
    assert calculate_cve_priority({'vulnerability_state': 'NO_MATCH'}, {}) == 'N/A'
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {}) == 'UNSCORED'
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'cvss_assessments': []}) == 'UNSCORED'

def test_cve_priority_cvss_boundaries():
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'cvss_assessments': [{'base_score': 9.0}]}) == 'P1'
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'cvss_assessments': [{'base_score': 8.9}]}) == 'P2'
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'cvss_assessments': [{'base_score': 7.0}]}) == 'P2'
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'cvss_assessments': [{'base_score': 6.9}]}) == 'P3'
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'cvss_assessments': [{'base_score': 4.0}]}) == 'P3'
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'cvss_assessments': [{'base_score': 3.9}]}) == 'P4'
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'cvss_assessments': [{'base_score': 0.1}]}) == 'P4'
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'cvss_assessments': [{'base_score': 0.0}]}) == 'P5'

def test_cve_priority_epss_boundaries():
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'epss': {'score': 0.10}}) == 'P1'
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'epss': {'score': 0.099}}) == 'P2'
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'epss': {'score': 0.01}}) == 'P2'
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'epss': {'score': 0.009}}) == 'P5'
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'epss': {'score': 0.0}}) == 'P5'

def test_cve_priority_conflicts():
    # CVSS P5, EPSS P1 => P1
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'cvss_assessments': [{'base_score': 0.0}], 'epss': {'score': 0.15}}) == 'P1'
    # CVSS P2, EPSS P5 => P2
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'cvss_assessments': [{'base_score': 7.5}], 'epss': {'score': 0.005}}) == 'P2'

def test_cve_priority_multiple_cvss():
    cve = {'cvss_assessments': [{'base_score': 3.0}, {'base_score': 9.5}, {'base_score': 5.0}]}
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, cve) == 'P1'

def test_cve_priority_malformed():
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'epss': {}}) == 'UNSCORED'
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'cvss_assessments': [{}]}) == 'UNSCORED'
    assert calculate_cve_priority({'vulnerability_state': 'MATCHED'}, {'cvss_assessments': [{'base_score': 'not_a_float'}]}) == 'UNSCORED'

import os
from api.scanner.reporting import generate_pdf_report

def test_integration_pdf_report():
    data = {
        'url': 'http://test.com',
        'executive_summary': 'Test',
        'score': 100,
        'potential_issues_count': 0,
        'category_scores': {'encryption_tls': 100, 'http_headers': 100, 'domain_email': 100, 'session_cookies': 100, 'information_exposure': 100},
        'findings': [
            {'name': 'Test P1', 'severity': 'Critical', 'owasp': 'A1', 'evidence': 'test1'},
            {'name': 'Test P2', 'severity': 'High', 'owasp': 'A2', 'evidence': 'test2'},
            {'name': 'Test P3', 'severity': 'Medium', 'owasp': 'A3', 'evidence': 'test3'},
            {'name': 'Test P4', 'severity': 'Low', 'owasp': 'A4', 'evidence': 'test4'},
            {'name': 'Test P5', 'severity': 'Informational', 'owasp': 'A5', 'evidence': 'test5'},
            {'name': 'Test UNSCORED', 'severity': 'Unknown', 'owasp': 'A6', 'evidence': 'test6'}
        ],
        'technology_identities': [{
            'vulnerability_state': 'MATCHED',
            'cves': [{'id': 'CVE-123', 'severity': 'high', 'summary': 'test', 'cvss_assessments': [{'base_score': 9.5}]}]
        }]
    }
    html_out = generate_pdf_report(data)
    # Verify exact row rendering (Priority before Severity) and correct CSS classes
    assert "<tr><td><span class='pri-P1'>P1</span></td><td class='sev-Critical'>Critical</td><td>Test P1</td>" in html_out
    assert "<tr><td><span class='pri-P2'>P2</span></td><td class='sev-High'>High</td><td>Test P2</td>" in html_out
    assert "<tr><td><span class='pri-P3'>P3</span></td><td class='sev-Medium'>Medium</td><td>Test P3</td>" in html_out
    assert "<tr><td><span class='pri-P4'>P4</span></td><td class='sev-Low'>Low</td><td>Test P4</td>" in html_out
    assert "<tr><td><span class='pri-P5'>P5</span></td><td class='sev-Informational'>Informational</td><td>Test P5</td>" in html_out
    assert "<tr><td><span class='pri-UNSCORED'>UNSCORED</span></td><td class='sev-Unknown'>Unknown</td><td>Test UNSCORED</td>" in html_out

    # Also verify CSS classes are actually injected in the style block
    assert ".pri-P1 {" in html_out
    assert ".pri-P5 {" in html_out
    assert 'Known Vulnerabilities' in html_out
    assert '[P1] high' in html_out

def test_integration_ui_files():
    # Minimum assertion to prove UI path invokes Priority
    with open('src/components/scanner/FindingCard.jsx', 'r', encoding='utf-8') as f:
        content = f.read()
    assert 'calculateFindingPriority(' in content

    with open('src/components/scanner/TechnicalReport.jsx', 'r', encoding='utf-8') as f:
        content = f.read()
    assert 'calculateCvePriority(' in content


def test_reporting_kev_ssvc_rendering():
    from api.scanner.reporting import generate_pdf_report
    data = {
        "url": "http://example.com",
        "executive_summary": "Summary",
        "findings": [],
        "score": 100,
        "potential_issues_count": 0,
        "category_scores": {
            "encryption_tls": 100,
            "http_headers": 100,
            "domain_email": 100,
            "session_cookies": 100,
            "information_exposure": 100
        },




        "scan_mode": "passive",
        "technology_identities": [
            {
                "vulnerability_state": "MATCHED",
                "cves": [
                    {
                        "id": "CVE-KEV",
                        "severity": "CRITICAL",
                        "summary": "KEV Test",
                        "kev": {
                            "added": "2024-01-01",
                            "due": "2024-02-01",
                            "action": "Fix it",
                            "name": "Vuln Name"
                        }
                    },
                    {
                        "id": "CVE-SSVC",
                        "severity": "HIGH",
                        "summary": "SSVC Test",
                        "ssvc": {
                            "source": "CISA-ADP",
                            "version": "2.0.3",
                            "timestamp": "2024-01-01",
                            "options": {
                                "exploitation": "active",
                                "automatable": "no",
                                "technicalImpact": "total"
                            }
                        }
                    },
                    {
                        "id": "CVE-ABSENT",
                        "severity": "MEDIUM",
                        "summary": "Absent Test"
                    },
                    {
                        "id": "CVE-ESCAPE",
                        "severity": "LOW",
                        "summary": "Escape Test",
                        "kev": {
                            "action": "<script>alert(1)</script>"
                        }
                    }
                ]
            }
        ]
    }

    html = generate_pdf_report(data)

    # KEV test
    assert "CVE-KEV" in html
    assert "[CISA KEV]" in html
    assert "Vuln Name" in html
    assert "Added: 2024-01-01" in html
    assert "Action: Fix it" in html
    assert "(Due: 2024-02-01)" in html

    # SSVC test
    assert "CVE-SSVC" in html
    assert "[CISA-ADP SSVC v2.0.3] (2024-01-01)" in html
    assert "exploitation: active" in html
    assert "automatable: no" in html
    assert "technicalImpact: total" in html
    assert "Track" not in html
    assert "Attend" not in html

    # Absent test
    assert "CVE-ABSENT" in html
    assert "not exploited" not in html.lower()

    # Escape test
    assert "CVE-ESCAPE" in html
    assert "<script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
