def calculate_finding_priority(finding: dict) -> str:
    # 1. Check CVE intelligence for P1 thresholds
    max_cvss = -1.0
    cvss = finding.get('cvss_score')
    if isinstance(cvss, (int, float)):
        max_cvss = float(cvss)

    epss_score = -1.0
    epss_info = finding.get('epss_info')
    if isinstance(epss_info, dict) and epss_info.get('status') == 'AVAILABLE':
        val = epss_info.get('epss')
        if isinstance(val, (int, float)):
            epss_score = float(val)

    if max_cvss >= 9.0 or epss_score >= 0.1:
        return 'P1'

    # 2. Fall back to standard severity mapping for P2-P5
    severity = finding.get('severity')
    if severity == 'High': return 'P2'
    if severity == 'Medium': return 'P3'
    if severity == 'Low': return 'P4'
    if severity in ['Informational', 'Passed']: return 'P5'
    return 'UNSCORED'

def calculate_cve_priority(identity: dict, cve: dict) -> str:
    state = identity.get('vulnerability_state')
    if state == 'NO_MATCH': return 'N/A'
    if state in ['NOT_EVALUATED', 'UNAVAILABLE']: return 'UNSCORED'

    # 1. Resolve CVSS Score
    max_cvss = -1.0

    # Phase 5 Schema
    phase5_cvss = cve.get('cvss_score')
    if isinstance(phase5_cvss, (int, float)):
        max_cvss = float(phase5_cvss)
    else:
        # Legacy Schema
        cvss = cve.get('cvss_assessments')
        if isinstance(cvss, list):
            for c in cvss:
                score = c.get('base_score')
                if isinstance(score, (int, float)) and score > max_cvss:
                    max_cvss = float(score)

    # 2. Resolve EPSS Score
    epss_score = -1.0

    # Phase 5 Schema
    epss_info = cve.get('epss_info')
    if isinstance(epss_info, dict) and epss_info.get('status') == 'AVAILABLE':
        val = epss_info.get('epss')
        if isinstance(val, (int, float)):
            epss_score = float(val)
    else:
        # Legacy Schema
        epss = cve.get('epss')
        if isinstance(epss, dict):
            val = epss.get('score')
            if isinstance(val, (int, float)):
                epss_score = float(val)

    if max_cvss < 0 and epss_score < 0:
        return 'UNSCORED'

    if max_cvss >= 9.0 or epss_score >= 0.1: return 'P1'
    if max_cvss >= 7.0 or epss_score >= 0.01: return 'P2'
    if max_cvss >= 4.0: return 'P3'
    if max_cvss > 0.0: return 'P4'
    return 'P5'
