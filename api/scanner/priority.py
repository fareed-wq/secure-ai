def calculate_finding_priority(finding: dict) -> str:
    severity = finding.get('severity')
    if severity == 'Critical': return 'P1'
    if severity == 'High': return 'P2'
    if severity == 'Medium': return 'P3'
    if severity == 'Low': return 'P4'
    if severity in ['Informational', 'Passed']: return 'P5'
    return 'UNSCORED'

def calculate_cve_priority(identity: dict, cve: dict) -> str:
    state = identity.get('vulnerability_state')
    if state == 'NO_MATCH': return 'N/A'
    if state in ['NOT_EVALUATED', 'UNAVAILABLE']: return 'UNSCORED'

    cvss = cve.get('cvss_assessments')
    epss = cve.get('epss')

    has_cvss = isinstance(cvss, list) and len(cvss) > 0
    has_epss = isinstance(epss, dict) and isinstance(epss.get('score'), (int, float))

    if not has_cvss and not has_epss:
        return 'UNSCORED'

    max_cvss = -1.0
    if has_cvss:
        for c in cvss:
            score = c.get('base_score')
            if isinstance(score, (int, float)):
                if score > max_cvss:
                    max_cvss = float(score)

    epss_score = -1.0
    if has_epss:
        epss_score = float(epss.get('score'))

    if max_cvss < 0 and epss_score < 0:
        return 'UNSCORED'

    if max_cvss >= 9.0 or epss_score >= 0.1: return 'P1'
    if max_cvss >= 7.0 or epss_score >= 0.01: return 'P2'
    if max_cvss >= 4.0: return 'P3'
    if max_cvss > 0.0: return 'P4'
    return 'P5'
