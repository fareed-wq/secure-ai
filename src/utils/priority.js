export function calculateFindingPriority(finding) {
    if (!finding) return 'UNSCORED';
    const severity = finding.severity;
    if (severity === 'Critical') return 'P1';
    if (severity === 'High') return 'P2';
    if (severity === 'Medium') return 'P3';
    if (severity === 'Low') return 'P4';
    if (severity === 'Informational' || severity === 'Passed') return 'P5';
    return 'UNSCORED';
}

export function calculateCvePriority(identity, cve) {
    if (!identity) return 'UNSCORED';
    const state = identity.vulnerability_state;
    if (state === 'NO_MATCH') return 'N/A';
    if (state === 'NOT_EVALUATED' || state === 'UNAVAILABLE') return 'UNSCORED';

    if (!cve) return 'UNSCORED';
    const cvss = cve.cvss_assessments;
    const epss = cve.epss;

    const hasCvss = Array.isArray(cvss) && cvss.length > 0;
    const hasEpss = epss && typeof epss === 'object' && typeof epss.score === 'number';

    if (!hasCvss && !hasEpss) return 'UNSCORED';

    let maxCvss = -1.0;
    if (hasCvss) {
        for (const c of cvss) {
            if (typeof c.base_score === 'number') {
                if (c.base_score > maxCvss) {
                    maxCvss = c.base_score;
                }
            }
        }
    }

    let epssScore = -1.0;
    if (hasEpss) {
        epssScore = epss.score;
    }

    if (maxCvss < 0 && epssScore < 0) return 'UNSCORED';

    if (maxCvss >= 9.0 || epssScore >= 0.1) return 'P1';
    if (maxCvss >= 7.0 || epssScore >= 0.01) return 'P2';
    if (maxCvss >= 4.0) return 'P3';
    if (maxCvss > 0.0) return 'P4';
    return 'P5';
}
