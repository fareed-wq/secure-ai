export function calculateFindingPriority(finding) {
    if (!finding) return 'UNSCORED';

    // 1. Check CVE intelligence for P1 thresholds
    let maxCvss = -1.0;
    if (typeof finding.cvss_score === 'number') {
        maxCvss = finding.cvss_score;
    }

    let epssScore = -1.0;
    if (finding.epss_info && finding.epss_info.status === 'AVAILABLE' && typeof finding.epss_info.epss === 'number') {
        epssScore = finding.epss_info.epss;
    }

    if (maxCvss >= 9.0 || epssScore >= 0.1) {
        return 'P1';
    }

    // 2. Fall back to standard severity mapping for P2-P5
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

    let maxCvss = -1.0;
    if (typeof cve.cvss_score === 'number') {
        maxCvss = cve.cvss_score;
    } else if (Array.isArray(cve.cvss_assessments)) {
        for (const c of cve.cvss_assessments) {
            if (typeof c.base_score === 'number') {
                if (c.base_score > maxCvss) {
                    maxCvss = c.base_score;
                }
            }
        }
    }

    let epssScore = -1.0;
    if (cve.epss_info && cve.epss_info.status === 'AVAILABLE' && typeof cve.epss_info.epss === 'number') {
        epssScore = cve.epss_info.epss;
    } else if (cve.epss && typeof cve.epss === 'object' && typeof cve.epss.score === 'number') {
        epssScore = cve.epss.score;
    }

    if (maxCvss < 0 && epssScore < 0) return 'UNSCORED';

    if (maxCvss >= 9.0 || epssScore >= 0.1) return 'P1';
    if (maxCvss >= 7.0 || epssScore >= 0.01) return 'P2';

    if (maxCvss < 0) return 'UNSCORED';

    if (maxCvss >= 4.0) return 'P3';
    if (maxCvss > 0.0) return 'P4';
    return 'P5';
}


export function getPriorityBadgeClasses(priority) {
    const styles = {
        'P1': 'text-rose-400 bg-rose-950/30 border-rose-800',
        'P2': 'text-amber-400 bg-amber-950/30 border-amber-800',
        'P3': 'text-yellow-400 bg-yellow-950/30 border-yellow-800',
        'P4': 'text-cyan-400 bg-cyan-950/30 border-cyan-800',
        'P5': 'text-violet-400 bg-violet-950/30 border-violet-800',
        'UNSCORED': 'text-slate-400 bg-slate-800 border-slate-700'
    };
    return styles[priority] || styles['UNSCORED'];
}
