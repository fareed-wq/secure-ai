/**
 * Export utilities for report findings
 * Client-side export functions for JSON and CSV formats
 */

import { calculateFindingPriority, calculateCvePriority } from '../utils/priority';

/**
 * Sanitize filename by removing unsafe characters
 */
const sanitizeFilename = (name) => {
    return name
        .replace(/[<>:"/\\|?*]/g, '_')
        .replace(/\s+/g, '_')
        .substring(0, 100);
};

/**
 * Escape CSV field values
 */
const escapeCSV = (value) => {
    if (value === null || value === undefined) {
        return '';
    }
    const strValue = String(value);
    // Escape quotes by doubling them, and wrap in quotes if contains comma, newline, or quote
    const escaped = strValue.replace(/"/g, '""');
    if (escaped.includes(',') || escaped.includes('\n') || escaped.includes('"')) {
        return `"${escaped}"`;
    }
    return escaped;
};

/**
 * Generate CSV content for Vulnerability Intelligence
 */
const generateVulnerabilitiesCSV = (technologyIdentities) => {
    // Header row
    const headers = [
        'Technology Name',
        'Technology Version',
        'Category',
        'CPE',
        'CPE Authority',
        'Vulnerability State',
        'CVE ID',
        'CVE Severity',
        'CVSS Score',
        'CVSS Severity',
        'CVSS Vector',
        'CWE',
        'EPSS Probability',
        'EPSS Percentile',
        'KEV Status',
        'SSVC Status',
        'CVE Priority',
        'Match Confidence'
    ];

    const rows = [];
    
    technologyIdentities.forEach(tech => {
        if (!tech) return;
        const cves = tech.cves && tech.cves.length > 0 ? tech.cves : [null];
        
        cves.forEach(cve => {
            let epssProb = '';
            let epssPerc = '';
            
            if (cve) {
                if (cve.epss_info) {
                    if (cve.epss_info.status === 'AVAILABLE' && typeof cve.epss_info.epss === 'number') {
                        epssProb = (cve.epss_info.epss * 100).toFixed(2) + '%';
                        if (typeof cve.epss_info.percentile === 'number') {
                            epssPerc = (cve.epss_info.percentile * 100).toFixed(0) + 'th';
                        }
                    } else if (cve.epss_info.status === 'NOT_FOUND') {
                        epssProb = 'Not Found';
                    } else if (cve.epss_info.status === 'UNAVAILABLE') {
                        epssProb = 'Unavailable';
                    }
                } else if (cve.epss && typeof cve.epss.score === 'number') {
                    epssProb = (cve.epss.score * 100).toFixed(2) + '%';
                }
            }

            const cweStr = cve && Array.isArray(cve.cwes) ? cve.cwes.join(' | ') : '';
            
            rows.push([
                escapeCSV(tech.name || ''),
                escapeCSV(tech.version || ''),
                escapeCSV(tech.category || ''),
                escapeCSV(tech.cpe_candidate || tech.cpe || ''),
                escapeCSV(tech.cpe_authority || ''),
                escapeCSV(tech.vulnerability_state || ''),
                escapeCSV(cve ? cve.id || '' : ''),
                escapeCSV(cve ? cve.severity || '' : ''),
                escapeCSV(cve ? (typeof cve.cvss_score === 'number' ? cve.cvss_score.toString() : (cve.cvss_score || '')) : ''),
                escapeCSV(cve ? cve.cvss_severity || '' : ''),
                escapeCSV(cve ? cve.cvss_vector || '' : ''),
                escapeCSV(cweStr),
                escapeCSV(epssProb),
                escapeCSV(epssPerc),
                escapeCSV(cve && cve.kev ? 'IN_KEV' : ''),
                escapeCSV(cve && cve.ssvc ? 'AVAILABLE' : ''),
                escapeCSV(cve ? calculateCvePriority(tech, cve) : ''),
                escapeCSV(cve ? cve.match_confidence || '' : '')
            ].join(','));
        });
    });
    
    return [headers.join(',')].concat(rows).join('\n');
};

/**
 * Generate CSV content from findings
 */
const generateCSV = (findings, reportData) => {
    const cov = reportData?.assessment_coverage;
    const covSummary = cov
        ? `Coverage: ${Math.round(cov.percentage)}% (${cov.completed_modules}/${cov.completed_modules + cov.partial_modules + cov.failed_modules + cov.blocked_modules + cov.execution_incomplete_modules + cov.not_applicable_modules} modules)`
        : 'Coverage: N/A';

    // Header row
    const headers = [
        'Finding Name',
        'Severity',
        'Priority',
        'OWASP Mapping',
        'Description',
        'Impact',
        'Remediation',
        'Confidence',
        'Verification State',
        'Rule ID',
        'Module',
        'Category',
        'Evidence',
        'CVSS',
        'CVSS Score',
        'CVSS Severity',
        'Domain',
        'Instance Key'
    ];

    // Findings rows
    const rows = findings.map(f => {
        const evidence = f.evidence && typeof f.evidence === 'object'
            ? JSON.stringify(f.evidence, null, 2).replace(/\n/g, ' | ')
            : f.evidence || '';

        const cvss = f.cvss || '';
        const cvssScore = f.cvss_score || '';
        const cvssSeverity = f.cvss_severity || '';

        return [
            escapeCSV(f.name),
            escapeCSV(f.severity),
            escapeCSV(f.priority || calculateFindingPriority(f)),
            escapeCSV(f.owasp || ''),
            escapeCSV(f.description || ''),
            escapeCSV(f.impact || ''),
            escapeCSV(f.remediation || ''),
            escapeCSV(f.confidence || ''),
            escapeCSV(f.state || ''),
            escapeCSV(f.rule_id || ''),
            escapeCSV(f.module || ''),
            escapeCSV(f.category || ''),
            escapeCSV(evidence),
            escapeCSV(cvss),
            escapeCSV(cvssScore),
            escapeCSV(cvssSeverity),
            escapeCSV(f.domain || ''),
            escapeCSV(f.instance_key || '')
        ].join(',');
    });

    // Add coverage summary at the end
    rows.push(`,"Scan Summary","${covSummary}"`);

    return [headers.join(','), ...rows].join('\n');
};

/**
 * Generate JSON content from findings
 */
const generateJSON = (findings, reportData) => {
    const cov = reportData?.assessment_coverage;

    return JSON.stringify({
        scan_metadata: {
            url: reportData?.url || 'N/A',
            timestamp: reportData?.timestamp || null,
            score: reportData?.score || null,
            assessment_coverage: cov ? {
                percentage: cov.percentage,
                available: cov.available,
                completed_modules: cov.completed_modules,
                partial_modules: cov.partial_modules,
                failed_modules: cov.failed_modules,
                blocked_modules: cov.blocked_modules,
                execution_incomplete_modules: cov.execution_incomplete_modules,
                not_applicable_modules: cov.not_applicable_modules
            } : null
        },
        findings: findings.map(f => ({
            name: f.name,
            severity: f.severity,
            priority: f.priority || calculateFindingPriority(f),
            owasp: f.owasp,
            description: f.description,
            impact: f.impact,
            remediation: f.remediation,
            confidence: f.confidence,
            state: f.state,
            rule_id: f.rule_id,
            module: f.module,
            category: f.category,
            evidence: f.evidence,
            cvss: f.cvss,
            cvss_score: f.cvss_score,
            cvss_severity: f.cvss_severity,
            domain: f.domain,
            instance_key: f.instance_key
        })),
        technology_identities: reportData?.technology_identities || []
    }, null, 2);
};

/**
 * Download file with given content, type, and filename
 */
const downloadFile = (content, mimeType, filename) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
};

/**
 * Export findings as JSON
 */
export const exportJSON = (reportData) => {
    const findings = reportData?.findings || [];
    const url = reportData?.url || 'scan';
    const timestamp = reportData?.timestamp || new Date().toISOString();
    const dateStr = new Date(timestamp).toISOString().split('T')[0];

    const filename = `security_scan_${sanitizeFilename(url)}_${dateStr}.json`;
    const content = generateJSON(findings, reportData);

    downloadFile(content, 'application/json', filename);
};

/**
 * Export findings as CSV
 */
export const exportCSV = (reportData) => {
    const findings = reportData?.findings || [];
    const url = reportData?.url || 'scan';
    const timestamp = reportData?.timestamp || new Date().toISOString();
    const dateStr = new Date(timestamp).toISOString().split('T')[0];

    const filename = `security_scan_${sanitizeFilename(url)}_${dateStr}.csv`;
    const content = generateCSV(findings, reportData);

    downloadFile(content, 'text/csv;charset=utf-8', filename);
};

/**
 * Export vulnerabilities as CSV
 */
export const exportVulnerabilitiesCSV = (reportData) => {
    const techIdentities = reportData?.technology_identities || [];
    const url = reportData?.url || 'scan';
    const timestamp = reportData?.timestamp || new Date().toISOString();
    const dateStr = new Date(timestamp).toISOString().split('T')[0];

    const filename = `security_vulnerabilities_${sanitizeFilename(url)}_${dateStr}.csv`;
    const content = generateVulnerabilitiesCSV(techIdentities);

    downloadFile(content, 'text/csv;charset=utf-8', filename);
};

