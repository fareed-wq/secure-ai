import datetime
import html
from api.scanner.priority import calculate_finding_priority, calculate_cve_priority
from urllib.parse import urlparse

def generate_pdf_report(data: dict) -> str:
    """
    Generates a print-ready executive PDF / HTML report for white-label client presentation.
    """
    hostname = urlparse(data["url"]).hostname or "report"

    # Safely escape all dynamic strings inserted into HTML
    escaped_url = html.escape(str(data['url']))
    escaped_summary = html.escape(str(data['executive_summary']))
    report_date = datetime.datetime.now().strftime("%B %d, %Y")

    table_rows = []
    for f in data['findings']:
        sev = html.escape(str(f['severity']))
        priority = html.escape(calculate_finding_priority(f))
        name = html.escape(str(f['name']))
        owasp = html.escape(str(f['owasp']))
        evidence = html.escape(str(f['evidence']))
        table_rows.append(
            f"<tr><td><span class='pri-{priority}'>{priority}</span></td><td class='sev-{sev}'>{sev}</td>"
            f"<td>{name}</td><td>{owasp}</td><td><div class='snippet'>{evidence}</div></td></tr>"
        )
    findings_rows = "".join(table_rows)

    cve_rows = []
    if 'technology_identities' in data:
        for ident in data['technology_identities']:
            if ident.get('vulnerability_state') == 'MATCHED' and 'cves' in ident:
                for cve in ident['cves']:
                    cve_id = html.escape(str(cve.get('id', 'Unknown')))
                    cve_sev = html.escape(str(cve.get('severity', 'Unknown')))
                    cve_pri = html.escape(calculate_cve_priority(ident, cve))
                    cve_sum = html.escape(str(cve.get('summary', '')))

                    meta_html = ""
                    kev = cve.get('kev')
                    if kev:
                        action = html.escape(str(kev.get('action', ''))) if kev.get('action') else ''
                        due = html.escape(str(kev.get('due', ''))) if kev.get('due') else ''
                        added = html.escape(str(kev.get('added', ''))) if kev.get('added') else ''
                        name = html.escape(str(kev.get('name', ''))) if kev.get('name') else ''

                        kev_parts = []
                        if name: kev_parts.append(name)
                        if added: kev_parts.append(f"Added: {added}")
                        if action: kev_parts.append(f"Action: {action}")
                        if due: kev_parts.append(f"(Due: {due})")

                        meta_html += f"<div style='margin-bottom:4px;font-size:0.85em;color:#b91c1c;'><strong>[CISA KEV]</strong> {' | '.join(kev_parts)}</div>"

                    ssvc = cve.get('ssvc')
                    if ssvc:
                        src = html.escape(str(ssvc.get('source', ''))) if ssvc.get('source') else 'Unknown'
                        ver = html.escape(str(ssvc.get('version', ''))) if ssvc.get('version') else ''
                        ts = html.escape(str(ssvc.get('timestamp', ''))) if ssvc.get('timestamp') else ''
                        opts = ssvc.get('options', {})
                        opt_str = " | ".join([f"{html.escape(k)}: {html.escape(str(v))}" for k, v in opts.items()])

                        ver_str = f" v{ver}" if ver else ""
                        ts_str = f" ({ts})" if ts else ""
                        meta_html += f"<div style='margin-bottom:4px;font-size:0.85em;color:#4338ca;'><strong>[{src} SSVC{ver_str}]{ts_str}</strong> {opt_str}</div>"

                    if meta_html:
                        cve_sum = f"{meta_html}<div style='margin-top:6px;'>{cve_sum}</div>"

                    cve_rows.append(
                        f"<tr><td class='sev-{cve_sev}'>[{cve_pri}] {cve_sev}</td><td>{cve_id}</td><td>{cve_sum}</td></tr>"
                    )
    cves_html = "".join(cve_rows)
    if cves_html:
        cves_section = f"""
    <div class="card">
        <h2>Known Vulnerabilities (CVEs)</h2>
        <table>
            <tr><th>Severity</th><th>CVE ID</th><th>Summary</th></tr>
            {cves_html}
        </table>
    </div>"""
    else:
        cves_section = ""


    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Security Posture Report - {html.escape(hostname)}</title>
    <style>
        body {{ font-family: 'Helvetica Neue', Arial, sans-serif; background: #0b0f19; color: #f3f4f6; margin: 0; padding: 40px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #1f293d; padding-bottom: 20px; }}
        .logo {{ font-size: 24px; font-weight: bold; color: #3b82f6; letter-spacing: 1px; }}
        .score-badge {{ font-size: 36px; font-weight: bold; color: #10b981; background: #064e3b; padding: 10px 25px; border-radius: 12px; border: 1px solid #059669; }}
        .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 24px; margin-top: 24px; }}
        h2 {{ color: #93c5fd; border-bottom: 1px solid #1e3a8a; padding-bottom: 8px; font-size: 18px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #1f2937; font-size: 14px; }}
        th {{ background: #1e293b; color: #94a3b8; }}
        .sev-High {{ color: #ef4444; font-weight: bold; }}
        .sev-Medium {{ color: #f59e0b; font-weight: bold; }}
        .sev-Low {{ color: #eab308; }}
        .sev-Passed {{ color: #10b981; font-weight: bold; }}
        .pri-P1 {{ color: #fb7185; background: rgba(76, 5, 25, 0.3); padding: 2px 6px; border: 1px solid #9f1239; border-radius: 4px; font-weight: bold; font-size: 11px; }}
        .pri-P2 {{ color: #fbbf24; background: rgba(69, 26, 3, 0.3); padding: 2px 6px; border: 1px solid #92400e; border-radius: 4px; font-weight: bold; font-size: 11px; }}
        .pri-P3 {{ color: #facc15; background: rgba(66, 32, 6, 0.3); padding: 2px 6px; border: 1px solid #854d0e; border-radius: 4px; font-weight: bold; font-size: 11px; }}
        .pri-P4 {{ color: #22d3ee; background: rgba(8, 51, 68, 0.3); padding: 2px 6px; border: 1px solid #155e75; border-radius: 4px; font-weight: bold; font-size: 11px; }}
        .pri-P5 {{ color: #a78bfa; background: rgba(46, 16, 101, 0.3); padding: 2px 6px; border: 1px solid #5b21b6; border-radius: 4px; font-weight: bold; font-size: 11px; }}
        .pri-UNSCORED {{ color: #94a3b8; background: #1e293b; padding: 2px 6px; border: 1px solid #334155; border-radius: 4px; font-weight: bold; font-size: 11px; }}
        .snippet {{ background: #030712; padding: 8px; font-family: monospace; font-size: 12px; border-radius: 4px; color: #a7f3d0; border: 1px solid #1f2937; white-space: pre-wrap; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="logo">URLScannerOnline Security Report</div>
            <div style="color: #94a3b8; margin-top: 5px;">Target: {escaped_url} | Date: {report_date}</div>
        </div>
        <div class="score-badge">{data['score']}/100</div>
    </div>

    <div class="card">
        <h2>Executive Summary</h2>
        <p>{escaped_summary}</p>
        <p><strong>Total Potential Issues Found:</strong> {data['potential_issues_count']}</p>
    </div>

    <div class="card">
        <h2>Category Posture Scores</h2>
        <table>
            <tr><th>Security Domain</th><th>Score</th></tr>
            <tr><td>Encryption & TLS</td><td>{data['category_scores']['encryption_tls']}/100</td></tr>
            <tr><td>HTTP Security Headers</td><td>{data['category_scores']['http_headers']}/100</td></tr>
            <tr><td>Domain & Email Protection (SPF/DMARC)</td><td>{data['category_scores']['domain_email']}/100</td></tr>
            <tr><td>Session & Cookie Hardening</td><td>{data['category_scores']['session_cookies']}/100</td></tr>
            <tr><td>Information Exposure Defenses</td><td>{data['category_scores']['information_exposure']}/100</td></tr>
        </table>
    </div>

    <div class="card" style="background: #1e293b; border-color: #334155; margin-bottom: 24px;">
        <h3 style="color: #cbd5e1; margin-top: 0; font-size: 16px; margin-bottom: 12px;">Understanding Priority (P1–P5)</h3>
        <p style="font-size: 13px; color: #94a3b8; margin: 0 0 12px 0;">
            Priority indicates <strong style="color: #e2e8f0;">remediation urgency</strong> and is not the same as Severity.
        </p>
        <div style="display: flex; gap: 24px;">
            <div style="flex: 1;">
                <strong style="color: #e2e8f0; font-size: 13px; display: block; margin-bottom: 4px;">Standard Findings</strong>
                <span style="font-size: 12px; color: #94a3b8; display: block; margin-bottom: 4px;">Priority follows the finding's technical severity:</span>
                <ul style="margin: 0; padding-left: 20px; font-size: 12px; color: #94a3b8;">
                    <li>Critical &rarr; P1</li>
                    <li>High &rarr; P2</li>
                    <li>Medium &rarr; P3</li>
                    <li>Low &rarr; P4</li>
                    <li>Info / Passed &rarr; P5</li>
                </ul>
            </div>
            <div style="flex: 1;">
                <strong style="color: #e2e8f0; font-size: 13px; display: block; margin-bottom: 4px;">Known Vulnerabilities (CVEs)</strong>
                <span style="font-size: 12px; color: #94a3b8; display: block; margin-bottom: 4px;">Priority is calculated from vulnerability-intelligence signals:</span>
                <ul style="margin: 0; padding-left: 20px; font-size: 12px; color: #94a3b8;">
                    <li><strong>P1:</strong> CVSS &ge; 9.0 OR EPSS &ge; 10%</li>
                    <li><strong>P2:</strong> CVSS &ge; 7.0 OR EPSS &ge; 1%</li>
                    <li><strong>P3:</strong> CVSS &ge; 4.0</li>
                    <li><strong>P4:</strong> CVSS &gt; 0</li>
                    <li><strong>P5:</strong> CVSS = 0, or CVSS unavailable with EPSS &lt; 1%</li>
                </ul>
            </div>
        </div>
        <div style="margin-top: 16px; padding-top: 12px; border-top: 1px solid #334155; font-size: 12px; color: #94a3b8;">
            <p style="margin: 0 0 4px 0;"><strong>Important:</strong> Higher-priority conditions take precedence. For example, a CVE meeting a P1 condition remains P1 even if it also meets a lower-tier condition.</p>
            <p style="margin: 0; font-style: italic;">CVSS indicates vulnerability severity; EPSS indicates exploitation likelihood. Priority uses these signals for remediation prioritization.</p>
        </div>
    </div>

    <div class="card">
        <h2>Vulnerability & Finding Matrix</h2>
        <table>
            <tr><th>Priority</th><th>Severity</th><th>Check Name</th><th>OWASP Category</th><th>Evidence</th></tr>
            {findings_rows}
        </table>
    </div>
{cves_section}
</body>
</html>"""
    return html_content
