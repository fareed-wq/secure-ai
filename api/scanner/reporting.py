import datetime
import html
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
        name = html.escape(str(f['name']))
        owasp = html.escape(str(f['owasp']))
        evidence = html.escape(str(f['evidence']))
        table_rows.append(
            f"<tr><td class='sev-{sev}'>{sev}</td><td>{name}</td><td>{owasp}</td>"
            f"<td><div class='snippet'>{evidence}</div></td></tr>"
        )
    findings_rows = "".join(table_rows)

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
        .snippet {{ background: #030712; padding: 8px; font-family: monospace; font-size: 12px; border-radius: 4px; color: #a7f3d0; border: 1px solid #1f2937; white-space: pre-wrap; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="logo">URLScanOnline Security Report</div>
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

    <div class="card">
        <h2>Vulnerability & Finding Matrix</h2>
        <table>
            <tr><th>Severity</th><th>Check Name</th><th>OWASP Category</th><th>Evidence</th></tr>
            {findings_rows}
        </table>
    </div>
</body>
</html>"""
    return html_content
