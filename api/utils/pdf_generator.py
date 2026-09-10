import reportlab.rl_config
reportlab.rl_config.invariant = 1

import io
from xml.sax.saxutils import escape
from typing import Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.pdfgen import canvas

MAX_EMAIL_PDF_BYTES = 10 * 1024 * 1024

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        self.setFont("Helvetica", 9)
        self.drawRightString(200 * 2.8, 20, f"Page {self._pageNumber} of {page_count}")

def _resolve_scan_timestamp(report_data: dict, scan_created_at: Optional[str] = None) -> str:
    if scan_created_at:
        return str(scan_created_at)[:10]
    if report_data.get("scan_start"):
        return str(report_data["scan_start"])[:10]
    return "undated"

def generate_pdf(report_data: dict, scan_created_at: Optional[str] = None) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()

    title_style = styles['Heading1']
    subtitle_style = styles['Heading2']
    normal_style = styles['Normal']

    finding_title_style = ParagraphStyle(
        'FindingTitle',
        parent=styles['Heading3'],
        spaceAfter=6,
        textColor=colors.darkblue
    )

    elements = []

    url_val = str(report_data.get("target_url") or report_data.get("url") or "Unknown Target")
    date_val = _resolve_scan_timestamp(report_data, scan_created_at)
    scan_mode_val = "Advanced" if report_data.get("scan_mode") == "active" else "Basic"
    score_val = str(report_data.get("score", "N/A"))

    # Process severities safely
    findings = report_data.get("findings", [])
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Passed": 0}
    actionable_severities = ["Critical", "High", "Medium", "Low"]
    informational_severities = ["Informational", "Info", "Inconclusive", "Skipped"]

    normalized_findings = []
    for f in findings:
        raw_sev = str(f.get("severity", "Info")).strip().title()
        if raw_sev == "Info" or raw_sev in informational_severities:
            norm_sev = "Informational"
        elif raw_sev in actionable_severities:
            norm_sev = raw_sev
        elif raw_sev == "Passed":
            norm_sev = "Passed"
        else:
            norm_sev = "Informational"

        severity_counts[norm_sev] = severity_counts.get(norm_sev, 0) + 1

        nf = dict(f)
        nf["normalized_severity"] = norm_sev
        normalized_findings.append(nf)

    # ----------------------------------------------------
    # PAGE 1 / EXECUTIVE OVERVIEW
    # ----------------------------------------------------
    elements.append(Paragraph("URLScannerOnline Scheduled Security Assessment Report", title_style))
    elements.append(Spacer(1, 10))

    header_data = [
        ["Target URL", escape(url_val)],
        ["Scan Date/Time", escape(date_val)],
        ["Scan Type", scan_mode_val],
        ["Overall Security Score", f"{escape(score_val)}/100"]
    ]
    t_header = Table(header_data, colWidths=[150, 350], hAlign='LEFT')
    t_header.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(t_header)
    elements.append(Spacer(1, 20))

    # Severity Summary
    elements.append(Paragraph("Executive Summary", subtitle_style))
    elements.append(Spacer(1, 10))

    summary_data = [
        ["Critical", "High", "Medium", "Low", "Informational", "Inconclusive", "Passed"],
        [
            str(severity_counts.get("Critical", 0)),
            str(severity_counts.get("High", 0)),
            str(severity_counts.get("Medium", 0)),
            str(severity_counts.get("Low", 0)),
            str(severity_counts.get("Informational", 0)),
            str(severity_counts.get("Inconclusive", 0)),
            str(severity_counts.get("Passed", 0))
        ]
    ]
    t_sev = Table(summary_data, colWidths=[65]*7)
    t_sev.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('TEXTCOLOR', (0, 1), (0, 1), colors.darkred),
        ('TEXTCOLOR', (1, 1), (1, 1), colors.red),
        ('TEXTCOLOR', (2, 1), (2, 1), colors.orange),
        ('TEXTCOLOR', (3, 1), (3, 1), colors.blue),
        ('TEXTCOLOR', (4, 1), (4, 1), colors.grey),
        ('TEXTCOLOR', (5, 1), (5, 1), colors.grey),
        ('TEXTCOLOR', (6, 1), (6, 1), colors.green),
    ]))
    elements.append(t_sev)
    elements.append(Spacer(1, 20))

    # Prioritized Recommendations
    elements.append(Paragraph("Key Risks & Prioritized Recommendations", subtitle_style))
    elements.append(Spacer(1, 10))

    sev_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Informational": 5, "Inconclusive": 6, "Passed": 7}
    actionable_findings = [f for f in normalized_findings if f["normalized_severity"] in actionable_severities]
    actionable_findings.sort(key=lambda x: sev_order.get(x["normalized_severity"], 99))

    if actionable_findings:
        for f in actionable_findings:
            sev = escape(f["normalized_severity"])
            name = escape(str(f.get("name", "Unknown Finding")))
            desc = escape(str(f.get("description", "No description provided.")))
            rec = escape(str(f.get("remediation", "No remediation provided.")))

            elements.append(Paragraph(f"<b>[{sev}]</b> {name}", finding_title_style))
            elements.append(Paragraph(f"<b>Description:</b> {desc}", normal_style))
            elements.append(Paragraph(f"<b>Recommendation:</b> {rec}", normal_style))
            elements.append(Spacer(1, 10))
    else:
        elements.append(Paragraph("No actionable risks identified.", normal_style))

    elements.append(PageBreak())

    # ----------------------------------------------------
    # TECHNICAL APPENDIX
    # ----------------------------------------------------
    elements.append(Paragraph("Technical Details", subtitle_style))
    elements.append(Spacer(1, 10))

    tech_findings = [f for f in normalized_findings if f["normalized_severity"] != "Passed"]
    tech_findings.sort(key=lambda x: sev_order.get(x["normalized_severity"], 99))

    if tech_findings:
        for f in tech_findings:
            name = escape(str(f.get("name", "Unknown Finding")))
            sev = escape(f["normalized_severity"])
            elements.append(Paragraph(f"{name} [{sev}]", finding_title_style))

            if f.get("category"):
                elements.append(Paragraph(f"<b>Category:</b> {escape(str(f.get('category')))}", normal_style))
            if f.get("confidence"):
                elements.append(Paragraph(f"<b>Confidence:</b> {escape(str(f.get('confidence')))}", normal_style))
            if f.get("owasp"):
                elements.append(Paragraph(f"<b>OWASP Mapping:</b> {escape(str(f.get('owasp')))}", normal_style))

            desc = escape(str(f.get("description", "No description provided.")))
            elements.append(Paragraph(f"<b>Description:</b> {desc}", normal_style))

            remediation = f.get("remediation")
            if remediation:
                elements.append(Paragraph(f"<b>Remediation:</b> {escape(str(remediation))}", normal_style))

            evidence = f.get("evidence")
            if evidence:
                elements.append(Paragraph(f"<b>Evidence:</b> {escape(str(evidence))}", normal_style))

            elements.append(Spacer(1, 15))
    else:
        elements.append(Paragraph("No technical details to display.", normal_style))
        elements.append(Spacer(1, 15))

    # Passed Checks
    passed_findings = [f for f in normalized_findings if f["normalized_severity"] == "Passed"]
    if passed_findings:
        elements.append(Paragraph("Passed Security Checks", subtitle_style))
        elements.append(Spacer(1, 10))
        for f in passed_findings:
            name = escape(str(f.get("name", "Unknown Check")))
            elements.append(Paragraph(f"&#10003; {name}", normal_style))
        elements.append(Spacer(1, 20))

    # Disclaimer
    elements.append(Paragraph("Disclaimer & Scope", subtitle_style))
    elements.append(Spacer(1, 10))
    if scan_mode_val == "Basic":
        elements.append(Paragraph("This is a passive security assessment using non-intrusive publicly accessible configuration and metadata checks. It does not actively probe for complex vulnerabilities or perform destructive testing. This report is for informational purposes only.", normal_style))
    else:
        elements.append(Paragraph("This is a passive-first, low-impact assessment that may perform bounded additional HTTP, DNS, and limited TCP checks. It does NOT perform exploitation, brute force attacks, arbitrary form/input attacks, or destructive testing. This report reflects findings discovered at the time of the scan and is for informational purposes only.", normal_style))

    doc.build(elements, canvasmaker=NumberedCanvas)

    pdf_bytes = buffer.getvalue()
    buffer.close()

    return pdf_bytes
