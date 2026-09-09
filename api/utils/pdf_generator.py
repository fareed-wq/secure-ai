import io
import json
from xml.sax.saxutils import escape
from typing import Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

MAX_EMAIL_PDF_BYTES = 10 * 1024 * 1024

def _resolve_scan_timestamp(report_data: dict, scan_created_at: Optional[str] = None) -> str:
    if scan_created_at:
        return str(scan_created_at)
    if report_data.get("scan_start"):
        return str(report_data["scan_start"])
    return "N/A"

def generate_pdf(report_data: dict, scan_created_at: Optional[str] = None) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    
    # Custom Styles
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
    
    # Header
    url_val = str(report_data.get("target_url") or report_data.get("url") or "Unknown Target")
    elements.append(Paragraph(f"Security Scan Report: {escape(url_val)}", title_style))
    
    date_val = _resolve_scan_timestamp(report_data, scan_created_at)
    elements.append(Paragraph(f"Date: {escape(date_val)}", normal_style))
    
    scan_mode_val = "Advanced" if report_data.get("scan_mode") == "active" else "Basic"
    elements.append(Paragraph(f"Mode: {scan_mode_val}", normal_style))
    
    score_val = str(report_data.get("score", "N/A"))
    elements.append(Paragraph(f"Score: {escape(score_val)}/100", normal_style))
    elements.append(Spacer(1, 20))
    
    # Severity Summary
    severity_counts = report_data.get("severity_counts", {})
    if not severity_counts and report_data.get("findings"):
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Passed": 0}
        for f in report_data.get("findings", []):
            sev = f.get("severity", "Low")
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts[sev] = 1

    if severity_counts:
        elements.append(Paragraph("Severity Summary", subtitle_style))
        data = [
            ["Critical", "High", "Medium", "Low"],
            [
                str(severity_counts.get("Critical", 0)),
                str(severity_counts.get("High", 0)),
                str(severity_counts.get("Medium", 0)),
                str(severity_counts.get("Low", 0))
            ]
        ]
        t = Table(data, colWidths=[100]*4)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('TEXTCOLOR', (0, 1), (0, 1), colors.darkred),
            ('TEXTCOLOR', (1, 1), (1, 1), colors.red),
            ('TEXTCOLOR', (2, 1), (2, 1), colors.orange),
            ('TEXTCOLOR', (3, 1), (3, 1), colors.blue),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 20))
        
    # Findings
    elements.append(Paragraph("Findings Detail", subtitle_style))
    findings = report_data.get("findings", [])
    
    for f in findings:
        severity = str(f.get("severity", "Info"))
        if severity == "Passed":
            continue
            
        name = escape(str(f.get("name", "Unknown Finding")))
        elements.append(Paragraph(f"{name} [{escape(severity)}]", finding_title_style))
        
        desc = escape(str(f.get("description", "No description provided.")))
        elements.append(Paragraph(f"<b>Description:</b> {desc}", normal_style))
        
        remediation = escape(str(f.get("remediation", "No remediation provided.")))
        elements.append(Paragraph(f"<b>Remediation:</b> {remediation}", normal_style))
        elements.append(Spacer(1, 10))

    doc.build(elements)
    
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    return pdf_bytes