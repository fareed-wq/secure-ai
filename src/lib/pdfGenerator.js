import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import { getTranslation } from "./utils/translations";

const sanitizeText = (text) => {
  if (typeof text !== 'string') return text;
  return text
    .replace(/[\u2018\u2019]/g, "'") // Smart single quotes
    .replace(/[\u201C\u201D]/g, '"') // Smart double quotes
    .replace(/[\u2013\u2014]/g, "-") // En and em dashes
    .replace(/\u2026/g, "...")      // Ellipsis
    .replace(/\uFFFD/g, "")         // Replacement character
    .replace(/[\u00A0\u200B-\u200F\uFEFF\x00-\x09\x0B-\x1F\x7F-\x9F]/g, " "); // Control characters and non-breaking spaces
};

export const generateStructuredPdf = (scanData, scanMode, reportMode) => {
  const doc = new jsPDF();
  const url = scanData.target_url || scanData.url || 'Unknown Target';
  const date = new Date(scanData.scan_start || Date.now()).toLocaleString();

  // Basic Settings
  const margin = 14;
  let yPos = 20;

  // Title
  doc.setFontSize(18);
  doc.setTextColor(15, 23, 42); // slate-900
  doc.text(sanitizeText("URLScannerOnline Security Assessment Report"), margin, yPos);

  yPos += 10;
  doc.setFontSize(11);
  doc.setTextColor(71, 85, 105); // slate-600
  doc.text(sanitizeText(`Target URL: ${url}`), margin, yPos);
  yPos += 6;
  doc.text(sanitizeText(`Date: ${date}`), margin, yPos);
  yPos += 6;
  doc.text(sanitizeText(`Scan Type: ${scanMode === 'active' ? 'Advanced' : 'Basic'}`), margin, yPos);
  yPos += 6;
  doc.text(sanitizeText(`Report Type: ${reportMode === 'technical' ? 'Technical' : 'Simple'}`), margin, yPos);
  yPos += 6;
  doc.text(sanitizeText(`Overall Security Score: ${scanData.score !== undefined ? scanData.score + '/100' : 'N/A'}`), margin, yPos);

  yPos += 6;
  const covData = scanData.report_data?.assessment_coverage || scanData.assessment_coverage;
  if (covData && covData.available) {
    doc.text(sanitizeText(`Assessment Coverage: ${Math.round(covData.percentage)}% of intended checks completed`), margin, yPos);
  } else {
    doc.text(sanitizeText('Assessment Coverage: Not available'), margin, yPos);
  }

  yPos += 6;
  const expData = scanData.report_data?.exposure || scanData.exposure;
  if (expData && expData.level) {
    const expText = expData.level === 'HIGH' ? 'This site exposes additional externally reachable surfaces.' :
                    expData.level === 'MODERATE' ? 'This site is publicly reachable on the web.' :
                    expData.level === 'LOW' ? 'This target appears limited to private/local network addressing.' :
                    'Exposure could not be determined from this scan.';
    doc.text(sanitizeText(`Exposure: ${expData.level} - ${expText}`), margin, yPos);
  } else {
    doc.text(sanitizeText('Exposure: Not available'), margin, yPos);
  }

  // Draw Line
  yPos += 10;
  doc.setDrawColor(203, 213, 225); // slate-300
  doc.line(margin, yPos, 210 - margin, yPos);
  yPos += 10;

  // Executive Summary
  doc.setFontSize(14);
  doc.setTextColor(15, 23, 42);
  doc.text(sanitizeText("1. Executive Summary"), margin, yPos);
  yPos += 8;

  doc.setFontSize(10);
  doc.setTextColor(51, 65, 85);
  const totalFindings = scanData.findings?.length || 0;
  const highCount = scanData.severity_counts?.High || 0;
  const mediumCount = scanData.severity_counts?.Medium || 0;
  const lowCount = scanData.severity_counts?.Low || 0;
  const passedCount = scanData.severity_counts?.Passed || 0;

  const summaryText = `Scan completed for ${url}. Total checks evaluated: ${totalFindings}.
High Priority: ${highCount} | Medium Priority: ${mediumCount} | Low Priority: ${lowCount} | Passed: ${passedCount}`;

  doc.text(doc.splitTextToSize(sanitizeText(summaryText), 210 - 2 * margin), margin, yPos);
  yPos += 16;

  let actionItems = (scanData.findings || []).filter(f => f.severity !== 'Passed');
  const passedItems = (scanData.findings || []).filter(f => f.severity === 'Passed');

  if (reportMode === 'simple') {
    // SIMPLE REPORT

    // Add score explanation and passive scope note
    yPos -= 8;
    doc.setFontSize(9);
    doc.setTextColor(100, 116, 139); // slate-500
    doc.text(sanitizeText("Your score is based on detected Critical, High, Medium, and Low findings. Informational observations and Passed checks do not change the score."), margin, yPos, { maxWidth: 210 - 2 * margin });
    yPos += 8;
    doc.text(sanitizeText("This assessment is a passive, external scan of publicly observable behavior. It does not replace comprehensive penetration testing or guarantee that no other vulnerabilities exist."), margin, yPos, { maxWidth: 210 - 2 * margin });
    yPos += 12;

    const scoredFindings = actionItems.filter(f => f.severity !== 'Informational' && f.severity !== 'Inconclusive');
    const informationalFindings = actionItems.filter(f => f.severity === 'Informational');

    // Sort findings for simple report (Critical/High/Medium/Low)
    const severityOrder = { 'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4 };
    scoredFindings.sort((a, b) => (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5));

    doc.setFontSize(14);
    doc.setTextColor(15, 23, 42);
    doc.text(sanitizeText("2. Issues That Need Attention"), margin, yPos);
    yPos += 6;

    if (scoredFindings.length === 0) {
      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85);
      doc.text(sanitizeText("No scored issues were detected in this passive assessment."), margin, yPos);
      yPos += 10;
    } else {
      const simpleData = scoredFindings.map(f => {
        const trans = getTranslation(f);
        const desc = trans.why ? `${trans.problem}\n\nWhy it matters: ${trans.why}` : trans.problem;
        return [
          sanitizeText(`[${f.severity.toUpperCase()}] ${trans.name}`),
          sanitizeText(desc),
          sanitizeText(trans.action || '')
        ];
      });

      autoTable(doc, {
        startY: yPos,
        head: [['Severity & Issue', 'Description', 'What to do']],
        body: simpleData,
        theme: 'grid',
        headStyles: { fillColor: [99, 102, 241] }, // indigo-500
        styles: { fontSize: 9, cellPadding: 4 },
        columnStyles: { 0: { cellWidth: 40 }, 1: { cellWidth: 70 }, 2: { cellWidth: 70 } },
        margin: { left: margin, right: margin },
        pageBreak: 'auto',
        rowPageBreak: 'avoid'
      });
      yPos = doc.lastAutoTable.finalY + 10;
    }

    let sectionNum = 3;

    // Additional Technical Observations
    if (informationalFindings.length > 0) {
      if (yPos > 240) { doc.addPage(); yPos = 20; }

      doc.setFontSize(14);
      doc.setTextColor(15, 23, 42);
      doc.text(sanitizeText(`${sectionNum}. Additional Technical Observations`), margin, yPos);
      yPos += 6;

      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85);
      const obsText = `${informationalFindings.length} additional technical ${informationalFindings.length === 1 ? 'observation was' : 'observations were'} collected. These do not affect your score. View the Technical report for detailed diagnostic information.`;
      doc.text(doc.splitTextToSize(sanitizeText(obsText), 210 - 2 * margin), margin, yPos);
      yPos += 14;

      sectionNum++;
    }

    // Passed Checks
    doc.setFontSize(14);
    doc.setTextColor(15, 23, 42);

    // Check if we need to page break before passed checks
    if (yPos > 250) {
      doc.addPage();
      yPos = 20;
    }

    doc.text(sanitizeText(`${sectionNum}. Passed Checks`), margin, yPos);
    yPos += 6;

    if (passedItems.length === 0) {
      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85);
      doc.text(sanitizeText("No passed checks to report."), margin, yPos);
      yPos += 10;
    } else {
      const passedData = passedItems.map(f => [sanitizeText(getTranslation(f).name)]);
      autoTable(doc, {
        startY: yPos,
        head: [['Passed Security Checks']],
        body: passedData,
        theme: 'grid',
        headStyles: { fillColor: [16, 185, 129] }, // emerald-500
        styles: { fontSize: 9, cellPadding: 3 },
        margin: { left: margin, right: margin },
        pageBreak: 'auto',
        rowPageBreak: 'avoid'
      });
      yPos = doc.lastAutoTable.finalY + 10;
    }

  } else {
    // TECHNICAL REPORT
    doc.setFontSize(14);
    doc.setTextColor(15, 23, 42);
    doc.text(sanitizeText("2. Detailed Findings"), margin, yPos);
    yPos += 6;

    if (actionItems.length === 0) {
      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85);
      doc.text(sanitizeText("No security issues were identified."), margin, yPos);
      yPos += 10;
    } else {
      const sevWeights = { Critical: 6, High: 5, Medium: 4, Low: 3, Informational: 2, Passed: 1 };
      const sortedItems = [...actionItems].sort((a, b) => {
        const wd = (sevWeights[b.severity] || 0) - (sevWeights[a.severity] || 0);
        if (wd !== 0) return wd;
        return (a.name || '').localeCompare(b.name || '');
      });
      sortedItems.forEach((f, index) => {
        // Page break if we are too close to the bottom (reserve ~67 units for header + 1-2 rows)
        if (yPos > 230) {
          doc.addPage();
          yPos = 20;
        }

        const severityColor = f.severity === 'High' || f.severity === 'Critical' ? [239, 68, 68] : f.severity === 'Medium' ? [245, 158, 11] : [99, 102, 241];

        const findingData = [];

        if (f.module || f.category) {
          findingData.push(['Module/Category', sanitizeText(`${f.module || 'N/A'} / ${f.category || 'N/A'}`)]);
        }

        if (f.description) {
          findingData.push(['Description', sanitizeText(f.description)]);
        }

        if (f.owasp) {
          findingData.push(['OWASP Mapping', sanitizeText(f.owasp)]);
        }

        if (f.confidence) {
          findingData.push(['Confidence', sanitizeText(f.confidence)]);
        }

        if (f.remediation) {
          findingData.push(['Remediation', sanitizeText(f.remediation)]);
        }

        if (f.evidence && Object.keys(f.evidence).length > 0) {
          const evStr = typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence, null, 2);
          findingData.push(['Evidence', sanitizeText(evStr)]);
        }

        if (f.remediation_snippets && Object.keys(f.remediation_snippets).length > 0) {
          const rsStr = typeof f.remediation_snippets === 'string' ? f.remediation_snippets : JSON.stringify(f.remediation_snippets, null, 2);
          findingData.push(['Remediation Snippets', sanitizeText(rsStr)]);
        }

        autoTable(doc, {
          startY: yPos,
          head: [[sanitizeText(`Finding ${index + 1}: ${f.name} [${f.severity.toUpperCase()}]`), '']],
          body: findingData,
          theme: 'grid',
          headStyles: { fillColor: severityColor },
          styles: { fontSize: 9, cellPadding: 4, overflow: 'linebreak' },
          columnStyles: { 0: { cellWidth: 40, fontStyle: 'bold' } },
          margin: { left: margin, right: margin },
          pageBreak: 'auto',
          rowPageBreak: 'avoid'
        });
        yPos = doc.lastAutoTable.finalY + 10;
      });
    }

    // Passed Checks
    doc.setFontSize(14);
    doc.setTextColor(15, 23, 42);

    // Check if we need to page break before passed checks
    if (yPos > 250) {
      doc.addPage();
      yPos = 20;
    }

    doc.text(sanitizeText("3. Passed Security Checks"), margin, yPos);
    yPos += 6;

    if (passedItems.length === 0) {
      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85);
      doc.text(sanitizeText("No passed checks to report."), margin, yPos);
      yPos += 10;
    } else {
      const sortedPassedItems = [...passedItems].sort(
        (a, b) => (a.name || '').localeCompare(b.name || '')
      );
      const passedData = sortedPassedItems.map(f => [sanitizeText(f.name), sanitizeText(f.module || 'N/A')]);
      autoTable(doc, {
        startY: yPos,
        head: [['Passed Check', 'Module']],
        body: passedData,
        theme: 'grid',
        headStyles: { fillColor: [16, 185, 129] }, // emerald-500
        styles: { fontSize: 9, cellPadding: 3 },
        margin: { left: margin, right: margin },
        pageBreak: 'auto',
        rowPageBreak: 'avoid'
      });
      yPos = doc.lastAutoTable.finalY + 10;
    }

    // Technologies
    if (scanData.technologies && scanData.technologies.length > 0) {
      doc.setFontSize(14);
      doc.setTextColor(15, 23, 42);

      if (yPos > 250) {
        doc.addPage();
        yPos = 20;
      }

      doc.text(sanitizeText("4. Technologies Detected"), margin, yPos);
      yPos += 6;

      const techData = scanData.technologies.map(t => [sanitizeText(t)]);
      autoTable(doc, {
        startY: yPos,
        head: [['Technology']],
        body: techData,
        theme: 'plain',
        styles: { fontSize: 9, cellPadding: 2 },
        margin: { left: margin, right: margin },
        pageBreak: 'auto',
        rowPageBreak: 'avoid'
      });
      yPos = doc.lastAutoTable.finalY + 10;
    }
  }

  // Footer Disclaimer
  if (yPos > 270) {
    doc.addPage();
    yPos = 20;
  }

  doc.setFontSize(12);
  doc.setTextColor(15, 23, 42);
  doc.text(sanitizeText("Disclaimer & Scope"), margin, yPos);
  yPos += 6;

  doc.setFontSize(8);
  doc.setTextColor(100, 116, 139);
  const disclaimerText = scanMode === 'active'
    ? "This report was generated using the Advanced scan mode. It is a passive, external assessment of publicly observable behavior. Findings identify observable security configuration and exposure signals. This automated assessment does not replace comprehensive manual penetration testing."
    : "This report was generated using Passive Security Assessment, which observes publicly accessible signals without intrusive testing. It is designed to be safe for production environments but may not detect vulnerabilities requiring active exploitation.";

  doc.text(doc.splitTextToSize(sanitizeText(disclaimerText), 210 - 2 * margin), margin, yPos);

  // Add page numbers
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184); // slate-400
    doc.text(sanitizeText(`Page ${i} of ${pageCount}`), 210 / 2, 297 - 10, { align: 'center' });
  }

  // FILE NAMING: Convert target URL to hostname only
  let hostname = url;
  try {
    hostname = new URL(url.startsWith('http') ? url : 'http://' + url).hostname;
    hostname = hostname.replace(/^www\./i, '');
  } catch (e) {
    // fallback to safeUrl if parsing fails
  }
  const safeHostname = hostname.replace(/[^a-z0-9.-]/gi, '_').toLowerCase();
  const displayScanMode = scanMode === 'active' ? 'advanced' : 'basic';
  const filename = `${safeHostname}_${displayScanMode}_${reportMode}_report.pdf`;

  // Save the PDF
  doc.save(filename);
};
