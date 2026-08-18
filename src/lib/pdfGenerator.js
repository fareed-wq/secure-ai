import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

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
  doc.text("URLScannerOnline Security Assessment Report", margin, yPos);
  
  yPos += 10;
  doc.setFontSize(11);
  doc.setTextColor(71, 85, 105); // slate-600
  doc.text(`Target URL: ${url}`, margin, yPos);
  yPos += 6;
  doc.text(`Date: ${date}`, margin, yPos);
  yPos += 6;
  doc.text(`Scan Type: ${scanMode === 'active' ? 'Advanced (Active Security Testing)' : 'Basic (Passive/Read-Only)'}`, margin, yPos);
  yPos += 6;
  doc.text(`Report Type: ${reportMode === 'technical' ? 'Technical' : 'Simple'}`, margin, yPos);
  yPos += 6;
  doc.text(`Overall Security Score: ${scanData.score !== undefined ? scanData.score + '/100' : 'N/A'}`, margin, yPos);
  
  // Draw Line
  yPos += 10;
  doc.setDrawColor(203, 213, 225); // slate-300
  doc.line(margin, yPos, 210 - margin, yPos);
  yPos += 10;

  // Executive Summary
  doc.setFontSize(14);
  doc.setTextColor(15, 23, 42);
  doc.text("1. Executive Summary", margin, yPos);
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
  
  doc.text(doc.splitTextToSize(summaryText, 210 - 2 * margin), margin, yPos);
  yPos += 16;

  const actionItems = (scanData.findings || []).filter(f => f.severity !== 'Passed');
  const passedItems = (scanData.findings || []).filter(f => f.severity === 'Passed');

  if (reportMode === 'simple') {
    // SIMPLE REPORT
    doc.setFontSize(14);
    doc.setTextColor(15, 23, 42);
    doc.text("2. Key Risks & Prioritized Recommendations", margin, yPos);
    yPos += 6;

    if (actionItems.length === 0) {
      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85);
      doc.text("No security issues were identified.", margin, yPos);
      yPos += 10;
    } else {
      const simpleData = actionItems.map(f => [
        `[${f.severity.toUpperCase()}] ${f.name}`,
        f.description || 'No description provided.',
        f.remediation || 'No remediation provided.'
      ]);

      autoTable(doc, {
        startY: yPos,
        head: [['Finding', 'Description', 'Recommendation']],
        body: simpleData,
        theme: 'grid',
        headStyles: { fillColor: [99, 102, 241] }, // indigo-500
        styles: { fontSize: 9, cellPadding: 4 },
        columnStyles: { 0: { cellWidth: 40 }, 1: { cellWidth: 70 }, 2: { cellWidth: 70 } },
        margin: { left: margin, right: margin }
      });
      yPos = doc.lastAutoTable.finalY + 10;
    }

    // Passed Checks
    doc.setFontSize(14);
    doc.setTextColor(15, 23, 42);
    
    // Check if we need to page break before passed checks
    if (yPos > 250) {
      doc.addPage();
      yPos = 20;
    }
    
    doc.text("3. Important Passed Checks", margin, yPos);
    yPos += 6;

    if (passedItems.length === 0) {
      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85);
      doc.text("No passed checks to report.", margin, yPos);
      yPos += 10;
    } else {
      const passedData = passedItems.map(f => [f.name]);
      autoTable(doc, {
        startY: yPos,
        head: [['Passed Security Checks']],
        body: passedData,
        theme: 'grid',
        headStyles: { fillColor: [16, 185, 129] }, // emerald-500
        styles: { fontSize: 9, cellPadding: 3 },
        margin: { left: margin, right: margin }
      });
      yPos = doc.lastAutoTable.finalY + 10;
    }

  } else {
    // TECHNICAL REPORT
    doc.setFontSize(14);
    doc.setTextColor(15, 23, 42);
    doc.text("2. Detailed Findings", margin, yPos);
    yPos += 6;

    if (actionItems.length === 0) {
      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85);
      doc.text("No security issues were identified.", margin, yPos);
      yPos += 10;
    } else {
      actionItems.forEach((f, index) => {
        const severityColor = f.severity === 'High' ? [239, 68, 68] : f.severity === 'Medium' ? [245, 158, 11] : [99, 102, 241];
        
        const findingData = [
          ['Module/Category', `${f.module || 'N/A'} / ${f.category || 'N/A'}`],
          ['Description', f.description || 'N/A'],
          ['OWASP Mapping', f.owasp || 'N/A'],
          ['Confidence', f.confidence || '100%'],
          ['Remediation', f.remediation || 'N/A']
        ];

        if (f.evidence) {
          findingData.push(['Evidence', typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence, null, 2)]);
        }
        
        if (f.remediation_snippets) {
            findingData.push(['Remediation Snippets', JSON.stringify(f.remediation_snippets, null, 2)]);
        }

        autoTable(doc, {
          startY: yPos,
          head: [[`Finding ${index + 1}: ${f.name} [${f.severity.toUpperCase()}]`, '']],
          body: findingData,
          theme: 'grid',
          headStyles: { fillColor: severityColor },
          styles: { fontSize: 9, cellPadding: 4, overflow: 'linebreak' },
          columnStyles: { 0: { cellWidth: 40, fontStyle: 'bold' } },
          margin: { left: margin, right: margin }
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

    doc.text("3. Passed Security Checks", margin, yPos);
    yPos += 6;

    if (passedItems.length === 0) {
      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85);
      doc.text("No passed checks to report.", margin, yPos);
      yPos += 10;
    } else {
      const passedData = passedItems.map(f => [f.name, f.module || 'N/A']);
      autoTable(doc, {
        startY: yPos,
        head: [['Passed Check', 'Module']],
        body: passedData,
        theme: 'grid',
        headStyles: { fillColor: [16, 185, 129] }, // emerald-500
        styles: { fontSize: 9, cellPadding: 3 },
        margin: { left: margin, right: margin }
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

      doc.text("4. Technologies Detected", margin, yPos);
      yPos += 6;

      const techData = scanData.technologies.map(t => [t]);
      autoTable(doc, {
        startY: yPos,
        head: [['Technology']],
        body: techData,
        theme: 'plain',
        styles: { fontSize: 9, cellPadding: 2 },
        margin: { left: margin, right: margin }
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
  doc.text("Disclaimer & Scope", margin, yPos);
  yPos += 6;

  doc.setFontSize(8);
  doc.setTextColor(100, 116, 139);
  const disclaimerText = scanMode === 'active' 
    ? "This report was generated using Active Security Testing, which performs deeper interaction with the target. While findings indicate potential risks based on responses received, this automated scan does not replace a manual penetration test." 
    : "This report was generated using Passive Security Assessment, which observes publicly accessible signals without intrusive testing. It is designed to be safe for production environments but may not detect vulnerabilities requiring active exploitation.";
  
  doc.text(doc.splitTextToSize(disclaimerText, 210 - 2 * margin), margin, yPos);

  // Add page numbers
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184); // slate-400
    doc.text(`Page ${i} of ${pageCount}`, 210 / 2, 297 - 10, { align: 'center' });
  }

  // Save the PDF
  const safeUrl = url.replace(/[^a-z0-9]/gi, '_').toLowerCase();
  const filename = `${safeUrl}_${scanMode}_${reportMode}_report.pdf`;
  doc.save(filename);
};
