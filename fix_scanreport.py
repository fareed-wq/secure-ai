def patch_file():
    with open('src/pages/ScanReport.jsx', 'r') as f:
        content = f.read()
        
    content = content.replace("import { generateReportPdf } from '../lib/pdfGenerator';", "import usePdfGenerator from '../hooks/usePdfGenerator';")
    
    # We need to extract generatePdf from usePdfGenerator
    content = content.replace("const { scanId } = useParams();", "const { scanId } = useParams();\n  const { isGeneratingPdf, generatePdf } = usePdfGenerator();")
    
    # And replace the handleExportPdf logic
    old_export = """  const handleExportPdf = async () => {
    try {
      await generateReportPdf(reportRef.current, scan.target_url);
    } catch (err) {
      console.error('Failed to generate PDF:', err);
      alert('Failed to generate PDF report.');
    }
  };"""
  
    new_export = """  const handleExportPdf = () => {
    generatePdf(scan.report_data, scan.scan_mode || 'basic', activeMode);
  };"""
    
    content = content.replace(old_export, new_export)
    
    with open('src/pages/ScanReport.jsx', 'w') as f:
        f.write(content)
        
patch_file()
