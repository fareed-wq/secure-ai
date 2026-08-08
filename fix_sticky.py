import re

with open('src/pages/Scanner.jsx', 'r', encoding='utf-8') as f:
    content = f.read()

old_block = '''          {/* 5. VIEW REPORT STATE */}
          {scanState === 'view-report' && reportData && (
            <motion.div
              key="view-report"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="max-w-6xl mx-auto"
            >
              <ReportHeader 
                url={url} 
                score={reportData.score} 
                timestamp={reportData.scan_start} 
                activeMode={reportMode} 
                onToggleMode={setReportMode}
                onExportPdf={handlePdfExport}
                onRequireAuth={handleRequireAuth}
              />
              
              <ErrorBoundary>
                {reportMode === 'simple' ? (
                  <SimpleReport reportData={reportData} />
                ) : (
                  <TechnicalReport reportData={reportData} />
                )}
              </ErrorBoundary>
            </motion.div>
          )}'''

new_block = '''          {/* 5. VIEW REPORT STATE */}
          {scanState === 'view-report' && reportData && (
            <div
              key="view-report"
              className="max-w-6xl mx-auto"
            >
              <ReportHeader 
                url={url} 
                score={reportData.score} 
                timestamp={reportData.scan_start} 
                activeMode={reportMode} 
                onToggleMode={setReportMode}
                onExportPdf={handlePdfExport}
                onRequireAuth={handleRequireAuth}
              />
              
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
              >
                <ErrorBoundary>
                  {reportMode === 'simple' ? (
                    <SimpleReport reportData={reportData} />
                  ) : (
                    <TechnicalReport reportData={reportData} />
                  )}
                </ErrorBoundary>
              </motion.div>
            </div>
          )}'''

if old_block in content:
    content = content.replace(old_block, new_block)
    with open('src/pages/Scanner.jsx', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Fixed sticky context!")
else:
    print("Could not find the block to replace. Here is the block from file:")
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if "5. VIEW REPORT STATE" in line:
            print('\n'.join(lines[i:i+25]))
