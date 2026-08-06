import { useState } from 'react';
import { Search, ArrowRight, Loader2, ShieldAlert } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import html2pdf from 'html2pdf.js';
import { Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import WhatsAppWidget from '../WhatsAppWidget';

import ModeSelection from '../components/scanner/ModeSelection';
import ReportHeader from '../components/scanner/ReportHeader';
import SimpleReport from '../components/scanner/SimpleReport';
import TechnicalReport from '../components/scanner/TechnicalReport';
import AuthModal from '../components/scanner/AuthModal';
import BottomTicker from '../components/scanner/BottomTicker';

function Scanner() {
  const { user } = useAuth();
  const [url, setUrl] = useState('');
  const [scanState, setScanState] = useState('idle'); // idle, scanning, error, mode-select, view-report
  const [reportData, setReportData] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');
  const [reportMode, setReportMode] = useState('simple'); // simple, technical
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authFeatureName, setAuthFeatureName] = useState('');

  const handleRequireAuth = (featureName) => {
    if (!user) {
      setAuthFeatureName(featureName);
      setAuthModalOpen(true);
    } else {
      // Feature implementation for authenticated users
      alert(`${featureName} is fully implemented in the authenticated dashboard.`);
    }
  };

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url) return;
    
    let parsedUrl = url.trim();
    if (!/^https?:\/\//i.test(parsedUrl)) {
      parsedUrl = 'https://' + parsedUrl;
      setUrl(parsedUrl);
    }
    
    setScanState('scanning');
    setErrorMessage('');
    
    try {
      const minWait = new Promise(resolve => setTimeout(resolve, 6000));
      const fetchPromise = fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: parsedUrl }),
      });
      
      const [response] = await Promise.all([fetchPromise, minWait]);
      const data = await response.json();
      
      if (data.error) {
        setErrorMessage(data.error);
        setScanState('error');
        return;
      }
      
      setReportData(data);
      setScanState('mode-select'); // Go to mode selection first
    } catch (error) {
      console.error('Failed to connect to backend:', error);
      setErrorMessage('Failed to connect to the backend scanner.');
      setScanState('error');
    }
  };

  const resetScan = () => {
    setScanState('idle');
    setUrl('');
    setReportData(null);
    setErrorMessage('');
  };

  const handleSelectMode = (mode) => {
    setReportMode(mode);
    setScanState('view-report');
  };

  const handlePdfExport = async () => {
    const reportElement = document.getElementById('report-container') || document.querySelector('main') || document.body;
    if (!reportElement) return;

    // Save original styles
    const originalHeight = reportElement.style.height;
    const originalOverflow = reportElement.style.overflow;
    
    // Apply temporary CSS fixes for multi-page export
    reportElement.style.height = 'auto';
    reportElement.style.setProperty('height', 'auto', 'important');
    reportElement.style.overflow = 'visible';
    reportElement.style.setProperty('overflow', 'visible', 'important');

    const opt = {
      margin:       [10, 10, 15, 10], // top, left, bottom, right
      filename:     `Security_Report_${new URL(url).hostname}.pdf`,
      image:        { type: 'jpeg', quality: 0.98 },
      html2canvas:  { scale: 2, useCORS: true, logging: false },
      jsPDF:        { unit: 'mm', format: 'a4', orientation: 'portrait' },
      pagebreak:    { mode: ['avoid-all', 'css', 'legacy'] }
    };

    try {
      await html2pdf().from(reportElement).set(opt).toPdf().get('pdf').then(function (pdf) {
        const totalPages = pdf.internal.getNumberOfPages();
        for (let i = 1; i <= totalPages; i++) {
          pdf.setPage(i);
          pdf.setFontSize(10);
          pdf.setTextColor(150);
          pdf.text('Page ' + i + ' of ' + totalPages, pdf.internal.pageSize.getWidth() / 2, pdf.internal.pageSize.getHeight() - 8, { align: 'center' });
        }
      }).save();
    } catch (err) {
      console.error('PDF generation failed', err);
    } finally {
      // Restore CSS
      reportElement.style.height = originalHeight;
      reportElement.style.overflow = originalOverflow;
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 font-sans text-slate-50 selection:bg-indigo-500/30">
      <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 pointer-events-none mix-blend-overlay"></div>
      
      {/* Top Navbar */}
      <nav className="border-b border-white/10 bg-white/5 backdrop-blur-md sticky top-0 z-50 print:hidden">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center cursor-pointer" onClick={resetScan}>
            <img src="/logo-transparent.png" alt="URLScan Online Logo" className="h-12 w-auto object-contain" />
          </div>
          <div className="flex items-center gap-4">
            {user && (
              <Link to="/dashboard" className="text-sm font-bold text-slate-300 hover:text-white bg-slate-800/50 hover:bg-slate-800 px-4 py-2 rounded-lg transition-colors">
                Go to Dashboard
              </Link>
            )}
          </div>
        </div>
      </nav>

      {/* Auth Modal */}
      <AuthModal 
        isOpen={authModalOpen} 
        onClose={() => setAuthModalOpen(false)} 
        featureName={authFeatureName} 
      />

      {/* Dynamic Content */}
      <div className="relative z-10 max-w-7xl mx-auto pb-32 print:hidden">
        <AnimatePresence mode="wait">
          
          {/* 1. IDLE STATE (Search Bar) */}
          {scanState === 'idle' && (
            <motion.div 
              key="idle"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="text-center space-y-8 mt-20"
            >
              <div className="space-y-6 overflow-hidden">
                <div className="space-y-4">
                  <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 via-purple-400 to-emerald-400">
                    IS YOUR WEBSITE SAFE?
                  </h1>
                  <p className="text-2xl font-semibold text-slate-300 max-w-2xl mx-auto tracking-wide">
                    FIND OUT IN ONE CLICK.
                  </p>
                </div>
              </div>

              <BottomTicker />

              <form onSubmit={handleScan} className="max-w-2xl mx-auto relative group">
                <div className="absolute -inset-1 bg-gradient-to-r from-indigo-500 to-purple-500 rounded-2xl blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200"></div>
                <div className="relative flex items-center bg-slate-900 border border-slate-700 rounded-2xl p-2 shadow-2xl focus-within:border-indigo-500 focus-within:ring-1 focus-within:ring-indigo-500 transition-all">
                  <Search className="w-6 h-6 text-slate-400 ml-4 hidden sm:block" />
                  <input
                    type="text"
                    required
                    placeholder="example.com"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className="w-full bg-transparent border-none text-lg px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:ring-0"
                  />
                  <button 
                    type="submit"
                    className="bg-indigo-600 hover:bg-indigo-500 text-white px-6 py-3 rounded-xl font-medium flex items-center gap-2 transition-all transform hover:scale-[1.02] active:scale-[0.98]"
                  >
                    Scan <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </form>
              
              <div className="flex justify-center text-sm text-slate-400 pt-2 font-medium">
                <div className="flex items-center gap-2">Interested in advanced testing? Let's chat on WhatsApp!</div>
              </div>
            </motion.div>
          )}

          {/* 2. SCANNING STATE */}
          {scanState === 'scanning' && (
            <motion.div
              key="scanning"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 1.05 }}
              className="max-w-2xl mx-auto mt-20 p-8 rounded-3xl bg-slate-900/50 border border-slate-800 backdrop-blur-xl shadow-2xl overflow-hidden relative"
            >
              <div className="absolute inset-0 bg-slate-800/[0.2] bg-[size:20px_20px]" style={{backgroundImage: 'radial-gradient(circle, #334155 1px, transparent 1px)'}}></div>
              
              <div className="flex flex-col items-center justify-center space-y-8 py-12 relative z-10">
                <div className="relative">
                  <div className="absolute inset-0 border-4 border-indigo-500/30 rounded-full blur-xl animate-pulse"></div>
                  <div className="absolute inset-0 border-2 border-emerald-500/20 rounded-full animate-[spin_3s_linear_infinite] scale-125"></div>
                  <div className="absolute inset-0 border-2 border-purple-500/20 rounded-full animate-[spin_4s_linear_infinite_reverse] scale-150"></div>
                  <Loader2 className="w-20 h-20 text-indigo-400 animate-spin relative z-10 drop-shadow-[0_0_15px_rgba(99,102,241,0.5)]" />
                </div>
                
                <div className="space-y-4 text-center w-full">
                  <h2 className="text-2xl font-bold tracking-wide text-transparent bg-clip-text bg-gradient-to-r from-indigo-300 to-emerald-300">
                    Establishing Secure Uplink to {url}...
                  </h2>
                  <div className="text-sm text-slate-400">Please wait while our engine performs passive analysis.</div>
                </div>
              </div>
            </motion.div>
          )}

          {/* 3. ERROR STATE */}
          {scanState === 'error' && (
            <motion.div
              key="error"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 1.05 }}
              className="max-w-2xl mx-auto mt-20 p-8 rounded-3xl bg-red-900/20 border border-red-800 backdrop-blur-xl shadow-2xl text-center"
            >
              <ShieldAlert className="w-20 h-20 text-red-500 mx-auto mb-6" />
              <h2 className="text-2xl font-bold text-red-400 mb-4">Scan Failed</h2>
              <p className="text-red-200 mb-8">{errorMessage}</p>
              <button onClick={resetScan} className="bg-slate-800 hover:bg-slate-700 text-white px-6 py-3 rounded-xl transition-all">
                Try Again
              </button>
            </motion.div>
          )}

          {/* 4. MODE SELECTION STATE */}
          {scanState === 'mode-select' && (
            <ModeSelection key="mode-select" onSelectMode={handleSelectMode} />
          )}

          {/* 5. VIEW REPORT STATE */}
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
                grade={reportData.grade} 
                timestamp={reportData.scan_start} 
                activeMode={reportMode} 
                onToggleMode={setReportMode}
                onExportPdf={handlePdfExport}
                onRequireAuth={handleRequireAuth}
              />
              
              {reportMode === 'simple' ? (
                <SimpleReport reportData={reportData} />
              ) : (
                <TechnicalReport reportData={reportData} />
              )}

              <div className="mt-12 flex justify-center">
                <button onClick={resetScan} className="text-slate-400 hover:text-white transition-colors underline underline-offset-4">
                  Run another scan
                </button>
              </div>
            </motion.div>
          )}

        </AnimatePresence>
      </div>
      
      {/* DEDICATED PRINT CONTAINER */}
      {scanState === 'view-report' && reportData && (
        <div className="hidden print:block print:w-full bg-white text-black p-8 font-sans">
          {/* CLEAN DOCUMENT HEADER */}
          <div className="border-b-2 border-slate-900 pb-4 mb-6">
            <h1 className="text-xl font-bold tracking-wide text-slate-900">
              REPORT GENERATED BY URLSCANONLINE.COM
            </h1>
            <p className="text-sm text-slate-600 mt-1">
              Target Domain: {url} | Date: {new Date(reportData.scan_start || Date.now()).toLocaleString()} | Overall Security Score: {reportData.score}/100 ({reportData.grade})
            </p>
          </div>

          {/* EXECUTIVE SUMMARY */}
          <div className="mb-6">
            <h2 className="text-lg font-bold text-slate-900 border-b border-slate-300 pb-1 mb-2">
              1. Executive Summary
            </h2>
            <p className="text-sm text-slate-800">
              Scan completed for {url}. Total checks evaluated: {reportData.findings?.length || 0}. 
              High Priority: {reportData.severity_counts?.High || 0} | Medium Priority: {reportData.severity_counts?.Medium || 0} | Low Priority: {reportData.severity_counts?.Low || 0} | Passed: {reportData.severity_counts?.Passed || 0}
            </p>
          </div>

          {/* DETECTED VULNERABILITIES */}
          <div className="mb-6">
            <h2 className="text-lg font-bold text-slate-900 border-b border-slate-300 pb-1 mb-3">
              2. Detected Vulnerabilities & Action Items
            </h2>
            {(reportData.findings || []).filter(f => f.severity !== 'Passed').map((f, index) => (
              <div key={index} className="mb-4 break-inside-avoid">
                <h3 className="font-bold text-sm text-slate-900">
                  • Finding {index + 1}: {f.name} [{f.severity.toUpperCase()}]
                </h3>
                <p className="text-xs text-slate-700 ml-4 mt-1">
                  <strong>OWASP:</strong> {f.owasp || 'N/A'} | <strong>Confidence:</strong> {f.confidence || '100%'}
                </p>
                {f.remediation_snippets?.nginx && (
                  <div className="ml-4 mt-2 p-3 bg-slate-100 border border-slate-300 rounded font-mono text-xs text-slate-900 break-all whitespace-pre-wrap">
                    {f.remediation_snippets.nginx}
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* PASSED CHECKS */}
          <div className="mb-6 break-inside-avoid">
            <h2 className="text-lg font-bold text-slate-900 border-b border-slate-300 pb-1 mb-2">
              3. Passed Security Checks
            </h2>
            <ul className="list-disc list-inside text-xs text-slate-800 space-y-1">
              {(reportData.findings || []).filter(f => f.severity === 'Passed').map((p, i) => (
                <li key={i}>{p.name}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
      
      {/* Floating Elements (e.g. WhatsApp Widget) preserved for UX */}
      <div className="print:hidden">
        <WhatsAppWidget />
      </div>
    </div>
  );
}

export default Scanner;
