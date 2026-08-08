import { useState, useEffect, useRef } from 'react';
import { Search, ArrowRight, Loader2, ShieldAlert, Lock } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import html2pdf from 'html2pdf.js';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import WhatsAppWidget from '../WhatsAppWidget';

import ModeSelection from '../components/scanner/ModeSelection';
import ReportHeader from '../components/scanner/ReportHeader';
import SimpleReport from '../components/scanner/SimpleReport';
import TechnicalReport from '../components/scanner/TechnicalReport';
import AuthModal from '../components/scanner/AuthModal';
import PdfComingSoonModal from '../components/scanner/PdfComingSoonModal';
import BottomTicker from '../components/scanner/BottomTicker';
import SafetyComparison from '../components/scanner/SafetyComparison';

// Force relative paths in production so it hits the Vercel Serverless functions directly
export const API_BASE_URL = 
  (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') 
    ? (import.meta.env.VITE_API_URL || 'http://localhost:5000') 
    : '';

function Scanner() {
  const { user } = useAuth();
  const location = useLocation();
  const [url, setUrl] = useState('');
  const [scanState, setScanState] = useState('idle'); // idle, scanning, error, mode-select, view-report
  const [reportData, setReportData] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');
  const [validationError, setValidationError] = useState('');
  const [reportMode, setReportMode] = useState('simple'); // simple, technical
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authFeatureName, setAuthFeatureName] = useState('');
  const [pdfModalOpen, setPdfModalOpen] = useState(false);
  const urlInputRef = useRef(null);

  useEffect(() => {
    if (location.state?.resetScan) {
      setScanState('idle');
      setReportData(null);
      setUrl('');
      setErrorMessage('');
    }
  }, [location.state?.resetScan]);

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
    let cleanInput = parsedUrl.replace(/^https?:\/\//i, '').replace(/^www\./i, '');
    const domainRegex = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)?$/;
    
    if (!domainRegex.test(cleanInput)) {
      setValidationError("Please enter a full domain name (e.g., google.com or site.in).");
      urlInputRef.current?.blur();
      return;
    }

    if (!/^https?:\/\//i.test(parsedUrl)) {
      parsedUrl = 'https://' + parsedUrl;
      setUrl(parsedUrl);
    }
    
    setScanState('scanning');
    setErrorMessage('');
    
    try {
      const minWait = new Promise(resolve => setTimeout(resolve, 6000));
      const fetchPromise = fetch(`${API_BASE_URL}/api/scan`, {
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
      console.error('Backend Connection Error:', error);
      setErrorMessage(`Failed to connect to the backend scanner: ${error.message || error}`);
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

  const handlePdfExport = () => {
    setPdfModalOpen(true);
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

      {/* PDF Coming Soon Modal */}
      <PdfComingSoonModal
        isOpen={pdfModalOpen}
        onClose={() => setPdfModalOpen(false)}
      />

      {/* Validation Error Popup */}
      <AnimatePresence>
        {validationError && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
            <motion.div 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-slate-900 border border-rose-500/30 shadow-2xl shadow-rose-500/10 rounded-2xl p-6 max-w-md w-full relative"
            >
              <div className="flex flex-col items-center text-center">
                <div className="bg-rose-500/10 p-3 rounded-full mb-4">
                  <ShieldAlert className="w-8 h-8 text-rose-400" />
                </div>
                <h4 className="text-white font-bold text-lg mb-2">Invalid Domain Format</h4>
                <p className="text-slate-300 text-sm mb-6">{validationError}</p>
                <button 
                  onClick={() => {
                    setValidationError('');
                    setTimeout(() => urlInputRef.current?.focus(), 100);
                  }}
                  className="bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2.5 px-6 rounded-xl transition-all w-full"
                >
                  Got it
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

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
              className="flex flex-col items-center justify-center text-center px-4 max-w-4xl mx-auto mt-20"
            >
              {/* 1. Hero Headline */}
              <div className="space-y-4">
                <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 via-purple-400 to-emerald-400">
                  IS YOUR WEBSITE SAFE?
                </h1>
                <p className="text-2xl font-semibold text-slate-300 max-w-2xl mx-auto tracking-wide">
                  FIND OUT IN ONE CLICK.
                </p>
              </div>

              <div className="mt-8 w-full">
                <BottomTicker />
              </div>

              {/* 3. Input Bar Container */}
              <form onSubmit={handleScan} className="w-full max-w-2xl mt-8 flex flex-col items-center gap-3">
                {/* Input Box with Glow focused ONLY on the box */}
                <div className="relative w-full rounded-2xl p-1 bg-slate-900/80 border border-slate-700/60 shadow-[0_0_30px_rgba(124,58,237,0.25)] flex items-center">
                  <Search className="w-5 h-5 text-slate-400 ml-4 shrink-0 hidden sm:block" />
                  <input
                    ref={urlInputRef}
                    type="text"
                    required
                    placeholder="example.com"
                    value={url}
                    onChange={(e) => {
                      setUrl(e.target.value);
                      if (validationError) setValidationError('');
                    }}
                    className="w-full bg-transparent px-4 py-3 text-slate-100 placeholder-slate-500 focus:outline-none"
                  />
                  <button type="submit" className="bg-indigo-600 hover:bg-indigo-500 text-white font-medium px-6 py-2.5 rounded-xl transition-all flex items-center gap-2 shrink-0">
                    Scan <ArrowRight className="w-4 h-4" />
                  </button>
                </div>

                {/* 4. Trust Badge Outside the Glow Box (Crisp Contrast) */}
                <div className="flex items-center gap-2 text-xs text-slate-400 mt-2 font-medium">
                  <span className="text-indigo-400">🔒</span>
                  <span><strong className="text-slate-300">100% Safe & Non-Intrusive</strong> • No invasive payloads, exploits, or database risks.</span>
                </div>
              </form>

              <div className="flex justify-center text-sm text-slate-400 mt-8 font-medium">
                <div className="flex items-center gap-2">Interested in advanced testing? Let's chat on WhatsApp!</div>
              </div>
              
              <div className="w-full mt-12 pb-16">
                <SafetyComparison />
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
              Target Domain: {url} | Date: {new Date(reportData.scan_start || Date.now()).toLocaleString()} | Overall Security Score: {reportData.score}/100
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
