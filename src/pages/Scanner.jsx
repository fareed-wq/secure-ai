import React, { useState, useEffect, useRef } from 'react';
import { Loader2, ShieldAlert, Lock } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { supabase } from '../lib/supabase';
import WhatsAppWidget from '../WhatsAppWidget';
import usePdfGenerator from '../hooks/usePdfGenerator';

import ScanForm from '../components/scanner/ScanForm';

import ReportHeader from '../components/scanner/ReportHeader';
const SimpleReport = React.lazy(() => import('../components/scanner/SimpleReport'));
const AuthModal = React.lazy(() => import('../components/scanner/AuthModal'));
import ErrorBoundary from '../components/ErrorBoundary';
import SafetyComparison from '../components/scanner/SafetyComparison';
import BottomTicker from '../components/scanner/BottomTicker';
const TechnicalReport = React.lazy(() => import('../components/scanner/TechnicalReport'));

import { scanApi } from '../lib/api/scanner';
import { useSEO } from '../hooks/useSEO';

function Scanner() {
  useSEO({
    title: 'Free Website Security Scanner',
    description: 'Check if your website is safe instantly. Uncover hidden security risks automatically with our passive security posture checker.',
    path: '/'
  });
  const { user } = useAuth();
  const location = useLocation();
  const [url, setUrl] = useState('');
  const [scanState, setScanState] = useState('idle'); // idle, scanning, error, mode-select, view-report
  const [reportData, setReportData] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');
  const [reportMode, setReportMode] = useState('simple'); // simple, technical
  const [executedScanMode, setExecutedScanMode] = useState('passive');
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authFeatureName, setAuthFeatureName] = useState('');
  const { isGeneratingPdf, generatePdf } = usePdfGenerator();
  const reportRef = useRef(null);
  const [quotaInfo, setQuotaInfo] = useState(null);

  const scrollToTop = () => {
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    document.getElementById('main-scroll-container')?.scrollTo({ top: 0, left: 0, behavior: 'instant' });
  };

  const fetchQuota = async () => {
    const q = await scanApi.getQuota();
    if (q) setQuotaInfo(q);
  };

  useEffect(() => {
    // Scroll to top on mount
    scrollToTop();
  }, []);

  // Fetch quota info
  useEffect(() => {
    fetchQuota();
  }, [user]);

  useEffect(() => {
    if (location.state?.resetScan) {
      setScanState('idle');
      setReportData(null);
      setUrl('');
      setErrorMessage('');
      scrollToTop();
      fetchQuota();
    }
  }, [location.state?.resetScan, user]);

  const handleRequireAuth = (featureName) => {
    if (!user) {
      setAuthFeatureName(featureName);
      setAuthModalOpen(true);
    } else {
      // Feature implementation for authenticated users
      alert(`${featureName} is fully implemented in the authenticated dashboard.`);
    }
  };

  const handleScan = async (parsedUrl, scanMode, reportModeValue) => {
    setUrl(parsedUrl);
    setScanState('scanning');
    setErrorMessage('');
    setReportMode(reportModeValue);
    setExecutedScanMode(scanMode);

    try {
      const data = await scanApi.runScan(parsedUrl, scanMode, reportModeValue);

      if (data.status === 'failed' || data.status === 'timeout') {
        setErrorMessage(data.error || "Unable to complete the security scan because the target could not be reached or the connection timed out.");
        setScanState('error');
        return;
      }

      setReportData(data);
      setScanState('view-report'); // Skip mode selection, go straight to report

      // Save scan to Supabase if user is logged in
      if (user) {
        // Run asynchronously so it doesn't block the UI
        supabase.from('scans').insert([{
          user_id: user.id,
          target_url: parsedUrl,
          score: data.score || 0,
          report_data: data
        }]).then(({ error }) => {
          if (error) console.error("Failed to save scan history:", error);
        });
      }
    } catch (error) {
      console.error('Backend Connection Error:', error);
      const msg = error.message || String(error);
      if (msg.includes("You've used your 3 free Basic scans")) {
        setErrorMessage(msg);
      } else {
        setErrorMessage(`Failed to connect to the backend scanner: ${msg}`);
      }
      scrollToTop();
      setScanState('error');
    } finally {
      if (!user) {
        fetchQuota();
      }
    }
  };

  const resetScan = () => {
    setScanState('idle');
    setUrl('');
    setReportData(null);
    setErrorMessage('');
    scrollToTop();
    if (!user) fetchQuota();
  };

  const handleSelectMode = (mode) => {
    setReportMode(mode);
    setScanState('view-report');
  };

  const handlePdfExport = () => {
    if (!user) {
      handleRequireAuth('download PDF reports');
      return;
    }
    generatePdf(reportData, executedScanMode, reportMode);
  };

  return (
    <div className="scanner-page scanner-wallpaper flow-root flex-1 bg-slate-950 font-sans text-slate-50 selection:bg-indigo-500/30">



      {/* Auth Modal */}
      <React.Suspense fallback={null}>
        <AuthModal
          isOpen={authModalOpen}
          onClose={() => setAuthModalOpen(false)}
          featureName={authFeatureName}
        />
      </React.Suspense>

      {/* Loading overlay for PDF generation */}
      <AnimatePresence>
        {isGeneratingPdf && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/80 backdrop-blur-sm"
          >
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 flex flex-col items-center max-w-sm w-full mx-4 text-center">
              <Loader2 className="w-12 h-12 text-indigo-500 animate-spin mb-4" />
              <h2 className="text-xl font-bold text-slate-50 mb-2">Generating PDF</h2>
              <p className="text-slate-400">Please wait while we prepare your report...</p>
            </div>
          </motion.div>
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

              <div className="mt-4 w-full">
                <BottomTicker />
              </div>

              {/* 3. Input Bar Container */}
              <ScanForm onScan={handleScan} quotaInfo={quotaInfo} user={user} />

              <div className="flex flex-col sm:flex-row items-center justify-center gap-4 text-sm text-slate-400 mt-8 font-medium">
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
          {scanState === 'error' && (() => {
            const isTlsError = errorMessage && (
              errorMessage.includes('SSLError') ||
              errorMessage.includes('SSL:') ||
              errorMessage.includes('TLSV1_ALERT') ||
              errorMessage.includes('certificate verify failed') ||
              errorMessage.includes('CERTIFICATE_VERIFY_FAILED')
            );

            return (
              <motion.div
                key="error"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 1.05 }}
                className="max-w-2xl mx-auto mt-20 p-8 rounded-3xl bg-red-900/20 border border-red-800 backdrop-blur-xl shadow-2xl text-center"
              >
                <ShieldAlert className="w-20 h-20 text-red-500 mx-auto mb-6" />

                {isTlsError ? (
                  <>
                    <h2 className="text-2xl font-bold text-red-400 mb-4 uppercase tracking-wider">SCAN INCOMPLETE</h2>
                    <p className="text-red-200 mb-4 font-medium">
                      We couldn't establish a secure HTTPS connection with the target website.<br/>
                      The target server terminated the TLS connection before the scan could begin.
                    </p>
                    <p className="text-red-300/80 mb-6 text-sm">
                      No security score was generated because the website could not be reached securely.
                    </p>
                    <details className="text-left mb-8 bg-red-950/50 p-4 rounded-lg border border-red-900/50">
                      <summary className="text-xs text-red-400/80 cursor-pointer hover:text-red-300 font-mono">View Technical Details</summary>
                      <pre className="mt-3 text-xs text-red-300 whitespace-pre-wrap font-mono break-all overflow-x-auto">{errorMessage}</pre>
                    </details>
                  </>
                ) : (
                  <>
                    <h2 className="text-2xl font-bold text-red-400 mb-4">Scan Incomplete</h2>
                    <p className="text-red-200 mb-8">{errorMessage}</p>
                    
                    {errorMessage && errorMessage.includes("You've used your 3 free Basic scans") && !user && (
                      <div className="mb-8">
                        <Link to="/register" className="bg-rose-500 hover:bg-rose-600 text-white font-medium px-6 py-3 rounded-xl transition-all inline-flex items-center gap-2 shadow-lg shadow-rose-500/20">
                          <Lock className="w-5 h-5" />
                          Create Free Account
                        </Link>
                        <p className="text-red-300/80 mt-3 text-sm">Sign up for a free account to unlock unlimited basic scans.</p>
                      </div>
                    )}
                  </>
                )}

                <button onClick={resetScan} className="bg-slate-800 hover:bg-slate-700 text-slate-50 px-6 py-3 rounded-xl transition-all">
                  Run Another Scan
                </button>
              </motion.div>
            );
          })()}

          {/* 5. VIEW REPORT STATE */}
          {scanState === 'view-report' && reportData && (
            <motion.div
              ref={reportRef}
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
                reportData={reportData}
              />

              <ErrorBoundary>
                <React.Suspense fallback={<div className="py-12 flex justify-center text-slate-500"><Loader2 className="animate-spin h-8 w-8" /></div>}>
                  {reportMode === 'simple' ? (
                    <SimpleReport reportData={reportData} />
                  ) : (
                    <TechnicalReport reportData={reportData} />
                  )}
                </React.Suspense>
              </ErrorBoundary>

              <div className="mt-12 flex justify-center">
                <button onClick={resetScan} className="text-slate-400 hover:text-slate-50 transition-colors underline underline-offset-4">
                  Run another scan
                </button>
              </div>
            </motion.div>
          )}

        </AnimatePresence>
      </div>



      {/* Floating Elements (e.g. WhatsApp Widget) preserved for UX */}
      <div className="print:hidden">
        <WhatsAppWidget />
      </div>
    </div>
  );
}

export default Scanner;
