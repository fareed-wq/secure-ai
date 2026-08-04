import { useState } from 'react';
import { Search, ArrowRight, Loader2, ShieldAlert } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import html2canvas from 'html2canvas';
import { jsPDF } from 'jspdf';
import { Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import WhatsAppWidget from '../WhatsAppWidget';

import ModeSelection from '../components/scanner/ModeSelection';
import ReportHeader from '../components/scanner/ReportHeader';
import SimpleReport from '../components/scanner/SimpleReport';
import TechnicalReport from '../components/scanner/TechnicalReport';
import AuthModal from '../components/scanner/AuthModal';

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
    // We target the report-content div which wraps either Simple or Technical report
    const element = document.getElementById('report-content');
    if (!element) return;
    
    try {
      const canvas = await html2canvas(element, { scale: 2, useCORS: true, logging: false, backgroundColor: '#020617' });
      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF('p', 'mm', 'a4');
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = (canvas.height * pdfWidth) / canvas.width;
      
      pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
      pdf.save(`secure-ai-${reportMode}-report-${url}.pdf`);
    } catch (err) {
      console.error('Failed to generate PDF', err);
      alert("Failed to generate PDF. Please try again.");
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 font-sans text-slate-50 selection:bg-indigo-500/30">
      <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 pointer-events-none mix-blend-overlay"></div>
      
      {/* Top Navbar */}
      <nav className="border-b border-white/10 bg-white/5 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center cursor-pointer" onClick={resetScan}>
            <img src="/logo-v6.png?v=7" alt="Secure-AI Logo" className="h-12 w-auto object-contain" />
          </div>
          <div className="flex items-center gap-4">
            {user ? (
              <Link to="/dashboard" className="text-sm font-bold text-slate-300 hover:text-white bg-slate-800/50 hover:bg-slate-800 px-4 py-2 rounded-lg transition-colors">
                Go to Dashboard
              </Link>
            ) : (
              <>
                <Link to="/login" className="text-sm font-bold text-slate-300 hover:text-white transition-colors hidden sm:block">
                  Log in
                </Link>
                <Link to="/register" className="text-sm font-bold bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg transition-colors">
                  Sign up free
                </Link>
              </>
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
      <div className="relative z-10 max-w-7xl mx-auto pb-32">
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
                url={reportData.url}
                score={reportData.score}
                grade={reportData.grade}
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
      
      {/* Floating Elements (e.g. WhatsApp Widget) preserved for UX */}
      <WhatsAppWidget />
    </div>
  );
}

export default Scanner;
