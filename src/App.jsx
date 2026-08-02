import { useState, useEffect } from 'react';
import { Search, Shield, ShieldAlert, ShieldCheck, ArrowRight, Loader2, Lock, Globe, Server, Activity, Download } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import html2canvas from 'html2canvas';
import { jsPDF } from 'jspdf';
import { Analytics } from '@vercel/analytics/react';

function App() {
  const [url, setUrl] = useState('');
  const [scanState, setScanState] = useState('idle'); // idle, scanning, complete
  const [scanProgress, setScanProgress] = useState(0);

  useEffect(() => {
    let interval;
    if (scanState === 'scanning') {
      interval = setInterval(() => {
        setScanProgress((prev) => {
          if (prev >= 100) {
            clearInterval(interval);
            setScanState('complete');
            return 100;
          }
          return prev + (100 / 30); // 30 seconds to reach 100% (called every second)
        });
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [scanState]);

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url) return;
    setScanState('scanning');
    setScanProgress(0);

    try {
      // Call our local mock backend
      const response = await fetch('http://localhost:3001/api/scans', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ target: url }),
      });
      
      const data = await response.json();
      console.log('Backend response:', data);
      
      // In a real application, we would poll the backend for status updates
      // using the returned data.jobId instead of simulating the timer.
      // For now, the simulation continues in the useEffect.
    } catch (error) {
      console.error('Failed to connect to backend:', error);
      // Fallback to simulation if backend is not running
    }
  };

  const resetScan = () => {
    setScanState('idle');
    setUrl('');
    setScanProgress(0);
  };

  const handleDownloadPdf = async () => {
    const element = document.getElementById('report-container');
    if (!element) return;
    
    try {
      const canvas = await html2canvas(element, { scale: 2, backgroundColor: '#020617' });
      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF('p', 'mm', 'a4');
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = (canvas.height * pdfWidth) / canvas.width;
      
      pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
      pdf.save('secure-ai-report.pdf');
    } catch (err) {
      console.error('Failed to generate PDF', err);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50 font-sans selection:bg-indigo-500/30">
      <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 pointer-events-none mix-blend-overlay"></div>
      
      {/* Navbar */}
      <nav className="border-b border-white/10 bg-white/5 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2 cursor-pointer" onClick={resetScan}>
            <div className="bg-indigo-500 p-2 rounded-lg">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <span className="text-xl font-bold tracking-tight">Secure-AI</span>
          </div>
          <div className="flex items-center gap-4">
            <button className="text-sm text-slate-300 hover:text-white transition-colors">Documentation</button>
            <button className="text-sm bg-white/10 hover:bg-white/20 px-4 py-2 rounded-full transition-all border border-white/5">Sign In</button>
          </div>
        </div>
      </nav>

      <main className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-32 relative z-10">
        
        <AnimatePresence mode="wait">
          {scanState === 'idle' && (
            <motion.div 
              key="idle"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="text-center space-y-8 mt-20"
            >
              <div className="space-y-4">
                <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 via-purple-400 to-emerald-400">
                  Analyze Any Endpoint.
                </h1>
                <p className="text-xl text-slate-400 max-w-2xl mx-auto">
                  Instant vulnerability scanning powered by AI. Enter your domain below to receive a comprehensive security posture report in seconds.
                </p>
              </div>

              <form onSubmit={handleScan} className="max-w-2xl mx-auto relative group">
                <div className="absolute -inset-1 bg-gradient-to-r from-indigo-500 to-purple-500 rounded-2xl blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200"></div>
                <div className="relative flex items-center bg-slate-900 border border-slate-700 rounded-2xl p-2 shadow-2xl focus-within:border-indigo-500 focus-within:ring-1 focus-within:ring-indigo-500 transition-all">
                  <Search className="w-6 h-6 text-slate-400 ml-4 hidden sm:block" />
                  <input
                    type="url"
                    required
                    placeholder="https://example.com"
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

              <div className="flex justify-center gap-8 text-sm text-slate-500 pt-8">
                <div className="flex items-center gap-2"><Lock className="w-4 h-4"/> SSL Verification</div>
                <div className="flex items-center gap-2"><Globe className="w-4 h-4"/> DNS Analysis</div>
                <div className="flex items-center gap-2"><Server className="w-4 h-4"/> Port Discovery</div>
              </div>
            </motion.div>
          )}

          {scanState === 'scanning' && (
            <motion.div
              key="scanning"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 1.05 }}
              className="max-w-2xl mx-auto mt-20 p-8 rounded-3xl bg-slate-900/50 border border-slate-800 backdrop-blur-xl shadow-2xl"
            >
              <div className="flex flex-col items-center justify-center space-y-8 py-12">
                <div className="relative">
                  <div className="absolute inset-0 border-4 border-indigo-500/20 rounded-full blur-md animate-pulse"></div>
                  <Loader2 className="w-20 h-20 text-indigo-400 animate-spin relative z-10" />
                </div>
                
                <div className="space-y-2 text-center w-full">
                  <h2 className="text-2xl font-bold tracking-wide">Analyzing {new URL(url || 'https://example.com').hostname}...</h2>
                  <p className="text-slate-400">Running basic vulnerability heuristics and surface scans.</p>
                </div>

                <div className="w-full max-w-md bg-slate-800 rounded-full h-3 mb-4 overflow-hidden shadow-inner">
                  <motion.div 
                    className="bg-gradient-to-r from-indigo-500 to-purple-500 h-3 rounded-full" 
                    initial={{ width: 0 }}
                    animate={{ width: `${scanProgress}%` }}
                    transition={{ ease: "linear", duration: 1 }}
                  ></motion.div>
                </div>
                <div className="flex w-full max-w-md justify-between text-xs text-slate-500 font-mono uppercase">
                  <span>Phase 1/3: Reconnaissance</span>
                  <span>{Math.round(scanProgress)}%</span>
                </div>
              </div>
            </motion.div>
          )}

          {scanState === 'complete' && (
            <motion.div
              key="complete"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="max-w-3xl mx-auto space-y-8"
            >
              <div id="report-container" className="space-y-8 p-4 -m-4 rounded-3xl bg-slate-950">
                <div className="flex items-start justify-between bg-slate-900/80 border border-slate-700/50 p-6 rounded-2xl backdrop-blur-sm">
                <div>
                  <h2 className="text-2xl font-bold mb-1">Basic Security Report</h2>
                  <p className="text-slate-400 flex items-center gap-2">
                    <Globe className="w-4 h-4"/> {url}
                  </p>
                </div>
                <div className="px-4 py-2 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-lg flex items-center gap-2 font-medium">
                  <ShieldCheck className="w-5 h-5" /> Score: B+
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-slate-900/50 border border-slate-800 p-5 rounded-xl space-y-4">
                   <div className="flex items-center gap-3 text-emerald-400 mb-2">
                     <ShieldCheck className="w-6 h-6" />
                     <h3 className="font-semibold text-lg text-slate-200">Passed Checks</h3>
                   </div>
                   <ul className="space-y-3 text-sm text-slate-300">
                     <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 bg-emerald-500 rounded-full"></div> Valid SSL/TLS Certificate (RSA 2048)</li>
                     <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 bg-emerald-500 rounded-full"></div> Strict-Transport-Security Header</li>
                     <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 bg-emerald-500 rounded-full"></div> No Open Directory Listings</li>
                   </ul>
                </div>
                
                <div className="bg-slate-900/50 border border-slate-800 p-5 rounded-xl space-y-4">
                   <div className="flex items-center gap-3 text-amber-400 mb-2">
                     <ShieldAlert className="w-6 h-6" />
                     <h3 className="font-semibold text-lg text-slate-200">Warnings</h3>
                   </div>
                   <ul className="space-y-3 text-sm text-slate-300">
                     <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 bg-amber-500 rounded-full"></div> Missing Content-Security-Policy</li>
                     <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 bg-amber-500 rounded-full"></div> Server Version Exposed in Headers</li>
                     <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 bg-amber-500 rounded-full"></div> Subdomain Takeover Risk (Low)</li>
                   </ul>
                </div>
              </div>

              <div className="mt-12 bg-gradient-to-br from-indigo-900/40 to-purple-900/40 border border-indigo-500/30 p-8 rounded-3xl relative overflow-hidden">
                <div className="absolute -right-20 -top-20 w-64 h-64 bg-indigo-500/20 blur-3xl rounded-full"></div>
                <div className="relative z-10 flex flex-col md:flex-row items-center justify-between gap-6">
                  <div className="space-y-2">
                    <h3 className="text-2xl font-bold text-white flex items-center gap-2">
                      <Activity className="w-6 h-6 text-indigo-400" />
                      Advanced Architecture Testing
                    </h3>
                    <p className="text-indigo-200/80 max-w-lg">
                      Ready for a deep dive? Initiate comprehensive penetration testing using our advanced distributed architecture. This covers OWASP Top 10, business logic flaws, and zero-day heuristic analysis.
                    </p>
                  </div>
                  <button className="whitespace-nowrap bg-white text-indigo-950 hover:bg-indigo-50 px-8 py-4 rounded-xl font-bold shadow-lg shadow-white/10 transition-all transform hover:scale-105">
                    Start Advanced Test
                  </button>
                </div>
              </div>
              </div>

              <div className="pt-4 flex justify-center gap-6">
                 <button onClick={handleDownloadPdf} className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-white px-6 py-3 rounded-xl transition-all">
                   <Download className="w-4 h-4" /> Download PDF
                 </button>
                 <button onClick={resetScan} className="text-slate-400 hover:text-white transition-colors underline underline-offset-4 flex items-center">
                   Scan another URL
                 </button>
              </div>

            </motion.div>
          )}
        </AnimatePresence>

      </main>
      <Analytics />
    </div>
  );
}

export default App;
