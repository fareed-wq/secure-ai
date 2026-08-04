import { useState } from 'react';
import { Search, Shield, ShieldAlert, ShieldCheck, ArrowRight, Loader2, Globe, Server, Download, Activity, Lock } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import html2canvas from 'html2canvas';
import { jsPDF } from 'jspdf';
import WhatsAppWidget from './WhatsAppWidget';

function App() {
  const [url, setUrl] = useState('');
  const [scanState, setScanState] = useState('idle'); // idle, scanning, complete, error
  const [reportData, setReportData] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');

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
      const minWait = new Promise(resolve => setTimeout(resolve, 10000));
      // By using a relative URL, Vercel will automatically route /api/scan to our Python serverless function.
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
      setScanState('complete');
    } catch (error) {
      console.error('Failed to connect to backend:', error);
      setErrorMessage('Failed to connect to the backend scanner. Ensure it is running on port 8000.');
      setScanState('error');
    }
  };

  const resetScan = () => {
    setScanState('idle');
    setUrl('');
    setReportData(null);
    setErrorMessage('');
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

  // Helper to categorize findings
  const getCategorizedFindings = () => {
    if (!reportData) return { passed: [], warnings: [] };
    
    const passed = [];
    const warnings = [];

    // Process SSL
    if (reportData.ssl_tls && reportData.ssl_tls.status === "OK") {
      passed.push(`Valid SSL/TLS Certificate (${reportData.ssl_tls.version})`);
      passed.push(`Issuer: ${reportData.ssl_tls.issuer?.organizationName || 'Unknown'}`);
    } else if (reportData.ssl_tls) {
      warnings.push(`SSL Error: ${reportData.ssl_tls.message}`);
    }

    // Process Headers
    reportData.header_findings?.forEach(finding => {
      if (finding.startsWith('Missing') || finding.includes('missing') || finding.startsWith('No ') || finding.startsWith('Error')) {
        warnings.push(finding);
      } else {
        passed.push(finding);
      }
    });

    return { passed, warnings };
  };

  const { passed, warnings } = getCategorizedFindings();

  // Calculate a basic letter score based on warnings
  const calculateScore = () => {
    if (!reportData) return 'N/A';
    const issues = reportData.potential_issues_count || 0;
    if (issues === 0) return 'A+';
    if (issues <= 2) return 'A';
    if (issues <= 4) return 'B';
    if (issues <= 6) return 'C';
    return 'D';
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50 font-sans selection:bg-indigo-500/30">
      <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 pointer-events-none mix-blend-overlay"></div>
      
      {/* Navbar */}
      <nav className="border-b border-white/10 bg-white/5 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center cursor-pointer" onClick={resetScan}>
            <img src="/logo.png" alt="Secure-AI Logo" className="h-12 w-auto object-contain drop-shadow-[0_0_8px_rgba(99,102,241,0.5)]" />
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
              <div className="space-y-6 overflow-hidden">
                <div className="space-y-4">
                  <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 via-purple-400 to-emerald-400">
                    IS YOUR WEBSITE SAFE?
                  </h1>
                  <p className="text-2xl font-semibold text-slate-300 max-w-2xl mx-auto tracking-wide">
                    FIND OUT IN ONE CLICK.
                  </p>
                </div>

                {/* Marquee Quotes */}
                <div className="relative flex overflow-x-hidden pt-4 pb-2" style={{ WebkitMaskImage: 'linear-gradient(to right, transparent, black 10%, black 90%, transparent)', maskImage: 'linear-gradient(to right, transparent, black 10%, black 90%, transparent)' }}>
                  <motion.div
                    className="flex whitespace-nowrap gap-12 items-center text-slate-400 italic text-sm md:text-base pr-12"
                    animate={{ x: ["0%", "-50%"] }}
                    transition={{
                      repeat: Infinity,
                      ease: "linear",
                      duration: 25,
                    }}
                  >
                    {[
                      "Paste your link below to catch hidden security flaws before they break your site.",
                      "Catch hidden website risks before they cause problems.",
                      "Enter your domain to uncover hidden security risks automatically.",
                      "Get a simple, easy-to-read safety report for your website instantly.",
                      "Paste your link below to catch hidden security flaws before they break your site.",
                      "Catch hidden website risks before they cause problems.",
                      "Enter your domain to uncover hidden security risks automatically.",
                      "Get a simple, easy-to-read safety report for your website instantly."
                    ].map((quote, idx) => (
                      <span key={idx} className="flex-shrink-0">
                        "{quote}"
                      </span>
                    ))}
                  </motion.div>
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
              
              <div className="flex justify-center text-sm text-slate-400 pt-8 font-medium">
                <div className="flex items-center gap-2">For more advance testing, contact by WhatsApp</div>
              </div>
            </motion.div>
          )}

          {scanState === 'scanning' && (
            <motion.div
              key="scanning"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 1.05 }}
              className="max-w-2xl mx-auto mt-20 p-8 rounded-3xl bg-slate-900/50 border border-slate-800 backdrop-blur-xl shadow-2xl overflow-hidden relative"
            >
              <div className="absolute inset-0 bg-slate-800/[0.2] bg-[size:20px_20px]" style={{backgroundImage: 'radial-gradient(circle, #334155 1px, transparent 1px)'}}></div>
              <div className="absolute inset-0 bg-gradient-to-t from-slate-950/80 to-transparent"></div>
              
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
                  
                  <div className="flex flex-col gap-3 max-w-sm mx-auto font-mono text-xs text-left">
                     <motion.div initial={{opacity:0}} animate={{opacity:1}} transition={{delay:0.5}} className="text-emerald-400 flex gap-2"><span>[+]</span> Resolved DNS and initiating connection...</motion.div>
                     <motion.div initial={{opacity:0}} animate={{opacity:1}} transition={{delay:2.5}} className="text-emerald-400 flex gap-2"><span>[+]</span> Evaluating SSL/TLS public certificate chain...</motion.div>
                     <motion.div initial={{opacity:0}} animate={{opacity:1}} transition={{delay:5.5}} className="text-indigo-400 flex gap-2"><span>[*]</span> Analyzing HTTP response security headers...</motion.div>
                     <motion.div initial={{opacity:0}} animate={{opacity:1}} transition={{delay:7.5}} className="text-purple-400 flex gap-2"><span>[*]</span> Aggregating passive heuristic data...</motion.div>
                     <motion.div initial={{opacity:0}} animate={{opacity:1}} transition={{delay:9.0}} className="text-emerald-400 flex gap-2"><span>[+]</span> Finalizing posture report...</motion.div>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

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

          {scanState === 'complete' && reportData && (
            <motion.div
              key="complete"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="max-w-4xl mx-auto space-y-8"
            >
              <div id="report-container" className="space-y-8 p-6 -m-6 rounded-3xl bg-slate-950">
                <div className="flex flex-col md:flex-row items-start md:items-center justify-between bg-slate-900/80 border border-slate-700/50 p-6 rounded-2xl backdrop-blur-sm gap-4">
                  <div>
                    <h2 className="text-2xl font-bold mb-1">Live Security Posture Report</h2>
                    <p className="text-slate-400 flex items-center gap-2">
                      <Globe className="w-4 h-4"/> {reportData.url}
                    </p>
                  </div>
                  <div className={`px-4 py-2 border rounded-lg flex items-center gap-2 font-medium ${calculateScore() === 'A+' || calculateScore() === 'A' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' : 'bg-amber-500/10 border-amber-500/20 text-amber-400'}`}>
                    <ShieldCheck className="w-5 h-5" /> Score: {calculateScore()}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-slate-900/50 border border-slate-800 p-5 rounded-xl space-y-4">
                     <div className="flex items-center gap-3 text-emerald-400 mb-2">
                       <ShieldCheck className="w-6 h-6" />
                       <h3 className="font-semibold text-lg text-slate-200">Passed Checks</h3>
                     </div>
                     <ul className="space-y-3 text-sm text-slate-300 break-words">
                       {passed.length > 0 ? passed.map((item, i) => (
                         <li key={i} className="flex items-start gap-2">
                           <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full mt-1.5 flex-shrink-0"></div> 
                           <span>{item}</span>
                         </li>
                       )) : (
                         <li className="text-slate-500 italic">No passed checks detected.</li>
                       )}
                     </ul>
                  </div>
                  
                  <div className="bg-slate-900/50 border border-slate-800 p-5 rounded-xl space-y-4">
                     <div className="flex items-center gap-3 text-amber-400 mb-2">
                       <ShieldAlert className="w-6 h-6" />
                       <h3 className="font-semibold text-lg text-slate-200">Warnings</h3>
                     </div>
                     <ul className="space-y-3 text-sm text-slate-300 break-words">
                        {warnings.length > 0 ? warnings.map((item, i) => (
                         <li key={i} className="flex items-start gap-2">
                           <div className="w-1.5 h-1.5 bg-amber-500 rounded-full mt-1.5 flex-shrink-0"></div> 
                           <span>{item}</span>
                         </li>
                       )) : (
                         <li className="text-emerald-500 italic">No warnings! Excellent posture.</li>
                       )}
                     </ul>
                  </div>
                </div>

              </div>

              <div className="pt-4 flex flex-wrap justify-center gap-4">
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
      <WhatsAppWidget />
    </div>
  );
}

export default App;
