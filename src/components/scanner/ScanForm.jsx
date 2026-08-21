import React, { useState, useRef } from 'react';
import { Search, ArrowRight, ShieldAlert } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const ScanForm = ({ onScan }) => {
  const [url, setUrl] = useState('');
  const [scanMode, setScanMode] = useState('passive');
  const [reportMode, setReportMode] = useState('simple');
  const [validationError, setValidationError] = useState('');
  const urlInputRef = useRef(null);

  const handleSubmit = (e) => {
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

    setValidationError('');
    if (onScan) {
      onScan(parsedUrl, scanMode, reportMode);
    }
  };

  return (
    <>
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
                <h4 className="text-slate-50 font-bold text-lg mb-2">Invalid Domain Format</h4>
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

      <form onSubmit={handleSubmit} className="w-full max-w-2xl mt-4 flex flex-col items-center gap-3">
        <div className="scan-url-shell relative w-full rounded-2xl p-1 bg-slate-900/80 border border-slate-700/60 shadow-[0_0_30px_rgba(124,58,237,0.25)] flex items-center focus-within:border-indigo-500 focus-within:ring-1 focus-within:ring-indigo-500 focus-within:shadow-[0_0_40px_rgba(124,58,237,0.4)] transition-all duration-300">
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
            className="scan-url-input w-full bg-transparent px-4 py-3 text-slate-100 placeholder-slate-500 focus:outline-none"
          />
          <button type="submit" className="bg-indigo-600 hover:bg-indigo-500 text-white font-medium px-6 py-2.5 rounded-xl transition-all flex items-center gap-2 shrink-0">
            Scan <ArrowRight className="w-4 h-4" />
          </button>
        </div>

        <div className="flex flex-col sm:flex-row gap-4 w-full mt-4 text-left">
          <div className="scan-config-card flex-1 bg-slate-900/60 p-4 rounded-xl border border-slate-700/50 hover:bg-slate-900/80 transition-colors">
            <h2 className="text-xs font-bold text-slate-400 mb-2.5 tracking-widest uppercase">Scan Configuration</h2>
            <div className="flex flex-col gap-1.5">
              <label className={`scan-option flex items-center gap-3 cursor-pointer px-3 py-2 rounded-lg border transition-all ${scanMode === 'passive' ? 'scan-option-selected bg-indigo-500/10 border-indigo-500/30' : 'bg-transparent border-transparent hover:bg-slate-800/50'}`}>
                <input type="radio" name="scanMode" value="passive" checked={scanMode === 'passive'} onChange={(e) => setScanMode(e.target.value)} className="w-4 h-4 text-indigo-500 bg-slate-800 border-slate-600 focus:ring-indigo-500 focus:ring-offset-slate-900 transition-colors cursor-pointer" />
                <span className={`text-sm font-medium transition-colors ${scanMode === 'passive' ? 'text-indigo-300' : 'text-slate-400'}`}>Basic Scan</span>
              </label>
              <label className={`scan-option flex items-center gap-3 cursor-pointer px-3 py-2 rounded-lg border transition-all ${scanMode === 'active' ? 'scan-option-selected bg-indigo-500/10 border-indigo-500/30' : 'bg-transparent border-transparent hover:bg-slate-800/50'}`}>
                <input type="radio" name="scanMode" value="active" checked={scanMode === 'active'} onChange={(e) => setScanMode(e.target.value)} className="w-4 h-4 text-indigo-500 bg-slate-800 border-slate-600 focus:ring-indigo-500 focus:ring-offset-slate-900 transition-colors cursor-pointer" />
                <span className={`text-sm font-medium transition-colors ${scanMode === 'active' ? 'text-indigo-300' : 'text-slate-400'}`}>Advanced Scan</span>
              </label>
            </div>
          </div>

          <div className="scan-config-card flex-1 bg-slate-900/60 p-4 rounded-xl border border-slate-700/50 hover:bg-slate-900/80 transition-colors">
            <h2 className="text-xs font-bold text-slate-400 mb-2.5 tracking-widest uppercase">Report Style</h2>
            <div className="flex flex-col gap-1.5">
              <label className={`scan-option flex items-center gap-3 cursor-pointer px-3 py-2 rounded-lg border transition-all ${reportMode === 'simple' ? 'scan-option-selected bg-indigo-500/10 border-indigo-500/30' : 'bg-transparent border-transparent hover:bg-slate-800/50'}`}>
                <input type="radio" name="reportMode" value="simple" checked={reportMode === 'simple'} onChange={(e) => setReportMode(e.target.value)} className="w-4 h-4 text-indigo-500 bg-slate-800 border-slate-600 focus:ring-indigo-500 focus:ring-offset-slate-900 transition-colors cursor-pointer" />
                <span className={`text-sm font-medium transition-colors ${reportMode === 'simple' ? 'text-indigo-300' : 'text-slate-400'}`}>Simple</span>
              </label>
              <label className={`scan-option flex items-center gap-3 cursor-pointer px-3 py-2 rounded-lg border transition-all ${reportMode === 'technical' ? 'scan-option-selected bg-indigo-500/10 border-indigo-500/30' : 'bg-transparent border-transparent hover:bg-slate-800/50'}`}>
                <input type="radio" name="reportMode" value="technical" checked={reportMode === 'technical'} onChange={(e) => setReportMode(e.target.value)} className="w-4 h-4 text-indigo-500 bg-slate-800 border-slate-600 focus:ring-indigo-500 focus:ring-offset-slate-900 transition-colors cursor-pointer" />
                <span className={`text-sm font-medium transition-colors ${reportMode === 'technical' ? 'text-indigo-300' : 'text-slate-400'}`}>Technical</span>
              </label>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-center flex-wrap gap-1 text-center text-xs text-slate-400 mt-2 font-medium px-2">
          <span className="text-indigo-400">🔒</span>
          <span><strong className="text-slate-300">Passive Mode — Non-Intrusive</strong> • Read-only security checks designed to minimize impact on live websites.</span>
        </div>
      </form>
    </>
  );
};

export default ScanForm;
