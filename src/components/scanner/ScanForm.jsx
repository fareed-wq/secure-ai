import React, { useState, useRef } from 'react';
import { Search, ArrowRight, ShieldAlert, Lock, AlertCircle } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';

const ScanForm = ({ onScan, quotaInfo, user }) => {
  const [url, setUrl] = useState('');
  const [scanMode, setScanMode] = useState('passive');
  const [reportMode, setReportMode] = useState('simple');
  const [validationError, setValidationError] = useState('');
  const urlInputRef = useRef(null);

  const isGuest = !user;
  const { isAdmin } = useAuth();
  const quotaReached = !isAdmin && quotaInfo?.quota?.quota_remaining <= 0;
  const quotaUsed = quotaInfo?.quota?.quota_used || 0;
  const quotaLimit = quotaInfo?.quota?.quota_limit || (isGuest ? 3 : 5);
  const quotaRemaining = quotaInfo?.quota?.quota_remaining || 0;
  const plan = quotaInfo?.plan || (isGuest ? 'guest' : 'free');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!url) return;
    
    if (quotaReached) {
      if (isGuest) {
        setValidationError("You've used your 3 free Guest scans for this week.");
      } else {
        setValidationError("You've used your 5 free scans for this week.");
      }
      return;
    }

    if (isGuest && scanMode === 'active') {
      setValidationError("Advanced scanning is available for signed-in users only.");
      return;
    }

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
                <h4 className="text-slate-50 font-bold text-lg mb-2">Scan Blocked</h4>
                <p className="text-slate-300 text-sm mb-6">{validationError}</p>
                
                {quotaReached && !isGuest && validationError.includes('5 free scans') ? (
                    <>
                      <p className="text-slate-400 text-sm mb-6">You have reached your weekly limit. Upgrade to Professional for unlimited scans.</p>
                      <button onClick={() => setValidationError('')} className="bg-slate-800 hover:bg-slate-700 text-white font-medium py-2.5 px-6 rounded-xl transition-all w-full mb-3">Close</button>
                    </>
                  ) : (
                    <button onClick={() => setValidationError('')} className="bg-slate-800 hover:bg-slate-700 text-white font-medium py-2.5 px-6 rounded-xl transition-all w-full">Close</button>
                  )}
                </div>
              </motion.div>
          </div>
        )}
      </AnimatePresence>

      <form onSubmit={handleSubmit} className="w-full max-w-2xl mt-4 flex flex-col items-center gap-3">
        {isAdmin && (
          <div className="flex items-center gap-2 text-xs font-medium px-3 py-1.5 rounded-full bg-slate-900 border border-emerald-500/30 mt-1">
            <ShieldAlert className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-slate-300">
              Admin Access (Unlimited scan quota)
            </span>
          </div>
        )}
        {quotaInfo && !isAdmin && (plan === 'guest' || plan === 'free') && (
          <div className="flex items-center gap-2 text-xs font-medium px-3 py-1.5 rounded-full bg-slate-900 border border-slate-700/50 mt-1">
            <AlertCircle className={`w-3.5 h-3.5 ${quotaReached ? 'text-rose-400' : 'text-indigo-400'}`} />
            <span className="text-slate-300">
              {plan === 'guest' ? 'Guest Quota: ' : 'Free Quota: '}
              {quotaUsed}/{quotaLimit} used, {quotaRemaining} remaining.
              {quotaReached && ' weekly limit reached.'}
            </span>
            <span className="text-slate-500 border-l border-slate-700 pl-2 ml-1">Resets Monday</span>
          </div>
        )}

        <div className="scan-url-shell relative w-full rounded-2xl p-1 bg-slate-900/80 border border-slate-700/60 shadow-[0_0_30px_rgba(124,58,237,0.25)] flex items-center focus-within:border-indigo-500 focus-within:ring-1 focus-within:ring-indigo-500 focus-within:shadow-[0_0_40px_rgba(124,58,237,0.4)] transition-all duration-300">
          <Search className="w-5 h-5 text-slate-400 ml-4 shrink-0 hidden sm:block" />
          <input
            ref={urlInputRef}
            type="text"
            required
            placeholder="example.com"
            value={url}
            disabled={quotaReached}
            onChange={(e) => {
              setUrl(e.target.value);
              if (validationError) setValidationError('');
            }}
            className="scan-url-input w-full bg-transparent px-4 py-3 text-slate-100 placeholder-slate-500 focus:outline-none disabled:opacity-50"
          />
          <button type="submit" disabled={quotaReached} className="bg-indigo-600 hover:bg-indigo-500 text-white font-medium px-6 py-2.5 rounded-xl transition-all flex items-center gap-2 shrink-0 disabled:opacity-50 disabled:cursor-not-allowed">
            Scan <ArrowRight className="w-4 h-4" />
          </button>
        </div>

        <div className="flex items-center justify-center flex-wrap gap-1 text-center text-xs text-slate-400 mt-2 font-medium px-2">
          <span className="text-indigo-400">🔒</span>
          <span><strong className="text-slate-300">Passive Mode & Non-Intrusive</strong> • Read-only security checks designed to minimize impact on live websites.</span>
        </div>

        <div className="flex flex-col sm:flex-row gap-4 w-full mt-4 text-left">
          <div className="scan-config-card flex-1 bg-slate-900/60 p-4 rounded-xl border border-slate-700/50 hover:bg-slate-900/80 transition-colors relative overflow-hidden">
            <h2 className="text-xs font-bold text-slate-400 mb-2.5 tracking-widest uppercase">Scan Configuration</h2>
            <div className="flex flex-col gap-1.5 relative z-10">
              <label className={`scan-option flex items-center gap-3 cursor-pointer px-3 py-2 rounded-lg border transition-all ${scanMode === 'passive' ? 'scan-option-selected bg-indigo-500/10 border-indigo-500/30' : 'bg-transparent border-transparent hover:bg-slate-800/50'}`}>
                <input type="radio" name="scanMode" value="passive" checked={scanMode === 'passive'} onChange={(e) => setScanMode(e.target.value)} className="w-4 h-4 text-indigo-500 bg-slate-800 border-slate-600 focus:ring-indigo-500 focus:ring-offset-slate-900 transition-colors cursor-pointer" />
                <span className={`text-sm font-medium transition-colors ${scanMode === 'passive' ? 'text-indigo-300' : 'text-slate-400'}`}>Basic Scan</span>
              </label>
              <label className={`scan-option flex items-center justify-between gap-3 cursor-pointer px-3 py-2 rounded-lg border transition-all ${scanMode === 'active' ? 'scan-option-selected bg-indigo-500/10 border-indigo-500/30' : 'bg-transparent border-transparent hover:bg-slate-800/50'} ${isGuest ? 'opacity-60 grayscale cursor-not-allowed' : ''}`} onClick={(e) => {
                if (isGuest) {
                  e.preventDefault();
                  setValidationError("Advanced scanning is available for signed-in users only.");
                }
              }}>
                <div className="flex items-center gap-3">
                  <input type="radio" name="scanMode" value="active" disabled={isGuest} checked={scanMode === 'active'} onChange={(e) => setScanMode(e.target.value)} className="w-4 h-4 text-indigo-500 bg-slate-800 border-slate-600 focus:ring-indigo-500 focus:ring-offset-slate-900 transition-colors cursor-pointer disabled:cursor-not-allowed" />
                  <span className={`text-sm font-medium transition-colors ${scanMode === 'active' ? 'text-indigo-300' : 'text-slate-400'}`}>Advanced Scan</span>
                </div>
                {isGuest && <Lock className="w-3.5 h-3.5 text-slate-500" />}
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

        

          {isGuest && (
            <div className={`w-full max-w-2xl bg-slate-900/90 border rounded-xl p-6 mt-4 text-center shadow-xl ${quotaReached ? 'border-rose-500/30' : 'border-indigo-500/20'}`}>
              {quotaReached && (
                <h3 className="text-rose-400 font-bold text-lg mb-2">You've used your 3 free Guest scans for this week.</h3>
              )}
              <p className="text-slate-300 text-sm mb-5 font-medium">Create a free account to unlock Advanced Scan, get 5 scans every week, download PDF reports, and access your scan history.</p>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                <Link to="/register" className="bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2.5 px-6 rounded-xl transition-all w-full sm:w-auto shadow-lg shadow-indigo-500/20">
                  Create Free Account
                </Link>
                <Link to="/login" className="bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold py-2.5 px-6 rounded-xl transition-all w-full sm:w-auto border border-slate-700">
                  Sign In
                </Link>
              </div>
            </div>
          )}

          
      </form>
    </>
  );
};

export default ScanForm;
