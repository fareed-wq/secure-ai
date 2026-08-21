import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Loader2, ShieldAlert } from 'lucide-react';
import SimpleReport from '../components/scanner/SimpleReport';
import TechnicalReport from '../components/scanner/TechnicalReport';

const SharedReport = () => {
  const { token } = useParams();
  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [reportMode, setReportMode] = useState('simple');

  useEffect(() => {
    const fetchSharedReport = async () => {
      try {
        const res = await fetch(`/api/share/${token}`);
        const data = await res.json();
        
        if (!res.ok) {
          throw new Error(data.error || 'Share link unavailable');
        }
        
        setReportData(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    
    fetchSharedReport();
  }, [token]);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center p-4">
        <Loader2 className="w-12 h-12 text-indigo-500 animate-spin mb-4" />
        <p className="text-slate-400">Loading shared report...</p>
      </div>
    );
  }

  if (error || !reportData) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center p-4">
        <div className="max-w-md w-full bg-slate-900 border border-slate-800 rounded-3xl p-8 text-center shadow-2xl">
          <ShieldAlert className="w-16 h-16 text-rose-500 mx-auto mb-6" />
          <h2 className="text-2xl font-bold text-slate-50 mb-4">Report Unavailable</h2>
          <p className="text-slate-400 mb-8">{error || 'This share link is invalid, expired, or has been revoked by the owner.'}</p>
          <Link to="/" className="inline-flex items-center justify-center bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-3 px-8 rounded-xl transition-all">
            Run a New Scan
          </Link>
        </div>
      </div>
    );
  }

  const { target_url, score, report_data, created_at } = reportData;
  const findings = report_data?.findings || [];
  const isWafBlocked = findings.length === 1 && findings[0]?.name?.includes('WAF');

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50 font-sans selection:bg-indigo-500/30 overflow-x-hidden">
      {/* Minimal Header */}
      <header className="bg-slate-900/50 backdrop-blur-md border-b border-slate-800/50 sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3 group">
            <div className="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center shadow-lg shadow-indigo-500/20 group-hover:bg-indigo-500 transition-colors">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <span className="font-bold text-lg tracking-tight text-slate-100 group-hover:text-white transition-colors">
              Secure-AI
            </span>
            <span className="bg-indigo-500/20 text-indigo-400 text-[10px] font-bold px-2 py-0.5 rounded uppercase tracking-wider hidden sm:block">
              Shared Report
            </span>
          </Link>
          <Link to="/register" className="text-sm font-medium text-slate-300 hover:text-white transition-colors">
            Create Free Account
          </Link>
        </div>
      </header>

      <main className="max-w-6xl mx-auto p-4 sm:p-6 lg:p-8 pt-8 lg:pt-12">
        {/* Report Header (Read Only) */}
        <div className="relative z-40 bg-slate-900/90 backdrop-blur-md border border-slate-700/50 p-6 rounded-2xl shadow-xl flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 mb-8">
          <div className="flex-1">
            <h2 className="text-2xl font-bold mb-1 text-slate-50">Security Posture Report</h2>
            <div className="flex flex-wrap items-center gap-4 text-sm text-slate-400">
              <span>{target_url}</span>
              <span className="opacity-50">?</span>
              <span>Scanned on {new Date(created_at).toLocaleString()}</span>
            </div>
          </div>
          
          <div className="flex bg-slate-950 p-1 rounded-xl border border-slate-800">
            <button
              onClick={() => setReportMode('simple')}
              className={`px-6 py-2 rounded-lg text-sm font-bold transition-all ${
                reportMode === 'simple'
                  ? 'bg-emerald-500/20 text-emerald-400 shadow'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              Simple
            </button>
            <button
              onClick={() => setReportMode('technical')}
              className={`px-6 py-2 rounded-lg text-sm font-bold transition-all ${
                reportMode === 'technical'
                  ? 'bg-blue-500/20 text-blue-400 shadow'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              Technical
            </button>
          </div>

          <div className={`flex items-center gap-2.5 px-4 py-2.5 bg-slate-900/90 border rounded-xl backdrop-blur-md shadow-lg ${
            isWafBlocked
              ? 'border-slate-500/30'
              : score >= 90 ? 'border-emerald-500/30'
              : score >= 80 ? 'border-teal-500/30'
              : score >= 70 ? 'border-amber-500/30'
              : score >= 60 ? 'border-orange-500/30'
              : 'border-rose-500/30'
          }`}>
            <div className="flex flex-col text-right">
              <span className="text-[10px] font-bold font-mono tracking-wider text-slate-400 uppercase">SCORE</span>
              {isWafBlocked ? (
                <span className="text-xl font-extrabold font-mono leading-none text-slate-400">N/A</span>
              ) : (
                <span className={`text-xl font-extrabold font-mono leading-none ${
                   score >= 90 ? 'text-emerald-400' :
                   score >= 80 ? 'text-teal-400' :
                   score >= 70 ? 'text-amber-400' :
                   score >= 60 ? 'text-orange-400' : 'text-rose-400'
                }`}>{score}<span className="text-sm font-normal text-slate-400">/100</span></span>
              )}
            </div>
          </div>
        </div>

        {/* Content */}
        {reportMode === 'simple' ? (
          <SimpleReport reportData={report_data} />
        ) : (
          <TechnicalReport reportData={report_data} />
        )}
      </main>
      
      {/* Minimal Footer */}
      <footer className="mt-20 py-8 border-t border-slate-800/50 text-center">
        <p className="text-slate-500 text-sm">
          Want to scan your own infrastructure? <Link to="/" className="text-indigo-400 hover:text-indigo-300">Run a free scan</Link>.
        </p>
      </footer>
    </div>
  );
};

export default SharedReport;
