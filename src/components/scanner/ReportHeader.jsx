import React from 'react';
import { Globe, Download, Bookmark, Share2 } from 'lucide-react';

const ReportHeader = ({ url, score, timestamp, activeMode, onToggleMode, onExportPdf, onRequireAuth }) => {
  return (
    <div className="bg-slate-900/90 backdrop-blur-md border border-slate-700/50 p-6 rounded-2xl shadow-xl flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 sticky top-20 z-40 mb-8">
      {/* Left: Info */}
      <div className="flex-1">
        <h2 className="text-2xl font-bold mb-1 text-white">Live Security Posture Report</h2>
        <div className="flex flex-wrap items-center gap-4 text-sm text-slate-400">
          <span className="flex items-center gap-2"><Globe className="w-4 h-4"/> {url}</span>
          <span className="opacity-50">•</span>
          <span>Scanned on {new Date(timestamp || Date.now()).toLocaleString()}</span>
        </div>
      </div>

      {/* Middle: Mode Toggle */}
      <div className="flex bg-slate-950 p-1 rounded-xl border border-slate-800 print:hidden">
        <button
          onClick={() => onToggleMode('simple')}
          className={`px-6 py-2 rounded-lg text-sm font-bold transition-all ${
            activeMode === 'simple' 
              ? 'bg-emerald-500/20 text-emerald-400 shadow' 
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
          }`}
        >
          Simple
        </button>
        <button
          onClick={() => onToggleMode('technical')}
          className={`px-6 py-2 rounded-lg text-sm font-bold transition-all ${
            activeMode === 'technical' 
              ? 'bg-blue-500/20 text-blue-400 shadow' 
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
          }`}
        >
          Technical
        </button>
      </div>

      {/* Right: Actions & Score */}
      <div className="flex items-center gap-4 w-full lg:w-auto justify-between lg:justify-end">
        <div className="flex gap-2 print:hidden">
          <button 
            onClick={onExportPdf}
            title="Export PDF"
            className="p-2.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors border border-slate-700"
          >
            <Download className="w-4 h-4" />
          </button>
          <button 
            onClick={() => onRequireAuth('save reports to your dashboard')}
            title="Save to Dashboard"
            className="p-2.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors border border-slate-700"
          >
            <Bookmark className="w-4 h-4" />
          </button>
          <button 
            onClick={() => onRequireAuth('share public links')}
            title="Share Public Link"
            className="p-2.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors border border-slate-700"
          >
            <Share2 className="w-4 h-4" />
          </button>
        </div>

        <div className={`flex items-center gap-2.5 px-4 py-2.5 bg-slate-900/90 border rounded-xl backdrop-blur-md shadow-lg ${
          score >= 90 
            ? 'border-emerald-500/30' 
            : score >= 70
              ? 'border-amber-500/30'
              : 'border-red-500/30'
        }`}>
          <div className="flex flex-col text-right">
            <span className="text-[10px] font-bold font-mono tracking-wider text-slate-400 uppercase">SCORE</span>
            <span className={`text-xl font-extrabold font-mono leading-none ${
               score >= 90 ? 'text-emerald-400' : score >= 70 ? 'text-amber-400' : 'text-red-400'
            }`}>{score}<span className="text-sm font-normal text-slate-400">/100</span></span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReportHeader;
