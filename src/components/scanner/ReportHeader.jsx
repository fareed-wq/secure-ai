import React from 'react';
import { Globe, Download, Bookmark, Share2 } from 'lucide-react';

const ReportHeader = ({ url, score, grade, timestamp, activeMode, onToggleMode, onExportPdf }) => {
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
      <div className="flex bg-slate-950 p-1 rounded-xl border border-slate-800">
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
        <div className="flex gap-2">
          <button 
            onClick={onExportPdf}
            title="Export PDF"
            className="p-2.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors border border-slate-700"
          >
            <Download className="w-4 h-4" />
          </button>
          <button 
            title="Save to Dashboard"
            className="p-2.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors border border-slate-700"
          >
            <Bookmark className="w-4 h-4" />
          </button>
          <button 
            title="Share Public Link"
            className="p-2.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors border border-slate-700"
          >
            <Share2 className="w-4 h-4" />
          </button>
        </div>

        <div className={`px-4 py-2 border rounded-xl flex items-center gap-3 font-bold ${
          grade === 'A+' || grade === 'A' 
            ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' 
            : 'bg-amber-500/10 border-amber-500/20 text-amber-400'
        }`}>
          <div className="text-3xl">{grade}</div>
          <div className="flex flex-col text-xs uppercase tracking-widest opacity-80 leading-tight">
            <span>Score</span>
            <span>{score}/100</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReportHeader;
