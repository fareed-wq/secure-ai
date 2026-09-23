import React, { useState } from 'react';
import { Globe, Download, FileJson, FileSpreadsheet, ChevronDown } from 'lucide-react';
import { exportJSON, exportCSV } from '../../lib/exportUtils';

const ReportHeader = ({ url, score, timestamp, activeMode, onToggleMode, onExportPdf, reportData }) => {
  const findings = reportData?.findings || [];
  const isWafBlocked = findings.length === 1 && findings[0]?.name?.includes('WAF');
  const [showExportMenu, setShowExportMenu] = useState(false);
  const exportMenuRef = React.useRef(null);

  return (
    <div className="relative z-40 bg-slate-900/90 backdrop-blur-md border border-slate-700/50 p-6 rounded-2xl shadow-md flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 mb-8">
      <div className="flex-1">
        <h2 className="text-2xl font-bold mb-1 text-slate-50">Security Posture Report</h2>
        <div className="flex flex-wrap items-center gap-4 text-sm text-slate-400">
          <span className="flex items-center gap-1 truncate max-w-[200px]">
            <Globe className="w-4 h-4 text-indigo-400 shrink-0" />
            <span className="truncate">{url}</span>
          </span>
          <span className="opacity-50 shrink-0">•</span>
          <span className="shrink-0">
            {(() => {
              const parsed = timestamp ? new Date(timestamp) : null;
              const valid = parsed && !Number.isNaN(parsed.getTime());
              return valid ? `Scanned on ${parsed.toLocaleString([], {
                year: 'numeric',
                month: 'numeric',
                day: 'numeric',
                hour: 'numeric',
                minute: '2-digit'
              })}` : 'Date unavailable';
            })()}
          </span>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-4">
        {/* Report Mode Toggle */}
        <div className="flex bg-slate-950 p-1 rounded-xl border border-slate-800">
          <button
            type="button"
            onClick={() => onToggleMode('simple')}
            className={`px-6 py-2 rounded-lg text-sm font-bold transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-inset ${activeMode === 'simple'
              ? 'bg-emerald-500/20 text-emerald-400 shadow'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
          >
            Simple
          </button>
          <button
            type="button"
            onClick={() => onToggleMode('technical')}
            className={`px-6 py-2 rounded-lg text-sm font-bold transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-inset ${activeMode === 'technical'
              ? 'bg-blue-500/20 text-blue-400 shadow'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
          >
            Technical
          </button>
        </div>

        {/* Export Menu */}
        <div className="relative" ref={exportMenuRef}>
          <button
            type="button"
            onClick={(e) => { e.preventDefault(); e.stopPropagation(); setShowExportMenu(!showExportMenu); }}
            title="Export Report"
            className="p-2.5 bg-slate-800 hover:bg-slate-700 text-slate-50 rounded-lg transition-colors border border-slate-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
          >
            <Download className="w-4 h-4" />
          </button>

          {showExportMenu && (
            <div className="absolute right-0 sm:right-auto sm:left-0 sm:mt-2 w-full sm:w-48 bg-slate-900 border border-slate-700 rounded-lg shadow-md z-50 overflow-hidden" ref={exportMenuRef}>
              <button
                type="button"
                onClick={(e) => { e.preventDefault(); e.stopPropagation(); onExportPdf(e); setShowExportMenu(false); }}
                className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-slate-300 hover:bg-slate-800 hover:text-slate-50 transition-colors text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-inset"
              >
                <FileSpreadsheet className="w-4 h-4" />
                Export PDF
              </button>
              <button
                type="button"
                onClick={(e) => { e.preventDefault(); e.stopPropagation(); exportJSON(reportData); setShowExportMenu(false); }}
                className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-slate-300 hover:bg-slate-800 hover:text-slate-50 transition-colors text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-inset"
              >
                <FileJson className="w-4 h-4" />
                Export JSON
              </button>
              <button
                type="button"
                onClick={(e) => { e.preventDefault(); e.stopPropagation(); exportCSV(reportData); setShowExportMenu(false); }}
                className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-slate-300 hover:bg-slate-800 hover:text-slate-50 transition-colors text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-inset"
              >
                <FileSpreadsheet className="w-4 h-4" />
                Export CSV
              </button>
            </div>
          )}
        </div>

        {/* Score Display */}
        <div className={`flex items-center gap-2.5 px-4 py-2.5 bg-slate-900/90 border rounded-xl backdrop-blur-md shadow-lg ${isWafBlocked
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
              <span className={`text-xl font-extrabold font-mono leading-none ${score >= 90 ? 'text-emerald-400' :
                score >= 80 ? 'text-teal-400' :
                  score >= 70 ? 'text-amber-400' :
                    score >= 60 ? 'text-orange-400' : 'text-rose-400'
                }`}>{score}<span className="text-sm font-normal text-slate-400">/100</span></span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReportHeader;
