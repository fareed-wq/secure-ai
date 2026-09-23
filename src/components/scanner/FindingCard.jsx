import React, { useMemo } from 'react';
import { getTranslation, getBusinessRisk, getEffort } from '../../lib/utils/translations';
import SeverityBadge from './SeverityBadge';
import { calculateFindingPriority } from '../../utils/priority';
import { ChevronDown } from 'lucide-react';


const FindingCard = ({ issue, idx }) => {
  // Memoize derived data to avoid repeated calls
  const trans = useMemo(() => getTranslation(issue), [issue]);
  const risk = useMemo(() => getBusinessRisk(issue.severity), [issue.severity]);
  const effort = useMemo(() => getEffort(issue.severity), [issue.severity]);

  const getConfidenceStyles = useMemo(() => (conf) => {
    if (!conf) return '';
    const lowerConf = conf.toString().toLowerCase();

    let level = 'medium';
    if (lowerConf.includes('high')) {
      level = 'high';
    } else if (lowerConf.includes('low')) {
      level = 'low';
    } else if (lowerConf.includes('%')) {
      const num = parseInt(lowerConf.replace(/[^0-9]/g, ''), 10);
      if (!isNaN(num)) {
        if (num >= 80) level = 'high';
        else if (num <= 40) level = 'low';
      }
    }

    if (level === 'high') {
      return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    } else if (level === 'low') {
      return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
    return 'text-amber-200/80 bg-amber-500/10 border-amber-500/20';
  }, []);

  return (
    <details className={`simple-finding-card finding-card border-y border-r border-slate-800 rounded-3xl overflow-hidden shadow-md ${issue.severity === 'Critical' || issue.severity === 'High' ? 'simple-risk-high border-l-4 border-l-red-500 bg-red-950/10' :
      issue.severity === 'Medium' ? 'simple-risk-medium border-l-4 border-l-amber-500 bg-amber-950/10' :
        issue.severity === 'Informational' ? 'simple-risk-info border-l-4 border-l-blue-500 bg-blue-900/10' :
          'simple-risk-low border-l-4 border-l-slate-600 bg-slate-900/40'
      }`}>

      {/* Collapsed Header */}
      <summary className="flex flex-col md:flex-row md:items-center gap-4 p-6 cursor-pointer list-none [&::-webkit-details-marker]:hidden hover:bg-slate-800/30 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:bg-slate-800/30">
        <div className="flex items-center gap-4 flex-1 min-w-0">
          <div className="w-10 h-10 rounded-full bg-slate-800/80 text-slate-50 font-bold text-xl flex items-center justify-center shrink-0" aria-hidden="true">{idx + 1}</div>
          <div className="flex-1 min-w-0">
            <h4 className="text-xl md:text-2xl font-bold text-slate-50 tracking-tight truncate">
              {trans.name}
            </h4>
            <div className="flex flex-wrap items-center gap-2 mt-2">
              <SeverityBadge severity={issue.severity} />
              <span className="text-[10px] uppercase font-bold text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded border border-slate-700 shrink-0">
                Priority: {calculateFindingPriority(issue)}
              </span>
              {effort && effort !== 'N/A' && (
                <span className="text-[10px] uppercase font-bold text-indigo-400 bg-indigo-500/10 px-1.5 py-0.5 rounded border border-indigo-500/30 shrink-0">
                  {effort}
                </span>
              )}
            </div>
          </div>
        </div>
        <div className="text-slate-500 bg-slate-800/50 p-2 rounded-full group-open:rotate-180 transition-transform shrink-0" aria-hidden="true">
          <ChevronDown size={20} />
        </div>
      </summary>

      {/* Expanded Content */}
      <div className="px-6 pb-6 pt-2">
        <div className="space-y-6">
          {issue.confidence && issue.confidence !== 'N/A' && (
            <div className={`flex items-center gap-2 w-fit px-3 py-1.5 rounded-lg border ${getConfidenceStyles(issue.confidence)}`} aria-label={`Confidence: ${issue.confidence}`}>
              <span className="text-xs font-bold uppercase tracking-wider opacity-80">Confidence:</span>
              <span className="text-sm font-bold">{issue.confidence}</span>
            </div>
          )}
          <div>
            <span className="text-lg font-bold text-slate-100 block mb-1" aria-hidden="true">What was detected?</span>
            <span className="text-lg text-slate-300 leading-relaxed block">{trans.problem}</span>
          </div>
          <div>
            <span className="text-lg font-bold text-slate-100 block mb-1" aria-hidden="true">Why does it matter?</span>
            <span className="text-lg text-slate-300 leading-relaxed block">{trans.why}</span>
          </div>

          {trans.action && issue.severity !== 'Passed' && (
            <div>
                <span className="text-lg font-bold text-slate-100 block mb-1" aria-hidden="true">What to do</span>
                <span className="text-lg text-slate-300 leading-relaxed block">{trans.action}</span>
              </div>
          )}

          {/* Business Risk Box */}
          <div className={`simple-business-risk-box ${issue.severity === 'Critical' || issue.severity === 'High' ? 'simple-business-risk-high' :
            issue.severity === 'Medium' ? 'simple-business-risk-medium' :
              issue.severity === 'Informational' ? 'simple-business-risk-info' :
                'simple-business-risk-low'
            } ${risk.container} w-full max-w-full sm:max-w-md`}>
            <div className="mb-1 flex items-center gap-2">
              <SeverityBadge severity={issue.severity} />
              <span className="text-[10px] uppercase font-bold text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded border border-slate-700">Priority: {calculateFindingPriority(issue)}</span>
            </div>
            <div className={`simple-business-risk-description ${risk.text}`}>{risk.desc}</div>
          </div>

          {/* Estimated Effort */}
          {effort && effort !== 'N/A' && (
            <div className="bg-slate-900/80 border border-indigo-500/30 rounded-xl p-4 shadow-sm w-full max-w-full sm:max-w-md">
              <div className="text-xs font-mono font-bold text-indigo-400 tracking-wider uppercase flex items-center gap-1.5" aria-label="Estimated effort to fix">
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Estimated Effort
              </div>
              <div className="text-base font-bold text-slate-50 mt-1 block">{effort}</div>
            </div>
          )}
        </div>
      </div>
    </details>
  );
};

export default FindingCard;
