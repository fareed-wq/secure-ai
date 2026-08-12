import React from 'react';
import { getTranslation, getBusinessRisk, getEffort } from '../../lib/utils/translations';
import SeverityBadge from './SeverityBadge';

const FindingCard = ({ issue, idx }) => {
  const trans = getTranslation(issue);
  const risk = getBusinessRisk(issue.severity);
  const effort = getEffort(issue.severity);

  const getConfidenceStyles = (conf) => {
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
  };

  return (
    <div className={`finding-card border-y border-r border-slate-800 rounded-3xl p-8 flex flex-col md:flex-row gap-8 items-start shadow-xl ${
      issue.severity === 'Critical' || issue.severity === 'High' ? 'border-l-4 border-l-red-500 bg-red-950/10' :
      issue.severity === 'Medium' ? 'border-l-4 border-l-amber-500 bg-amber-950/10' :
      'border-l-4 border-l-slate-600 bg-slate-900/40'
    }`}>
      
      <div className="flex-1 space-y-4">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 rounded-full bg-slate-800/80 text-white font-bold text-xl flex items-center justify-center shrink-0">{idx + 1}</div>
          <h4 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            {trans.name}
          </h4>
        </div>
        
        <div className="space-y-3 mt-3">
          {issue.confidence && issue.confidence !== 'N/A' && (
            <div className={`flex items-center gap-2 w-fit px-3 py-1.5 rounded-lg border mb-4 ${getConfidenceStyles(issue.confidence)}`}>
              <span className="text-xs font-bold uppercase tracking-wider opacity-80">Confidence:</span>
              <span className="text-sm font-bold">{issue.confidence}</span>
            </div>
          )}
          <span className="text-lg font-bold text-slate-100 block mb-1">What was detected?</span>
          <span className="text-lg text-slate-300 leading-relaxed block mb-4">{trans.problem}</span>
          <span className="text-lg font-bold text-slate-100 block mb-1">Why does it matter?</span>
          <span className="text-lg text-slate-300 leading-relaxed block mb-4">{trans.why}</span>
          

        </div>
      </div>

      <div className="w-full md:w-80">
        <div className={`${risk.container} w-full md:w-80`}>
          <div className="mb-1">
            <SeverityBadge severity={issue.severity} />
          </div>
          <div className={risk.text}>{risk.desc}</div>
        </div>
        
        <div className="bg-slate-900/80 border border-indigo-500/30 rounded-xl p-4 mt-3 shadow-sm w-full md:w-80">
          <div className="text-xs font-mono font-bold text-indigo-400 tracking-wider uppercase flex items-center gap-1.5">
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Estimated Effort
          </div>
          <div className="text-base font-bold text-white mt-1 block">{effort}</div>
        </div>
      </div>
    </div>
  );
};

export default FindingCard;
