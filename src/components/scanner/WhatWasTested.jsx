import React from 'react';
import { ChevronDown, CheckCircle2, AlertTriangle, XCircle, MinusCircle, HelpCircle, ShieldAlert } from 'lucide-react';
import { getTestedState, getCapabilityLabel } from '../../lib/assessmentReporting';

export const WhatWasTested = ({ moduleExecution }) => {
  const renderScopeLimitations = () => (
    <div className="border-t border-slate-800/50 pt-6 mt-6">
      <div className="text-xs font-bold text-slate-400 mb-4 font-mono uppercase tracking-wider flex items-center gap-2">
        <ShieldAlert className="w-4 h-4 text-slate-500" />
        Not tested by this scan
      </div>
      <div className="flex flex-wrap gap-2">
        {[
          "Exploit validation for SQL injection or XSS",
          "Authenticated application workflows",
          "Destructive testing",
          "Password guessing or brute-force attacks",
          "Broad fuzzing",
          "Malware scanning"
        ].map((item, i) => (
          <span key={i} className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-slate-900 border border-slate-800 text-slate-400 shadow-sm hover:bg-slate-800/50 transition-colors">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-600"></span>
            {item}
          </span>
        ))}
      </div>
    </div>
  );

  if (!moduleExecution || Object.keys(moduleExecution).length === 0) {
    return (
      <details className="group report-section bg-slate-950/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-xl shadow-2xl mt-6">
        <summary className="flex items-center justify-between cursor-pointer list-none [&::-webkit-details-marker]:hidden mb-2">
          <span className="font-mono text-xs font-bold text-cyan-400 tracking-wider">&gt;_ WHAT_WAS_TESTED</span>
          <span className="group-open:rotate-180 transition-transform"><ChevronDown size={16} className="text-slate-500" /></span>
        </summary>
        <div className="mt-4">
          <div className="text-sm text-slate-500 mb-6">Not available</div>
          <div className="text-[11px] text-slate-500 mb-6">
            These statuses show whether scanner capabilities completed their intended assessment work. They do not indicate whether the target is secure.
          </div>
          {renderScopeLimitations()}
        </div>
      </details>
    );
  }

  const groups = {
    "Tested": [],
    "Partially tested": [],
    "Not completed": [],
    "Blocked": [],
    "Not applicable": [],
    "Not available": []
  };

  for (const [modKey, modData] of Object.entries(moduleExecution)) {
    let status = null;
    let outcome = null;
    if (modData && typeof modData === 'object' && !Array.isArray(modData)) {
      status = modData.status;
      outcome = modData.assessment_outcome;
    }
    const state = getTestedState(status, outcome);
    groups[state].push(getCapabilityLabel(modKey));
  }

  const order = ["Tested", "Partially tested", "Not completed", "Blocked", "Not applicable", "Not available"];

  const getStateConfig = (state) => {
    switch (state) {
      case "Tested":
        return { icon: CheckCircle2, iconColor: "text-emerald-400", bg: "bg-emerald-500/5", text: "text-emerald-400", border: "border-emerald-500/20", dot: "bg-emerald-500" };
      case "Partially tested":
        return { icon: AlertTriangle, iconColor: "text-amber-400", bg: "bg-amber-500/5", text: "text-amber-400", border: "border-amber-500/20", dot: "bg-amber-500" };
      case "Not completed":
        return { icon: XCircle, iconColor: "text-rose-400", bg: "bg-rose-500/5", text: "text-rose-400", border: "border-rose-500/20", dot: "bg-rose-500" };
      case "Blocked":
        return { icon: MinusCircle, iconColor: "text-slate-400", bg: "bg-slate-500/5", text: "text-slate-400", border: "border-slate-500/20", dot: "bg-slate-500" };
      case "Not applicable":
        return { icon: HelpCircle, iconColor: "text-slate-500", bg: "bg-slate-800/40", text: "text-slate-500", border: "border-slate-700", dot: "bg-slate-600" };
      case "Not available":
        return { icon: HelpCircle, iconColor: "text-slate-500", bg: "bg-slate-800/40", text: "text-slate-500", border: "border-slate-700", dot: "bg-slate-600" };
      default:
        return { icon: HelpCircle, iconColor: "text-slate-500", bg: "bg-slate-800/40", text: "text-slate-500", border: "border-slate-700", dot: "bg-slate-600" };
    }
  };

  const activeStates = order.filter(state => groups[state].length > 0);
  const totalModules = Object.values(groups).flat().length;

  return (
    <details className="group report-section bg-slate-950/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-xl shadow-2xl mt-6">
      <summary className="flex items-center justify-between cursor-pointer list-none [&::-webkit-details-marker]:hidden mb-4">
        <span className="font-mono text-xs font-bold text-cyan-400 tracking-wider">&gt;_ WHAT_WAS_TESTED</span>
        <span className="group-open:rotate-180 transition-transform"><ChevronDown size={16} className="text-slate-500" /></span>
      </summary>
      <div className="mt-4">

        {/* Status Summary Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6 pb-4 border-b border-slate-800/50">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-slate-900/50 border border-slate-800 flex items-center justify-center shadow-inner">
              <span className="text-2xl font-black text-slate-50 font-mono">{totalModules}</span>
            </div>
            <div>
              <div className="text-sm font-bold text-slate-50 uppercase tracking-wide">Scanner Capabilities</div>
              <div className="text-[11px] text-slate-500 font-mono uppercase tracking-wider">{activeStates.length} status groups</div>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {order.map(state => {
              const count = groups[state].length;
              if (count === 0) return null;
              const config = getStateConfig(state);
              const Icon = config.icon;
              return (
                <span key={state} className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono font-medium ${config.bg} ${config.text} ${config.border} shadow-sm`}>
                  <Icon className={`w-3.5 h-3.5 ${config.iconColor}`} aria-hidden="true" />
                  <span className="font-bold">{count}</span>
                  <span className="hidden sm:inline">{state}</span>
                </span>
              );
            })}
          </div>
        </div>

        <div className="text-[11px] text-slate-500 mb-6">
          These statuses show whether scanner capabilities completed their intended assessment work. They do not indicate whether the target is secure.
        </div>

        {/* Grouped Capabilities */}
        <div className="space-y-4 mb-6">
          {order.map(state => {
            if (groups[state].length === 0) return null;
            const config = getStateConfig(state);
            const Icon = config.icon;
            return (
              <div key={state} className={`bg-slate-900/40 border ${config.border} rounded-xl p-5 shadow-sm`}>
                <div className="flex items-center gap-2 mb-4 border-b border-slate-800/50 pb-3">
                  <Icon className={`w-5 h-5 ${config.iconColor}`} aria-hidden="true" />
                  <span className={`font-bold text-sm ${config.text} uppercase tracking-wider`}>{state}</span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${config.bg} ${config.text} ${config.border}`}>
                    {groups[state].length}
                  </span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {groups[state].sort().map((cap, i) => (
                    <span key={i} className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm border ${config.bg} ${config.border} hover:bg-slate-800/50 transition-colors`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`}></span>
                      <span className="text-slate-200">{cap}</span>
                    </span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>

        {renderScopeLimitations()}
      </div>
    </details>
  );
};
