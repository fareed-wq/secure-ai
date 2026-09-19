import React from 'react';
import { ChevronDown } from 'lucide-react';
import { getTestedState, getCapabilityLabel } from '../../lib/assessmentReporting';

export const WhatWasTested = ({ moduleExecution }) => {
  const renderScopeLimitations = () => (
    <div className="border-t border-slate-800/50 pt-4 mt-2">
      <div className="text-xs font-bold text-slate-400 mb-2 font-mono uppercase tracking-wider">Not tested by this scan</div>
      <ul className="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-1">
        <li className="text-sm text-slate-500 flex items-start gap-2"><span className="text-slate-700 mt-1">•</span>Exploit validation for SQL injection or XSS</li>
        <li className="text-sm text-slate-500 flex items-start gap-2"><span className="text-slate-700 mt-1">•</span>Authenticated application workflows</li>
        <li className="text-sm text-slate-500 flex items-start gap-2"><span className="text-slate-700 mt-1">•</span>Destructive testing</li>
        <li className="text-sm text-slate-500 flex items-start gap-2"><span className="text-slate-700 mt-1">•</span>Password guessing or brute-force attacks</li>
        <li className="text-sm text-slate-500 flex items-start gap-2"><span className="text-slate-700 mt-1">•</span>Broad fuzzing</li>
        <li className="text-sm text-slate-500 flex items-start gap-2"><span className="text-slate-700 mt-1">•</span>Malware scanning</li>
      </ul>
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

  return (
    <details className="group report-section bg-slate-950/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-xl shadow-2xl mt-6">
      <summary className="flex items-center justify-between cursor-pointer list-none [&::-webkit-details-marker]:hidden mb-4">
        <span className="font-mono text-xs font-bold text-cyan-400 tracking-wider">&gt;_ WHAT_WAS_TESTED</span>
        <span className="group-open:rotate-180 transition-transform"><ChevronDown size={16} className="text-slate-500" /></span>
      </summary>
      <div className="mt-4">

      <div className="flex flex-wrap gap-3 mb-3">
        {order.map(state => {
          const count = groups[state].length;
          if (count === 0) return null;
          let color = "bg-slate-800/60 text-slate-400 border-slate-700";
          if (state === "Tested") color = "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
          else if (state === "Partially tested") color = "bg-amber-500/10 text-amber-400 border-amber-500/20";
          else if (state === "Not completed" || state === "Blocked") color = "bg-red-500/10 text-red-400 border-red-500/20";
          else if (state === "Not available") color = "bg-slate-800/60 text-slate-400 border-slate-700";

          return (
            <div key={state} className={`px-3 py-1.5 rounded-md border text-xs font-mono ${color}`}>
              <span className="font-bold">{count}</span> {state}
            </div>
          );
        })}
      </div>

      <div className="text-[11px] text-slate-500 mb-6">
        These statuses show whether scanner capabilities completed their intended assessment work. They do not indicate whether the target is secure.
      </div>


        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6 border-t border-slate-800/50 pt-4">
          {order.map(state => {
            if (groups[state].length === 0) return null;
            return (
              <div key={state}>
                <div className="text-xs font-bold text-slate-400 mb-2 font-mono uppercase tracking-wider">{state}</div>
                <ul className="space-y-1">
                  {groups[state].sort().map((cap, i) => (
                    <li key={i} className="text-sm text-slate-300 flex items-start gap-2">
                      <span className="text-slate-600 mt-1">•</span>
                      <span>{cap}</span>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>

      {renderScopeLimitations()}
          </div>
    </details>
  );
};

