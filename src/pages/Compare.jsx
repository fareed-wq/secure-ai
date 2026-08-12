import React from 'react';
import { ArrowRight, GitCommit } from 'lucide-react';

const Compare = () => {
  return (
    <div className="space-y-6 text-slate-200">
      <div>
        <h1 className="text-3xl font-bold text-slate-50 tracking-tight">Report Comparison</h1>
        <p className="text-slate-400 mt-1">Track remediation progress across different scans.</p>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8">
        <div className="flex flex-col md:flex-row items-center justify-center gap-6">
          <div className="flex-1 w-full">
            <label className="block text-sm font-medium text-slate-400 mb-2">Base Scan</label>
            <select className="block w-full bg-slate-950 border border-slate-700 rounded-lg py-3 px-4 text-slate-50 focus:ring-indigo-500 focus:border-indigo-500">
              <option>example.com - 2026-08-01 (Score: 85)</option>
            </select>
          </div>
          
          <div className="hidden md:flex mt-6 items-center justify-center">
            <ArrowRight className="w-6 h-6 text-slate-600" />
          </div>

          <div className="flex-1 w-full">
            <label className="block text-sm font-medium text-slate-400 mb-2">Compare Against</label>
            <select className="block w-full bg-slate-950 border border-slate-700 rounded-lg py-3 px-4 text-slate-50 focus:ring-indigo-500 focus:border-indigo-500">
              <option>example.com - 2026-08-04 (Score: 92)</option>
            </select>
          </div>
        </div>
        
        <div className="mt-8 flex justify-center">
          <button className="px-6 py-3 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium transition-colors">
            Generate Diff
          </button>
        </div>
      </div>

      {/* Mock Diff Result */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden mt-8">
        <div className="p-6 border-b border-slate-800 bg-slate-800/30 flex justify-between items-center">
          <h2 className="font-bold text-slate-50 flex items-center gap-2">
            <GitCommit className="w-5 h-5 text-indigo-400" />
            Remediation Progress
          </h2>
          <div className="text-emerald-400 font-bold">+7 Points</div>
        </div>
        
        <div className="p-6">
          <div className="space-y-4">
            <div className="flex items-center gap-4 p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-xl">
              <span className="bg-emerald-500 text-slate-900 text-xs font-bold px-2 py-1 rounded">FIXED</span>
              <p className="text-sm text-emerald-100">Missing Content-Security-Policy (CSP) has been resolved.</p>
            </div>
            
            <div className="flex items-center gap-4 p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-xl">
              <span className="bg-emerald-500 text-slate-900 text-xs font-bold px-2 py-1 rounded">FIXED</span>
              <p className="text-sm text-emerald-100">Missing Strict-Transport-Security (HSTS) has been resolved.</p>
            </div>
            
            <div className="flex items-center gap-4 p-4 bg-slate-800/50 border border-slate-700 rounded-xl opacity-60">
              <span className="bg-slate-600 text-slate-50 text-xs font-bold px-2 py-1 rounded">UNCHANGED</span>
              <p className="text-sm text-slate-300">X-Powered-By Header Exposed remains present.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Compare;
