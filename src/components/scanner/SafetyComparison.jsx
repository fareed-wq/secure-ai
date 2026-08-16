import React from 'react';
import { ShieldCheck, AlertOctagon, Check, X, Shield } from 'lucide-react';

const SafetyComparison = () => {
  return (
    <div className="w-full mt-12 animate-in fade-in slide-in-from-bottom-4 duration-700 delay-300">
      <div className="text-center mb-8">
        <h2 className="text-2xl md:text-3xl font-bold text-slate-200 flex flex-wrap items-center justify-center gap-2 md:gap-3">
          <div className="w-12 h-12 md:w-14 md:h-14 rounded-xl border border-emerald-500/40 bg-emerald-500/10 flex items-center justify-center text-emerald-400 flex-shrink-0 drop-shadow-[0_0_15px_rgba(16,185,129,0.5)]">
            <ShieldCheck className="w-6 h-6 md:w-8 md:h-8" strokeWidth={2.5} />
          </div> Designed for Live Production Environments
        </h2>
        <p className="text-slate-400 mt-2 font-medium">Passive scanning is read-only and designed to minimize impact on live websites.</p>
      </div>

      <div className="grid md:grid-cols-2 gap-6 max-w-5xl mx-auto text-left">
        {/* URLScanOnline Column (Highlighted) */}
        <div className="bg-slate-900/80 border border-indigo-500/40 rounded-2xl p-6 md:p-8 shadow-[0_0_30px_rgba(99,102,241,0.15)] relative overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10">
            <ShieldCheck size={100} />
          </div>
          
          <div className="flex items-center gap-3 mb-6 relative z-10">
            <div className="bg-indigo-600 p-2 rounded-lg text-white shadow-lg shadow-indigo-500/20">
              <ShieldCheck size={24} />
            </div>
            <h3 className="text-xl font-bold text-indigo-400">URLScannerOnline Audit</h3>
          </div>

          <ul className="space-y-5 relative z-10">
            <li className="flex items-start gap-3">
              <div className="bg-emerald-500/20 p-1 rounded-full text-emerald-400 mt-0.5 shrink-0">
                <Check size={16} strokeWidth={3} />
              </div>
              <div>
                <span className="block text-sm font-semibold text-slate-200">Production-Friendly</span>
                <span className="text-sm text-slate-400">Designed to minimize impact on live websites</span>
              </div>
            </li>
            <li className="flex items-start gap-3">
              <div className="bg-emerald-500/20 p-1 rounded-full text-emerald-400 mt-0.5 shrink-0">
                <Check size={16} strokeWidth={3} />
              </div>
              <div>
                <span className="block text-sm font-semibold text-slate-200">Data Safety</span>
                <span className="text-sm text-slate-400">Read-only security checks</span>
              </div>
            </li>
            <li className="flex items-start gap-3">
              <div className="bg-emerald-500/20 p-1 rounded-full text-emerald-400 mt-0.5 shrink-0">
                <Check size={16} strokeWidth={3} />
              </div>
              <div>
                <span className="block text-sm font-semibold text-slate-200">WAF & Firewall</span>
                <span className="text-sm text-slate-400">Low-impact traffic patterns</span>
              </div>
            </li>
            <li className="flex items-start gap-3">
              <div className="bg-emerald-500/20 p-1 rounded-full text-emerald-400 mt-0.5 shrink-0">
                <Check size={16} strokeWidth={3} />
              </div>
              <div>
                <span className="block text-sm font-semibold text-slate-200">Audit Speed</span>
                <span className="text-sm text-slate-400">⚡ Fast automated scanning</span>
              </div>
            </li>
          </ul>
        </div>

        {/* Intrusive Pen-Testing Column */}
        <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6 md:p-8 relative overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-5">
            <AlertOctagon size={100} />
          </div>

          <div className="flex items-center gap-3 mb-6 relative z-10 opacity-70 hover:opacity-100 transition-opacity">
            <div className="bg-rose-500/10 p-2 rounded-lg text-rose-400">
              <AlertOctagon size={24} />
            </div>
            <h3 className="text-xl font-bold text-slate-400">Active Security Testing</h3>
          </div>

          <ul className="space-y-5 relative z-10">
            <li className="flex items-start gap-3">
              <div className="bg-rose-500/20 p-1 rounded-full text-rose-400 mt-0.5 shrink-0">
                <X size={16} strokeWidth={3} />
              </div>
              <div>
                <span className="block text-sm font-semibold text-slate-400">Higher Production Risk</span>
                <span className="text-sm text-slate-400">May affect or disrupt live systems</span>
              </div>
            </li>
            <li className="flex items-start gap-3">
              <div className="bg-rose-500/20 p-1 rounded-full text-rose-400 mt-0.5 shrink-0">
                <X size={16} strokeWidth={3} />
              </div>
              <div>
                <span className="block text-sm font-semibold text-slate-400">Interactive Testing</span>
                <span className="text-sm text-slate-400">Additional requests to application endpoints</span>
              </div>
            </li>
            <li className="flex items-start gap-3">
              <div className="bg-rose-500/20 p-1 rounded-full text-rose-400 mt-0.5 shrink-0">
                <X size={16} strokeWidth={3} />
              </div>
              <div>
                <span className="block text-sm font-semibold text-slate-400">WAF & Firewall</span>
                <span className="text-sm text-slate-400">May trigger security alerts or blocks</span>
              </div>
            </li>
            <li className="flex items-start gap-3">
              <div className="bg-rose-500/20 p-1 rounded-full text-rose-400 mt-0.5 shrink-0">
                <X size={16} strokeWidth={3} />
              </div>
              <div>
                <span className="block text-sm font-semibold text-slate-400">Audit Speed</span>
                <span className="text-sm text-slate-400">⏳ Can take hours to days</span>
              </div>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default SafetyComparison;
