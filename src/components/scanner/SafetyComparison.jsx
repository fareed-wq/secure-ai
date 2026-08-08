import React from 'react';
import { ShieldCheck, AlertOctagon, Check, X } from 'lucide-react';

const SafetyComparison = () => {
  return (
    <div className="w-full mt-12 animate-in fade-in slide-in-from-bottom-4 duration-700 delay-300">
      <div className="text-center mb-8">
        <h2 className="text-2xl md:text-3xl font-bold text-slate-200 flex flex-wrap items-center justify-center gap-2 md:gap-3">
          <span className="text-3xl">🌟</span> Safe for Live Production Environments
        </h2>
        <p className="text-slate-400 mt-2 font-medium">100% zero-impact scanning. No slowdowns, no downtime, no risks.</p>
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
            <h3 className="text-xl font-bold text-indigo-400">URLScanOnline Audit</h3>
          </div>

          <ul className="space-y-5 relative z-10">
            <li className="flex items-start gap-3">
              <div className="bg-emerald-500/20 p-1 rounded-full text-emerald-400 mt-0.5 shrink-0">
                <Check size={16} strokeWidth={3} />
              </div>
              <div>
                <span className="block text-sm font-semibold text-slate-200">Production Safe</span>
                <span className="text-sm text-slate-400">Zero Risk to uptime</span>
              </div>
            </li>
            <li className="flex items-start gap-3">
              <div className="bg-emerald-500/20 p-1 rounded-full text-emerald-400 mt-0.5 shrink-0">
                <Check size={16} strokeWidth={3} />
              </div>
              <div>
                <span className="block text-sm font-semibold text-slate-200">Database Integrity</span>
                <span className="text-sm text-slate-400">Read-Only Header/DNS Probes</span>
              </div>
            </li>
            <li className="flex items-start gap-3">
              <div className="bg-emerald-500/20 p-1 rounded-full text-emerald-400 mt-0.5 shrink-0">
                <Check size={16} strokeWidth={3} />
              </div>
              <div>
                <span className="block text-sm font-semibold text-slate-200">WAF & Firewall</span>
                <span className="text-sm text-slate-400">Non-Disruptive Traffic</span>
              </div>
            </li>
            <li className="flex items-start gap-3">
              <div className="bg-emerald-500/20 p-1 rounded-full text-emerald-400 mt-0.5 shrink-0">
                <Check size={16} strokeWidth={3} />
              </div>
              <div>
                <span className="block text-sm font-semibold text-slate-200">Audit Speed</span>
                <span className="text-sm text-slate-400">⚡ Sub-5 Seconds</span>
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
            <h3 className="text-xl font-bold text-slate-400">Intrusive Pen-Testing</h3>
          </div>

          <ul className="space-y-5 relative z-10">
            <li className="flex items-start gap-3">
              <div className="bg-rose-500/20 p-1 rounded-full text-rose-400 mt-0.5 shrink-0">
                <X size={16} strokeWidth={3} />
              </div>
              <div>
                <span className="block text-sm font-semibold text-slate-400">Production Safe</span>
                <span className="text-sm text-slate-400">High Downtime Risk</span>
              </div>
            </li>
            <li className="flex items-start gap-3">
              <div className="bg-rose-500/20 p-1 rounded-full text-rose-400 mt-0.5 shrink-0">
                <X size={16} strokeWidth={3} />
              </div>
              <div>
                <span className="block text-sm font-semibold text-slate-400">Database Integrity</span>
                <span className="text-sm text-slate-400">Risk of Data Corruption (SQLi)</span>
              </div>
            </li>
            <li className="flex items-start gap-3">
              <div className="bg-rose-500/20 p-1 rounded-full text-rose-400 mt-0.5 shrink-0">
                <X size={16} strokeWidth={3} />
              </div>
              <div>
                <span className="block text-sm font-semibold text-slate-400">WAF & Firewall</span>
                <span className="text-sm text-slate-400">Triggers IP Bans / Alerts</span>
              </div>
            </li>
            <li className="flex items-start gap-3">
              <div className="bg-rose-500/20 p-1 rounded-full text-rose-400 mt-0.5 shrink-0">
                <X size={16} strokeWidth={3} />
              </div>
              <div>
                <span className="block text-sm font-semibold text-slate-400">Audit Speed</span>
                <span className="text-sm text-slate-400">⏳ Hours to Days</span>
              </div>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default SafetyComparison;
