import React, { useState } from 'react';
import { ShieldCheck, AlertOctagon, Check, X, Shield, ChevronDown, FileSearch, Users, Scale, Globe2, Database, Gauge, Server, Code2, Lock, Clock3, ShieldAlert } from 'lucide-react';

const faqs = [
  {
    icon: Shield,
    question: "Do you need access to my systems?",
    answer: "No. URLScannerOnline only needs your public website URL—no passwords, admin access, or credentials.\nDeeper testing requires your explicit approval and separate access."
  },
  {
    icon: Scale,
    question: "Is this legal and safe for my site?",
    answer: "Yes, when you scan a website you own or are authorized to assess.\nOur passive checks are read-only and designed to minimize impact on live systems."
  },
  {
    icon: FileSearch,
    question: "What happens after I submit?",
    answer: "We analyze the website using automated security checks and generate a clear report.\nYou’ll see detected risks, severity levels, and recommended remediation steps."
  },
  {
    icon: Users,
    question: "Who is this for?",
    answer: "It’s designed for website owners, developers, businesses, and security teams.\nIt’s especially useful for anyone who wants a quick security overview without intrusive testing."
  }
];

const SafetyComparison = () => {
  const [openFaq, setOpenFaq] = useState(null);
  return (
    <div className="w-full mt-12 animate-in fade-in slide-in-from-bottom-4 duration-700 delay-300">
      <div className="text-center mb-8">
        <h2 className="text-2xl md:text-3xl font-bold text-slate-200 flex items-center justify-center gap-3">
          <ShieldCheck className="w-8 h-8 text-indigo-400" />
          How URLScannerOnline Protects Live Websites
        </h2>
        <p className="text-slate-400 mt-2 font-medium">We use a passive-first approach to deliver actionable insights without risk or disruption.</p>
      </div>

      <div className="grid md:grid-cols-2 gap-6 max-w-5xl mx-auto text-left">
        {/* Left Card — Our Approach */}
        <div className="bg-slate-900 border border-emerald-500/30 rounded-2xl p-6 md:p-8 shadow-[0_0_30px_rgba(16,185,129,0.05)] relative overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-[0.03]">
            <ShieldCheck size={160} />
          </div>

          <div className="relative z-10">
            <span className="inline-block bg-emerald-500/20 text-emerald-400 text-xs font-bold px-2 py-1 rounded mb-4 tracking-wider uppercase">✓ WHAT WE DO</span>
            <div className="flex items-center gap-3 mb-2">
              <h3 className="text-xl font-bold text-slate-100">URLScannerOnline Audit</h3>
            </div>
            <span className="inline-block bg-slate-800 text-slate-300 text-xs px-2 py-0.5 rounded border border-slate-700 mb-6">Passive • Read-Only</span>
          </div>

          <ul className="relative z-10">
            <li className="flex items-center justify-between gap-3 py-4 border-t border-slate-800/70">
              <div className="flex items-start gap-3">
                <div className="bg-emerald-500/20 p-1 rounded-full text-emerald-400 mt-0.5 shrink-0">
                  <Check size={14} strokeWidth={3} />
                </div>
                <div>
                  <span className="block text-sm font-semibold text-slate-200">Production-Friendly</span>
                  <span className="text-sm text-slate-400">Designed to minimize impact on live websites</span>
                </div>
              </div>
              <Globe2 size={18} className="text-slate-500 shrink-0 hidden sm:block" />
            </li>
            <li className="flex items-center justify-between gap-3 py-4 border-t border-slate-800/70">
              <div className="flex items-start gap-3">
                <div className="bg-emerald-500/20 p-1 rounded-full text-emerald-400 mt-0.5 shrink-0">
                  <Check size={14} strokeWidth={3} />
                </div>
                <div>
                  <span className="block text-sm font-semibold text-slate-200">Data Safety</span>
                  <span className="text-sm text-slate-400">Read-only security checks</span>
                </div>
              </div>
              <Database size={18} className="text-slate-500 shrink-0 hidden sm:block" />
            </li>
            <li className="flex items-center justify-between gap-3 py-4 border-t border-slate-800/70">
              <div className="flex items-start gap-3">
                <div className="bg-emerald-500/20 p-1 rounded-full text-emerald-400 mt-0.5 shrink-0">
                  <Check size={14} strokeWidth={3} />
                </div>
                <div>
                  <span className="block text-sm font-semibold text-slate-200">WAF & Firewall</span>
                  <span className="text-sm text-slate-400">Low-impact traffic patterns</span>
                </div>
              </div>
              <Lock size={18} className="text-slate-500 shrink-0 hidden sm:block" />
            </li>
            <li className="flex items-center justify-between gap-3 py-4 border-t border-slate-800/70">
              <div className="flex items-start gap-3">
                <div className="bg-emerald-500/20 p-1 rounded-full text-emerald-400 mt-0.5 shrink-0">
                  <Check size={14} strokeWidth={3} />
                </div>
                <div>
                  <span className="block text-sm font-semibold text-slate-200">Audit Speed</span>
                  <span className="text-sm text-slate-400">Fast automated scanning</span>
                </div>
              </div>
              <Gauge size={18} className="text-slate-500 shrink-0 hidden sm:block" />
            </li>
          </ul>
        </div>

        {/* Right Card — What We Avoid */}
        <div className="bg-slate-900/60 border border-rose-500/30 rounded-2xl p-6 md:p-8 relative overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-[0.03]">
            <AlertOctagon size={160} />
          </div>

          <div className="relative z-10">
            <span className="inline-block bg-rose-500/10 text-rose-400 text-xs font-bold px-2 py-1 rounded mb-4 tracking-wider uppercase">✕ WHAT WE AVOID</span>
            <div className="flex items-center gap-3 mb-2">
              <h3 className="text-xl font-bold text-slate-300">Intrusive Security Testing</h3>
            </div>
            <span className="inline-block bg-slate-800/50 text-slate-400 text-xs px-2 py-0.5 rounded border border-slate-700/50 mb-6">Not part of our standard scan</span>
          </div>

          <ul className="relative z-10">
            <li className="flex items-center justify-between gap-3 py-4 border-t border-slate-800/70">
              <div className="flex items-start gap-3">
                <div className="bg-rose-500/20 p-1 rounded-full text-rose-400 mt-0.5 shrink-0">
                  <X size={14} strokeWidth={3} />
                </div>
                <div>
                  <span className="block text-sm font-semibold text-slate-400">Higher Production Risk</span>
                  <span className="text-sm text-slate-500">May affect or disrupt live systems</span>
                </div>
              </div>
              <Server size={18} className="text-slate-600 shrink-0 hidden sm:block" />
            </li>
            <li className="flex items-center justify-between gap-3 py-4 border-t border-slate-800/70">
              <div className="flex items-start gap-3">
                <div className="bg-rose-500/20 p-1 rounded-full text-rose-400 mt-0.5 shrink-0">
                  <X size={14} strokeWidth={3} />
                </div>
                <div>
                  <span className="block text-sm font-semibold text-slate-400">Interactive Testing</span>
                  <span className="text-sm text-slate-500">Additional requests to application endpoints</span>
                </div>
              </div>
              <Code2 size={18} className="text-slate-600 shrink-0 hidden sm:block" />
            </li>
            <li className="flex items-center justify-between gap-3 py-4 border-t border-slate-800/70">
              <div className="flex items-start gap-3">
                <div className="bg-rose-500/20 p-1 rounded-full text-rose-400 mt-0.5 shrink-0">
                  <X size={14} strokeWidth={3} />
                </div>
                <div>
                  <span className="block text-sm font-semibold text-slate-400">WAF & Firewall</span>
                  <span className="text-sm text-slate-500">May trigger security alerts or blocks</span>
                </div>
              </div>
              <ShieldAlert size={18} className="text-slate-600 shrink-0 hidden sm:block" />
            </li>
            <li className="flex items-center justify-between gap-3 py-4 border-t border-slate-800/70">
              <div className="flex items-start gap-3">
                <div className="bg-rose-500/20 p-1 rounded-full text-rose-400 mt-0.5 shrink-0">
                  <X size={14} strokeWidth={3} />
                </div>
                <div>
                  <span className="block text-sm font-semibold text-slate-400">Audit Speed</span>
                  <span className="text-sm text-slate-500">Can take hours to days</span>
                </div>
              </div>
              <Clock3 size={18} className="text-slate-600 shrink-0 hidden sm:block" />
            </li>
          </ul>
        </div>
      </div>

      <div className="max-w-5xl mx-auto mt-6 bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex items-center justify-center gap-3 text-sm text-slate-400 text-center">
        <ShieldCheck className="w-5 h-5 text-indigo-400 shrink-0" />
        <p>Our passive-first approach ensures your website stays <span className="text-indigo-300 font-medium">fast, secure, and uninterrupted.</span></p>
      </div>

      {/* FAQ Section */}
      <div className="max-w-3xl mx-auto mt-16 text-left animate-in fade-in slide-in-from-bottom-4 duration-700 delay-500">
        <div className="text-center mb-8">
          <h3 className="text-xl md:text-2xl font-bold text-slate-200 mb-2">Frequently Asked Questions</h3>
          <p className="text-sm text-slate-400">Everything you need to know about our scanning engine.</p>
        </div>
        <div className="space-y-3">
          {faqs.map((faq, index) => {
            const isOpen = openFaq === index;
            const Icon = faq.icon;
            return (
              <div
                key={index}
                className={`transition-colors rounded-lg border overflow-hidden ${
                  isOpen
                    ? 'bg-slate-800/80 border-indigo-500/30'
                    : 'bg-slate-900/70 border-slate-700/60 hover:bg-slate-800/50 hover:border-slate-600/60'
                }`}
              >
                <button
                  onClick={() => setOpenFaq(isOpen ? null : index)}
                  className="w-full flex items-center justify-between p-4 md:px-5 md:py-4 text-left focus:outline-none"
                >
                  <div className="flex items-center gap-3">
                    <Icon className="w-4 h-4 md:w-5 md:h-5 text-indigo-300 shrink-0" />
                    <span className="font-semibold text-slate-200 text-sm md:text-base pr-4">{faq.question}</span>
                  </div>
                  <div className={`text-slate-400 shrink-0 transition-transform duration-300 ${isOpen ? 'rotate-180' : ''}`}>
                    <ChevronDown size={18} />
                  </div>
                </button>
                <div
                  className={`transition-all duration-300 ease-in-out ${isOpen ? 'max-h-48 opacity-100' : 'max-h-0 opacity-0'} overflow-hidden`}
                >
                  <div className="p-4 md:px-5 md:pb-5 pt-0 text-slate-400 text-sm leading-relaxed ml-7 md:ml-8">
                    {faq.answer.split('\n').map((line, i) => (
                      <React.Fragment key={i}>
                        {line}
                        {i !== faq.answer.split('\n').length - 1 && <br />}
                      </React.Fragment>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default SafetyComparison;
