import React, { useState } from 'react';
import { ShieldCheck, AlertOctagon, Check, X, Shield, ChevronDown, FileSearch, Users, Scale } from 'lucide-react';

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
