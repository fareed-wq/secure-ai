import React, { useMemo } from 'react';
import { motion } from 'framer-motion';
import { ShieldCheck, ShieldAlert, Target, CheckCircle2, AlertTriangle, Info, Activity, Lock, Globe } from 'lucide-react';

// --- TRANSLATION LAYER ---
// Maps technical backend findings to plain-English business language
const TRANSLATIONS = {
  "Missing Strict-Transport-Security Header": {
    name: "Insecure Connection Fallback",
    problem: "Your website does not always force visitors to use a secure connection.",
    why: "If visitors type 'http://' instead of 'https://', their connection might not be encrypted, allowing attackers to intercept their data.",
    category: "Encryption"
  },
  "Missing X-Content-Type-Options Header": {
    name: "Browser Confusion Vulnerability",
    problem: "Your server does not explicitly tell browsers how to handle certain files.",
    why: "Attackers can upload malicious scripts masked as safe files (like images). The browser might execute them by mistake.",
    category: "Browser Protection"
  },
  "Missing X-Frame-Options Header": {
    name: "Missing Clickjacking Protection (X-Frame-Options)",
    problem: "Your website lacks rules preventing external sites from embedding your web pages inside hidden frames.",
    why: "Attackers can overlay invisible buttons over your website to trick users into clicking malicious links or submitting data.",
    category: "Browser Protection"
  },
  "Missing X-Frame-Options": {
    name: "Missing Clickjacking Protection (X-Frame-Options)",
    problem: "Your website lacks rules preventing external sites from embedding your web pages inside hidden frames.",
    why: "Attackers can overlay invisible buttons over your website to trick users into clicking malicious links or submitting data.",
    category: "Browser Protection"
  },
  "Missing Content-Security-Policy (CSP)": {
    name: "Missing Data Theft Protection",
    problem: "Your website is missing an important browser protection against unauthorized scripts.",
    why: "If a hacker manages to inject a malicious script, there is no defense layer stopping it from stealing user data or passwords.",
    category: "Browser Protection"
  },
  "Missing Content-Security-Policy Header": {
    name: "Missing Data Theft Protection",
    problem: "Your website is missing an important browser protection against unauthorized scripts.",
    why: "If a hacker manages to inject a malicious script, there is no defense layer stopping it from stealing user data or passwords.",
    category: "Browser Protection"
  },
  "Server Banner Information Disclosure": {
    name: "Server Information Leak",
    problem: "Your server is broadcasting its exact software version to the public.",
    why: "Hackers use this information to search for known weaknesses specific to that exact software version to plan a targeted attack.",
    category: "Privacy Protection"
  },
  "Missing HttpOnly Flag": {
    name: "Insecure Session Cookies",
    problem: "Your website cookies can be accessed by scripts running in the browser.",
    why: "If an attacker runs a malicious script on your site, they can easily steal these cookies and hijack your users' accounts.",
    category: "Privacy Protection"
  },
  "Missing Secure Flag": {
    name: "Unencrypted Cookies",
    problem: "Cookies are allowed to be sent over unencrypted connections.",
    why: "If a user connects over public Wi-Fi, their session could be intercepted and stolen.",
    category: "Encryption"
  },
  "Directory Listing Enabled": {
    name: "Exposed Website Files",
    problem: "Anyone can browse the files and folders on your web server.",
    why: "Attackers can download source code, backup files, or sensitive documents that were not meant for public viewing.",
    category: "Privacy Protection"
  },
  "Missing Strict-Transport-Security (HSTS)": {
    name: "Missing Forced Encryption (HSTS)",
    problem: "Your website does not force browsers to use secure HTTPS connections automatically.",
    why: "Attackers on public Wi-Fi networks can downgrade your visitors' connection to unencrypted HTTP and steal sensitive session data.",
    category: "Encryption"
  },
  "Missing SPF Record": {
    name: "Missing Email Anti-Spoofing (SPF)",
    problem: "Your domain is missing an authorization record that specifies who can send email on your behalf.",
    why: "Scammers can send fake emails pretending to come from your company, damaging your reputation and tricking your customers.",
    category: "Email Trust"
  },
  "Missing DMARC Policy": {
    name: "Inactive Email Phishing Defense (DMARC)",
    problem: "Your domain is missing email verification policies.",
    why: "Receiving mail servers are instructed to deliver spoofed emails pretending to be from your domain rather than blocking them.",
    category: "Email Trust"
  },
  "Weak DMARC Policy (p=none)": {
    name: "Inactive Email Phishing Defense (DMARC)",
    problem: "Your domain has email verification set to 'monitoring only' mode (p=none).",
    why: "Receiving mail servers are instructed to deliver spoofed emails pretending to be from your domain rather than blocking them.",
    category: "Email Trust"
  }
};

const getTranslation = (technicalName) => {
  return TRANSLATIONS[technicalName] || {
    name: technicalName, // fallback
    problem: "A security misconfiguration was detected that deviates from industry best practices.",
    why: "Leaving this unresolved slightly increases your overall attack surface.",
    category: "Website Trust"
  };
};

const getBusinessRisk = (severity) => {
  const risks = {
    'Critical': { label: 'Critical Business Risk', badge: 'bg-red-700 text-white px-3.5 py-1.5 rounded-md text-base font-bold tracking-wide inline-block shadow-sm', container: 'bg-red-950/40 border border-red-500/50 rounded-xl p-4 shadow-sm', text: 'text-red-100 text-sm mt-3 font-medium block', desc: 'Immediate risk of data breach, financial loss, or severe disruption.' },
    'High': { label: 'High Business Risk', badge: 'bg-rose-600 text-white px-3.5 py-1.5 rounded-md text-base font-bold tracking-wide inline-block shadow-sm', container: 'bg-rose-950/40 border border-rose-500/50 rounded-xl p-4 shadow-sm', text: 'text-rose-100 text-sm mt-3 font-medium block', desc: 'Significant risk of unauthorized access or reputational damage.' },
    'Medium': { label: 'Moderate Business Risk', badge: 'bg-amber-500 text-black px-3.5 py-1.5 rounded-md text-base font-bold tracking-wide inline-block shadow-sm', container: 'bg-amber-950/40 border border-amber-500/50 rounded-xl p-4 shadow-sm', text: 'text-amber-100 text-sm mt-3 font-medium block', desc: 'Operational risk that could be exploited if combined with other flaws.' },
    'Low': { label: 'Minimal Business Risk', badge: 'bg-yellow-400 text-black px-3.5 py-1.5 rounded-md text-base font-bold tracking-wide inline-block shadow-sm', container: 'bg-yellow-950/30 border border-yellow-500/40 rounded-xl p-4 shadow-sm', text: 'text-yellow-100 text-sm mt-3 font-medium block', desc: 'Minor risk, mostly missing recommended security best practices.' },
    'Informational': { label: 'Observation', badge: 'bg-blue-600 text-white px-3.5 py-1.5 rounded-md text-base font-bold tracking-wide inline-block shadow-sm', container: 'bg-blue-950/40 border border-blue-500/50 rounded-xl p-4 shadow-sm', text: 'text-blue-100 text-sm mt-3 font-medium block', desc: 'Technical details that are not directly exploitable.' },
  };
  return risks[severity] || risks['Informational'];
};

const getEffort = (severity) => {
  const effort = {
    'Critical': 'Emergency (Hours)',
    'High': 'High Priority (Days)',
    'Medium': 'Scheduled (Weeks)',
    'Low': 'Routine Backlog',
  };
  return effort[severity] || 'Minimal';
};

const SimpleReport = ({ reportData }) => {
  const findings = reportData?.findings || [];
  const passed = findings.filter(f => f.severity === 'Passed');
  const issues = findings.filter(f => f.severity !== 'Passed' && f.severity !== 'Informational').sort((a, b) => {
    const w = { Critical: 5, High: 4, Medium: 3, Low: 2 };
    return (w[b.severity] || 0) - (w[a.severity] || 0);
  });

  const topPriorities = issues.slice(0, 5); // Max 5 items
  const score = reportData?.score ?? 0;
  
  let healthSummary = "";
  if (score >= 90) healthSummary = "Your website is generally secure. We found a few minor recommendations that will further improve your security.";
  else if (score >= 70) healthSummary = "Your website has moderate security risks. Addressing the top priorities below is highly recommended.";
  else healthSummary = "Your website is currently at high risk. Please review the critical action items below immediately.";

  // Calculate generic health bars based on the translations categories we saw
  const calculateHealth = (category) => {
    const catIssues = issues.filter(i => getTranslation(i.name).category === category);
    if (catIssues.length === 0) return 100;
    if (catIssues.some(i => i.severity === 'Critical' || i.severity === 'High')) return 20;
    return 60;
  };

  const healthMetrics = [
    { name: 'Website Trust', val: calculateHealth('Website Trust') },
    { name: 'Encryption', val: calculateHealth('Encryption') },
    { name: 'Browser Protection', val: calculateHealth('Browser Protection') },
    { name: 'Privacy Protection', val: calculateHealth('Privacy Protection') }
  ];

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-8" id="report-content">
      
      {/* 1. Executive Summary & Score */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 text-white p-8 rounded-3xl shadow-xl flex flex-col justify-center">
          <h2 className="text-2xl font-black mb-4">Executive Summary</h2>
          <p className="text-xl text-slate-300 leading-relaxed">
            {healthSummary}
          </p>
          <div className="mt-8 flex gap-4">
            <div className="bg-slate-800/50 border border-slate-700/50 px-6 py-4 rounded-2xl">
              <div className="text-sm font-bold text-slate-400 uppercase">Issues Found</div>
              <div className="text-3xl font-black text-white">{issues.length}</div>
            </div>
            <div className="bg-emerald-950/30 border border-emerald-900/30 px-6 py-4 rounded-2xl">
              <div className="text-sm font-bold text-emerald-500 uppercase">Passed Checks</div>
              <div className="text-3xl font-black text-emerald-400">{passed.length}</div>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-8 rounded-3xl shadow-xl flex flex-col items-center justify-center text-center">
          <div className="relative">
            <svg className="w-40 h-40 transform -rotate-90">
              <circle cx="80" cy="80" r="70" stroke="currentColor" strokeWidth="12" fill="transparent" className="text-slate-800" />
              <circle cx="80" cy="80" r="70" stroke="currentColor" strokeWidth="12" fill="transparent"
                strokeDasharray={2 * Math.PI * 70}
                strokeDashoffset={2 * Math.PI * 70 * (1 - score / 100)}
                className={score >= 80 ? 'text-emerald-500' : score >= 60 ? 'text-amber-500' : 'text-red-500'}
                strokeLinecap="round"
              />
            </svg>
            <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 flex flex-col items-center">
              <span className="text-5xl font-black text-white">{score}</span>
            </div>
          </div>
          <div className="mt-6">
            <div className="text-sm font-bold uppercase tracking-widest text-slate-400">Risk Meter</div>
            <div className={`text-2xl font-black mt-1 ${score >= 80 ? 'text-emerald-400' : score >= 60 ? 'text-amber-400' : 'text-red-400'}`}>
              {score >= 90 ? 'Excellent' : score >= 80 ? 'Good' : score >= 70 ? 'Fair' : 'Poor'}
            </div>
          </div>
        </div>
      </div>

      {/* 2. Security Health Bars */}
      <div className="bg-slate-900 border border-slate-800 p-8 rounded-3xl">
        <h3 className="text-xl font-bold text-white mb-6">Website Health Summary</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-12 gap-y-6">
          {healthMetrics.map((metric, i) => (
            <div key={i} className="space-y-2">
              <div className="flex justify-between text-sm font-bold">
                <span className="text-slate-300">{metric.name}</span>
                <span className={metric.val === 100 ? 'text-emerald-400' : metric.val >= 60 ? 'text-amber-400' : 'text-red-400'}>
                  {metric.val === 100 ? 'Optimal' : metric.val >= 60 ? 'Needs Attention' : 'Vulnerable'}
                </span>
              </div>
              <div className="h-3 w-full bg-slate-800 rounded-full overflow-hidden">
                <div 
                  className={`h-full rounded-full ${metric.val === 100 ? 'bg-emerald-500' : metric.val >= 60 ? 'bg-amber-500' : 'bg-red-500'}`} 
                  style={{ width: `${metric.val}%` }}
                ></div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 3. Action Checklist (Top Priorities) */}
      {topPriorities.length > 0 && (
        <div className="space-y-6">
          <div className="flex flex-col">
            <h3 className="font-black text-2xl text-white">Top Priorities ({topPriorities.length})</h3>
            <p className="text-slate-400 mt-1">Review these business risks with your IT provider or web developer.</p>
          </div>
          
          <div className="grid gap-6">
            {topPriorities.map((issue, idx) => {
              const trans = getTranslation(issue.name);
              const risk = getBusinessRisk(issue.severity);
              
              return (
                <div key={idx} className="finding-card bg-slate-900 border border-slate-800 rounded-3xl p-8 flex flex-col md:flex-row gap-8 items-start shadow-xl">
                  
                  <div className="flex-1 space-y-4">
                    <div className="flex items-center gap-3 mb-2">
                      <div className="w-10 h-10 rounded-full bg-slate-800 text-white font-bold text-xl flex items-center justify-center shrink-0">{idx + 1}</div>
                      <h4 className="text-2xl font-bold text-white tracking-tight">{trans.name}</h4>
                    </div>
                    
                    <div className="space-y-3 mt-3">
                      <span className="text-lg font-bold text-slate-100 block mb-1">The Problem:</span>
                      <span className="text-lg text-slate-200 leading-relaxed block mb-4">{trans.problem}</span>
                      <span className="text-lg font-bold text-slate-100 block mb-1">Why it matters:</span>
                      <span className="text-lg text-slate-200 leading-relaxed block">{trans.why}</span>
                    </div>
                  </div>

                  <div className="w-full md:w-80">
                    <div className={`${risk.container} w-full md:w-80`}>
                      <div className="mb-1">
                        <span className={risk.badge}>{risk.label}</span>
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
                      <div className="text-base font-bold text-white mt-1 block">{getEffort(issue.severity)}</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 4. Security Strengths */}
      {passed.length > 0 && (
        <div className="bg-emerald-950/20 border border-emerald-900/50 p-8 rounded-3xl mt-12">
          <div className="flex items-center gap-4 mb-8">
            <div className="p-3 bg-emerald-500 rounded-2xl text-white shadow-lg shadow-emerald-500/20">
              <ShieldCheck className="w-8 h-8" />
            </div>
            <div>
              <h3 className="font-black text-2xl text-white">Security Strengths</h3>
              <p className="text-emerald-200/70">What your website is already doing correctly.</p>
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {passed.slice(0, 6).map((item, i) => (
              <div key={i} className="flex items-center gap-3 bg-slate-900/50 p-5 rounded-2xl border border-slate-800">
                <CheckCircle2 className="w-6 h-6 text-emerald-500 shrink-0" />
                <span className="font-bold text-slate-200">{item.name}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 5. Final Recommendation */}
      <div className="text-center mt-12 py-12 border-t border-slate-800">
        <h3 className="text-2xl font-black text-white mb-4">Ready to improve your score?</h3>
        <p className="text-slate-400 text-lg max-w-2xl mx-auto">
          Interested in advanced testing? Let's chat on WhatsApp!
        </p>
      </div>

    </motion.div>
  );
};

export default SimpleReport;
