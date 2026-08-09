import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldCheck, ShieldAlert, Target, CheckCircle2, AlertTriangle, Info, Activity, Lock, Globe, Layout, Key, Copy, Check, Shield, Layers, Code2, Box, Mail } from 'lucide-react';


// --- TRANSLATION LAYER ---
// Maps technical backend findings to plain-English business language
const TRANSLATIONS = {
  "Missing Strict-Transport-Security Header": {
    name: "Insecure Connection Fallback",
    problem: "Your website does not always force visitors to use a secure connection.",
    why: "If visitors type 'http://' instead of 'https://', their connection might not be encrypted, allowing attackers to intercept their data.",
    category: "Encryption"
  },
  "Missing Strict-Transport-Security (HSTS)": {
    name: "Missing Forced Encryption (HSTS)",
    problem: "Your website does not force browsers to use secure HTTPS connections automatically.",
    why: "Allows attackers to downgrade HTTPS connections to unencrypted HTTP via man-in-the-middle SSL stripping attacks.",
    category: "Encryption"
  },
  "Missing Content-Security-Policy (CSP)": {
    name: "Weak Data Injection Guard (CSP)",
    problem: "Your site either lacks a Content Security Policy or has permissive rules that allow unauthorized scripts.",
    why: "Permissive directives like 'unsafe-inline' or 'unsafe-eval' weaken browser defenses, leaving your site vulnerable to Cross-Site Scripting (XSS) and data theft.",
    category: "Browser Protection"
  },
  "Weak Content-Security-Policy (CSP)": {
    name: "Weak Data Injection Guard (CSP)",
    problem: "Your site has a permissive Content Security Policy that allows unauthorized scripts.",
    why: "Permissive directives like 'unsafe-inline' or 'unsafe-eval' weaken browser defenses, leaving your site vulnerable to Cross-Site Scripting (XSS) and data theft.",
    category: "Browser Protection"
  },
  "Missing X-Frame-Options": {
    name: "Missing Clickjacking Protection (X-Frame-Options)",
    problem: "Your website lacks rules preventing external sites from embedding your web pages inside hidden frames.",
    why: "Attackers can overlay invisible buttons over your website to trick users into clicking malicious links or submitting data.",
    category: "Browser Protection"
  },
  "Missing X-Frame-Options Header": {
    name: "Missing Clickjacking Protection (X-Frame-Options)",
    problem: "Your website lacks rules preventing external sites from embedding your web pages inside hidden frames.",
    why: "Attackers can overlay invisible buttons over your website to trick users into clicking malicious links or submitting data.",
    category: "Browser Protection"
  },
  "Missing X-Content-Type-Options": {
    name: "Missing Malicious File Guard (nosniff)",
    problem: "Your server does not explicitly instruct browsers to strictly enforce file types.",
    why: "Browsers may try to guess a file's format and accidentally execute a fake image or document containing hidden script code.",
    category: "Browser Protection"
  },
  "Missing Referrer-Policy": {
    name: "Missing External Link Privacy (Referrer-Policy)",
    problem: "Your website does not control what URL details are shared when visitors click links leading to external websites.",
    why: "Sensitive internal page URLs or parameters could leak to third-party web servers when users leave your site.",
    category: "Privacy Protection"
  },
  "Missing Permissions-Policy": {
    name: "Unrestricted Browser Capabilities (Permissions-Policy)",
    problem: "Your site does not define rules for accessing browser hardware features (like camera, microphone, or geolocation).",
    why: "Embedded third-party scripts could attempt to request or misuse browser hardware permissions.",
    category: "Privacy Protection"
  },
  "Missing Cross-Origin-Opener-Policy": {
    name: "Missing Cross-Window Isolation (COOP)",
    problem: "Your website does not isolate its browser process from external sites opened via links.",
    why: "Malicious pop-ups or external links could attempt side-channel timing attacks against active user sessions.",
    category: "Browser Protection"
  },
  "Missing Cross-Origin-Embedder-Policy": {
    name: "Missing Cross-Origin Resource Isolation (COEP)",
    problem: "Your site loads external assets without requiring explicit cross-origin loading permission.",
    why: "Prevents advanced browser-level data isolation needed to defend against processor-level memory leaks.",
    category: "Browser Protection"
  },
  "Missing Cross-Origin-Resource-Policy": {
    name: "Unprotected Cross-Origin Assets (CORP)",
    problem: "Your web server does not restrict which external domains are allowed to read your site's images and scripts.",
    why: "Other websites could embed or read your private media assets directly without authorization.",
    category: "Privacy Protection"
  },
  "Missing SPF Record": {
    name: "Missing Email Anti-Spoofing (SPF)",
    problem: "Your domain is missing an authorization record that specifies who can send email on your behalf.",
    why: "Scammers can send fake emails pretending to come from your company, damaging your reputation and tricking your customers.",
    category: "Email Trust"
  },
  "Missing DMARC Policy": {
    name: "Inactive Email Phishing Defense (DMARC)",
    problem: "Your domain has email verification set to 'monitoring only' mode (p=none) or lacks a DMARC policy entirely.",
    why: "Receiving mail servers are instructed to deliver spoofed emails pretending to be from your domain rather than blocking them.",
    category: "Email Trust"
  },
  "Weak DMARC Policy (p=none)": {
    name: "Inactive Email Phishing Defense (DMARC)",
    problem: "Your domain has email verification set to 'monitoring only' mode (p=none) or lacks a DMARC policy entirely.",
    why: "Receiving mail servers are instructed to deliver spoofed emails pretending to be from your domain rather than blocking them.",
    category: "Email Trust"
  },
  "Missing DNS CAA Record": {
    name: "Missing Certificate Authority Lock (CAA)",
    problem: "Your domain DNS settings lack a CAA record restricting who can issue SSL certificates for your site.",
    why: "Allows any unauthorized Certificate Authority (CA) to issue SSL/TLS certificates for your domain without restriction.",
    category: "Domain Trust"
  },
  "Missing security.txt": {
    name: "Missing Vulnerability Disclosure Contact (security.txt)",
    problem: "Your domain does not publish a standard security contact file at /.well-known/security.txt.",
    why: "Ethical security researchers who find vulnerabilities on your site have no official path to privately report them to your team.",
    category: "Website Trust"
  },
  "Missing HttpOnly Flag on Cookie": {
    name: "Unsecured Session Cookie (HttpOnly)",
    problem: "A cookie saved in your browser is missing the HttpOnly security restriction.",
    why: "If a malicious script runs on your site, it can steal this cookie and hijack active user logins or sessions.",
    category: "Session Security"
  },
  "Missing Secure Flag on Cookie": {
    name: "Unencrypted Cookie Transmission (Secure Flag)",
    problem: "Session cookies are missing the 'Secure' flag.",
    why: "Browsers may send sensitive authentication cookies over unencrypted HTTP connections if requested.",
    category: "Session Security"
  },
  "Missing SameSite Attribute on Cookie": {
    name: "Unprotected Cross-Site Cookie (SameSite)",
    problem: "Your website sets browser cookies without defining strict cross-site sharing restrictions.",
    why: "Browsers may send these cookies automatically on third-party links, making users vulnerable to Cross-Site Request Forgery (CSRF).",
    category: "Session Security"
  },
  "Exposed Server Header": {
    name: "Exposed Web Server Technology",
    problem: "Your web server advertises its exact software name and version in response headers.",
    why: "Revealing exact backend technologies helps attackers run automated recon to target known, published vulnerabilities in your tech stack.",
    category: "Privacy Protection"
  },
  "Exposed X-Powered-By Header": {
    name: "Exposed Web Server Technology",
    problem: "Your web server advertises its exact software name and version in response headers.",
    why: "Revealing exact backend technologies helps attackers run automated recon to target known, published vulnerabilities in your tech stack.",
    category: "Privacy Protection"
  },
  "X-Powered-By Header Exposed": {
    name: "X-Powered-By Header Exposed",
    problem: "Backend technology is explicitly declared.",
    why: "Revealing exact backend technologies helps attackers run automated recon to target known, published vulnerabilities in your tech stack.",
    category: "Privacy Protection"
  },
  "Missing Automatic HTTPS Forwarding": {
    name: "Missing Automatic HTTPS Forwarding",
    problem: "Visitors opening your website via unencrypted http:// are not automatically redirected to secure https://.",
    why: "Unencrypted traffic can be intercepted, exposed, or modified by attackers on local networks.",
    category: "Encryption"
  },
  "Wildcard SSL Certificate": {
    name: "Broad Subdomain Certificate Scope",
    problem: "Your site uses a wildcard SSL certificate (*.yourdomain.com).",
    why: "If any single sub-domain server is compromised, the private key can be used to intercept traffic across all subdomains.",
    category: "Encryption"
  },
  "Directory Listing Enabled": {
    name: "Exposed Website Files",
    problem: "Anyone can browse the files and folders on your web server.",
    why: "Attackers can download source code, backup files, or sensitive documents that were not meant for public viewing.",
    category: "Privacy Protection"
  },
  "Wildcard CORS Policy": {
    name: "Permissive CORS Policy",
    problem: "Your API allows cross-origin requests from any domain using a wildcard origin.",
    why: "Malicious external websites can make authenticated API requests on behalf of logged-in users and exfiltrate private session data.",
    category: "Session Security"
  },
  "Weak TLS Cipher Negotiated": {
    name: "Weak TLS Cipher",
    problem: "Your server negotiates weak or obsolete TLS ciphers.",
    why: "Deprecated ciphers allow attackers performing Man-in-the-Middle (MitM) network eavesdropping to decrypt confidential user traffic.",
    category: "Encryption"
  },
  "Insecure or Obsolete TLS Ciphers Enforced": {
    name: "Obsolete TLS Ciphers Enforced",
    problem: "Your server enforces deprecated legacy TLS ciphers or protocols.",
    why: "Deprecated ciphers allow attackers performing Man-in-the-Middle (MitM) network eavesdropping to decrypt confidential user traffic.",
    category: "Encryption"
  },
  "Legacy Weak TLS Ciphers Supported": {
    name: "Legacy Weak TLS Ciphers Supported",
    problem: "Server accepts connections configured with deprecated weak ciphers (e.g. 3DES / RC4).",
    why: "Deprecated ciphers allow attackers performing Man-in-the-Middle (MitM) network eavesdropping to decrypt confidential user traffic.",
    category: "Encryption"
  },
  "Missing HTTPS Redirection": {
    name: "Missing HTTPS Redirection",
    problem: "Your website does not redirect visitors from unencrypted HTTP to secure HTTPS.",
    why: "Unencrypted HTTP traffic can be intercepted by eavesdroppers on public networks, exposing passwords, cookies, and sensitive user data.",
    category: "Encryption"
  },
  "SSL/TLS Connection Failure": {
    name: "SSL/TLS Connection Failure",
    problem: "Your server's SSL/TLS certificate is invalid, expired, or the secure handshake is failing.",
    why: "Browsers display severe security warnings or block access entirely, destroying user trust and preventing secure data transmission.",
    category: "Encryption"
  }
};

const getTranslation = (finding) => {
  const technicalName = finding.name;

  if (TRANSLATIONS[technicalName]) {
    return TRANSLATIONS[technicalName];
  }
  
  if (technicalName.startsWith("Unsecured Cookie")) {
    return {
      name: technicalName,
      problem: finding.description,
      why: "If a malicious script runs on your site, it can steal these cookies and hijack active user logins or sessions.",
      category: "Session Security"
    };
  }

  return {
    name: technicalName,
    problem: finding.description || "A recommended security configuration is missing or partially configured on your web server.",
    why: finding.impact && finding.impact !== "N/A" ? finding.impact : "Resolving this configuration aligns your site with industry baseline security standards.",
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
  const getCategoryIcon = (category) => {
    if (category === 'Encryption') return <Lock className="w-5 h-5 text-red-400" />;
    if (category === 'Browser Protection') return <ShieldAlert className="w-5 h-5 text-red-400" />;
    if (category === 'Privacy Protection') return <Layout className="w-5 h-5 text-amber-400" />;
    return <Key className="w-5 h-5 text-slate-400" />;
  };

  const findings = reportData?.findings || [];
  const passed = findings.filter(f => f.severity === 'Passed');
  const issues = findings.filter(f => f.severity !== 'Passed' && f.severity !== 'Informational').sort((a, b) => {
    const w = { Critical: 5, High: 4, Medium: 3, Low: 2 };
    return (w[b.severity] || 0) - (w[a.severity] || 0);
  });

  const topPriorities = issues.slice(0, 5); // Max 5 items
  const score = reportData?.score ?? 0;
  
  // Check if this is a WAF-blocked scan (only 1 finding and it's the WAF finding)
  const isWafBlocked = findings.length === 1 && findings[0]?.name?.includes('WAF');

  let healthSummary = "";
  if (reportData?.executive_summary && isWafBlocked) {
    // Use backend-provided summary for WAF-blocked or limited scans
    healthSummary = reportData.executive_summary;
  } else if (score === 100) {
    healthSummary = "Your website meets all baseline security best practices with zero open issues or vulnerabilities detected. Outstanding security posture!";
  } else if (score >= 90) {
    healthSummary = "Your website demonstrates a strong security posture. Addressing the few remaining recommendations below will achieve a perfect score.";
  } else if (score >= 80) {
    healthSummary = "Your website is well-secured overall. Addressing the few minor recommendations below will further harden your posture.";
  } else if (score >= 50) {
    healthSummary = "Your website has moderate security risks. Addressing the top priorities below is highly recommended.";
  } else {
    healthSummary = "Your website faces significant security risks. Resolving the top priorities below is strongly recommended to protect your users.";
  }

  // Calculate domain-based health from backend findings
  const calculateDomainHealth = (domain) => {
    if (isWafBlocked) return -1;
    const domainFindings = findings.filter(f => f.domain === domain);
    const domainIssues = domainFindings.filter(f => f.severity !== 'Passed' && f.severity !== 'Informational');
    const domainPassed = domainFindings.filter(f => f.severity === 'Passed');
    if (domainFindings.length === 0) return 100; // No checks in this domain
    if (domainIssues.length === 0) return 100;
    if (domainIssues.some(f => f.severity === 'Critical' || f.severity === 'High')) return 20;
    if (domainIssues.some(f => f.severity === 'Medium')) return 50;
    return 70;
  };

  const healthMetrics = [
    { name: 'Transport & TLS', val: calculateDomainHealth('transport_tls'), icon: Lock },
    { name: 'Browser Defense', val: calculateDomainHealth('browser_defense'), icon: ShieldAlert },
    { name: 'API Surface', val: calculateDomainHealth('api_surface'), icon: Code2 },
    { name: 'Email & Domain', val: calculateDomainHealth('email_domain'), icon: Mail }
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
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 w-full mt-4">
            <div className="bg-slate-800/50 border border-slate-700/50 p-4 rounded-xl flex flex-col justify-center">
              <div className="text-xs font-bold text-slate-400 uppercase tracking-wider">Issues Found</div>
              <div className="text-2xl font-black text-white mt-1">{issues.length}</div>
            </div>
            <div className="bg-emerald-500/10 border border-emerald-500/20 p-4 rounded-xl flex flex-col justify-center">
              <div className="text-xs font-bold text-emerald-500 uppercase tracking-wider">Passed Checks</div>
              <div className="text-2xl font-black text-emerald-400 mt-1">{passed.length}</div>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-8 rounded-3xl shadow-xl flex flex-col items-center justify-center text-center">
          <div className="relative">
            <svg className="w-40 h-40 transform -rotate-90">
              <circle cx="80" cy="80" r="70" stroke="currentColor" strokeWidth="12" fill="transparent" className="text-slate-800" />
              {!isWafBlocked && (
                <circle cx="80" cy="80" r="70" stroke="currentColor" strokeWidth="12" fill="transparent"
                  strokeDasharray={2 * Math.PI * 70}
                  strokeDashoffset={2 * Math.PI * 70 * (1 - score / 100)}
                  className={score >= 80 ? 'text-emerald-500' : score >= 60 ? 'text-amber-500' : 'text-red-500'}
                  strokeLinecap="round"
                />
              )}
              {isWafBlocked && (
                <circle cx="80" cy="80" r="70" stroke="currentColor" strokeWidth="12" fill="transparent"
                  strokeDasharray="8 6"
                  className="text-slate-600"
                />
              )}
            </svg>
            <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 flex flex-col items-center">
              <span className="text-5xl font-black text-white">{isWafBlocked ? 'N/A' : score}</span>
            </div>
          </div>
          <div className="mt-6">
            <div className="text-sm font-bold uppercase tracking-widest text-slate-400">Risk Meter</div>
            <div className={`text-2xl font-black mt-1 ${isWafBlocked ? 'text-slate-400' : score >= 80 ? 'text-emerald-400' : score >= 60 ? 'text-amber-400' : 'text-red-400'}`}>
              {isWafBlocked ? 'Blocked' : score >= 90 ? 'Excellent' : score >= 80 ? 'Good' : score >= 50 ? 'Fair' : 'Poor'}
            </div>
          </div>
        </div>
      </div>

      {/* 1.5. Target Surface Breakdown */}
      {reportData?.target_surface && (() => {
        const ts = reportData.target_surface;
        const isApiClean = (ts.api_surface || '').toLowerCase().includes('no public');
        const isJsClean = (ts.js_health || '').toLowerCase().includes('clean');
        const perfRating = reportData?.metadata?.performance_rating || ts.performance || '';
        const wafSubtext = (() => {
          const status = ts.waf_status || '';
          const statusCode = status.match(/\d{3}/)?.[0] || '';
          if (statusCode === '200') return '200 OK • Healthy';
          if (statusCode === '403') return '403 • Access Restricted';
          if (statusCode === '503') return '503 • Service Issue';
          if (statusCode) return `${statusCode} • Detected`;
          return perfRating || 'Status Unknown';
        })();
        const surfaceCards = [
          {
            title: 'WAF / SERVER',
            value: ts.waf_server || 'Direct Origin',
            subtext: wafSubtext,
            icon: Shield,
            iconColor: 'text-sky-400',
            pill: perfRating?.toLowerCase().includes('optimal') ? 'OPTIMAL LATENCY' : perfRating?.toLowerCase().includes('average') ? 'AVERAGE LATENCY' : 'LATENCY CHECKED',
            pillColor: perfRating?.toLowerCase().includes('optimal') ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : perfRating?.toLowerCase().includes('high') ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' : 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30',
          },
          {
            title: 'FRONTEND STACK',
            value: ts.frontend_stack || 'Standard Web Stack',
            subtext: (ts.frontend_stack && ts.frontend_stack !== 'Standard Web Stack') ? ts.frontend_stack : 'HTML5 / JavaScript Application',
            icon: Layers,
            iconColor: 'text-indigo-400',
            pill: 'VERIFIED STACK',
            pillColor: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30',
          },
          {
            title: 'API SURFACE',
            value: isApiClean ? 'No Public Spec Exposed' : (ts.api_surface || 'Unknown'),
            subtext: isApiClean ? 'GraphQL / OpenAPI Clean' : 'Public Endpoint Detected',
            icon: Code2,
            iconColor: isApiClean ? 'text-emerald-400' : 'text-amber-400',
            pill: isApiClean ? 'CLEAN SURFACE' : 'EXPOSED ENDPOINT',
            pillColor: isApiClean ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-amber-500/10 text-amber-400 border-amber-500/30',
          },
          {
            title: 'JS HEALTH',
            value: isJsClean ? 'Clean Build' : 'Leak Detected',
            subtext: isJsClean ? '0 .map Leaks Detected' : 'Source Map Exposed',
            icon: Box,
            iconColor: isJsClean ? 'text-emerald-400' : 'text-rose-400',
            pill: isJsClean ? '0 LEAKS DETECTED' : 'LEAK FOUND',
            pillColor: isJsClean ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-rose-500/10 text-rose-400 border-rose-500/30',
          },
        ];
        return (
          <div className="rounded-2xl border border-slate-800 bg-slate-950/80 p-6 backdrop-blur-md shadow-xl">
            <div className="flex items-center gap-2.5 mb-6">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <span className="relative flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
                </span>
              </div>
              <h2 className="text-lg font-semibold tracking-tight text-white">Target Surface Breakdown</h2>
            </div>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {surfaceCards.map((card, idx) => {
                const Icon = card.icon;
                return (
                  <div key={idx} className="w-full min-w-0 min-h-[150px] p-4 bg-slate-900/60 border border-slate-800 hover:border-slate-700/80 rounded-xl flex flex-col justify-between transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/5">
                    <div>
                      <div className="flex items-center gap-2 text-[11px] font-bold font-mono tracking-wider text-slate-400 uppercase h-5">
                        <Icon className={`w-3.5 h-3.5 shrink-0 ${card.iconColor}`} />
                        {card.title}
                      </div>
                      <div className="text-base sm:text-lg font-bold text-white mt-2">
                        {card.value}
                      </div>
                      <div className="text-xs text-slate-400 mt-1">
                        {card.subtext}
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5 mt-auto pt-3">
                      <span className={`inline-flex items-center px-2.5 py-1 rounded-md text-[10px] font-bold font-mono tracking-wider uppercase border ${card.pillColor}`}>
                        {card.pill}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })()}

      {/* 2. Security Health Bars */}
      <div className="bg-slate-900 border border-slate-800 p-8 rounded-3xl">
        <h3 className="text-xl font-bold text-white mb-6">Website Health Summary</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-12 gap-y-6">
          {healthMetrics.map((metric, i) => {
            const MetricIcon = metric.icon;
            return (
              <div key={i} className="space-y-2">
                <div className="flex justify-between items-center text-sm font-bold mb-1">
                  <span className="text-slate-300 flex items-center gap-2">
                    <MetricIcon className="w-4 h-4 text-slate-500 shrink-0" />
                    {metric.name}
                    {metric.val !== -1 && (
                      <span className="text-[11px] font-mono text-slate-500">{metric.val}%</span>
                    )}
                  </span>
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider ${metric.val === -1 ? 'bg-slate-500/10 text-slate-400 border border-slate-500/20' : metric.val >= 90 ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : metric.val >= 50 ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                    {metric.val === -1 ? '⚪ No Data' : metric.val >= 90 ? '🟢 Optimal' : metric.val >= 50 ? '🟡 Needs Attention' : '🔴 Vulnerable'}
                  </span>
                </div>
                <div className="h-3 w-full bg-slate-800 rounded-full overflow-hidden">
                  {metric.val === -1 ? (
                    <div className="h-full rounded-full bg-slate-600/40" style={{ width: '100%', backgroundImage: 'repeating-linear-gradient(45deg, transparent, transparent 4px, rgba(148,163,184,0.1) 4px, rgba(148,163,184,0.1) 8px)' }}></div>
                  ) : (
                    <div 
                      className={`h-full rounded-full ${metric.val >= 90 ? 'bg-emerald-500' : metric.val >= 50 ? 'bg-amber-500' : 'bg-red-500'}`} 
                      style={{ width: `${metric.val}%` }}
                    ></div>
                  )}
                </div>
              </div>
            );
          })}
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
              const trans = getTranslation(issue);
              const risk = getBusinessRisk(issue.severity);
              
              return (
                <div key={idx} className={`finding-card border-y border-r border-slate-800 rounded-3xl p-8 flex flex-col md:flex-row gap-8 items-start shadow-xl ${
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
                      <span className="text-lg font-bold text-slate-100 block mb-1">The Problem:</span>
                      <span className="text-lg text-slate-300 leading-relaxed block mb-4">{trans.problem}</span>
                      <span className="text-lg font-bold text-slate-100 block mb-1">Why it matters:</span>
                      <span className="text-lg text-slate-300 leading-relaxed block">{trans.why}</span>
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
            <div>
              <h3 className="font-black text-2xl text-white flex items-center">
                Security Strengths
                <span className="ml-3 px-3 py-1 text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-full">
                  {passed.length} Passed
                </span>
              </h3>
              <p className="text-emerald-200/70 mt-1">What your website is already doing correctly.</p>
            </div>
          </div>
          
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
            {passed.map((item, i) => (
              <div key={i} className="bg-slate-900/60 hover:bg-slate-900/90 backdrop-blur-md border border-emerald-500/20 hover:border-emerald-500/40 transition-all duration-300 hover:-translate-y-0.5 hover:shadow-lg hover:shadow-emerald-500/5 rounded-xl p-3.5 flex items-center gap-3">
                <div className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 shrink-0">
                  <Check className="w-4 h-4" />
                </div>
                <span className="text-sm font-semibold text-slate-200 leading-snug">{item.name}</span>
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
