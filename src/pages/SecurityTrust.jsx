import React, { useEffect } from 'react';
import { ArrowLeft, Shield, Lock, Eye, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useSEO } from '../hooks/useSEO';

const SecurityTrust = () => {
  useSEO({ title: 'Security & Trust | URLScanOnline', description: 'Learn about our defensive scanning practices and commitment to platform security.', path: '/security-trust' });

  return (
        <div className="flex-1 w-full max-w-4xl mx-auto p-4 sm:p-6 lg:p-8 overflow-y-auto space-y-12 pb-24">
      <div className="mb-2">
        <Link
          to="/trust-policy"
          className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-indigo-400 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Trust & Policy
        </Link>
      </div>
      {/* Hero */}
      <section className="relative overflow-hidden rounded-3xl bg-slate-900 border border-slate-800 p-8 md:p-16 text-center mb-8">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-full max-w-4xl opacity-30 pointer-events-none">
          <div className="absolute inset-0 bg-gradient-to-r from-indigo-500/20 via-purple-500/20 to-blue-500/20 blur-3xl rounded-full transform -translate-y-1/2" />
        </div>
        <div className="relative z-10 max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 text-indigo-400 text-sm font-semibold mb-6">
            <Shield className="w-4 h-4" />
            Security & Trust
          </div>
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-black text-slate-50 mb-6 tracking-tight">
            Our commitment to <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-purple-400">responsible security.</span>
          </h1>
          <p className="text-lg md:text-xl text-slate-400 leading-relaxed">
            URLScanOnline is built around passive-first, non-intrusive security assessment. We believe security tools should help protect, not endanger, the websites they analyze.
          </p>
        </div>
      </section>

      {/* Scanning Philosophy */}
      <section>
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold text-slate-50 mb-4">Our Scanning Philosophy</h2>
          <p className="text-slate-400 max-w-2xl mx-auto">
            URLScanOnline is designed as a passive-first, low-impact security scanner. Basic scans focus on passive observations, while Advanced scans perform additional bounded, non-destructive checks.
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
            <div className="w-10 h-10 rounded-lg border border-indigo-500/30 bg-indigo-500/10 flex items-center justify-center text-indigo-400 mb-4">
              <Eye className="w-5 h-5" />
            </div>
            <h3 className="text-xl font-bold text-slate-50 mb-3">Passive Analysis</h3>
            <p className="text-slate-400 leading-relaxed">
              Our passive scan analyzes publicly accessible security signals such as HTTP headers, TLS configuration, and visible security indicators. It does not send exploit payloads or attempt to modify target systems.
            </p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
            <div className="w-10 h-10 rounded-lg border border-indigo-500/30 bg-indigo-500/10 flex items-center justify-center text-indigo-400 mb-4">
              <Shield className="w-5 h-5" />
            </div>
            <h3 className="text-xl font-bold text-slate-50 mb-3">Minimal Impact</h3>
            <p className="text-slate-400 leading-relaxed">
              Passive scans are designed to minimize impact on live websites. The scanning engine generates a limited number of requests similar to normal browsing activity, making it suitable for production environments.
            </p>
          </div>
        </div>
      </section>

      {/* No Exploitation */}
      <section>
        <div className="rounded-3xl border border-slate-800 bg-slate-900 p-8 md:p-12">
          <div className="flex items-start gap-4 mb-6">
            <div className="w-10 h-10 rounded-lg border border-indigo-500/30 bg-indigo-500/10 flex items-center justify-center text-indigo-400 shrink-0">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-3xl font-bold text-slate-50 mb-4">No Exploitation or Destructive Testing</h2>
              <p className="text-slate-400 leading-relaxed mb-6">
                URLScanOnline's scans are explicitly designed to avoid harm to the websites it analyzes.
              </p>
            </div>
          </div>
          <ul className="space-y-4">
            {[
              "Does not intentionally exploit discovered vulnerabilities",
              "Does not inject payloads or malicious content",
              "Does not attempt to modify, delete, or corrupt target data",
              "Does not perform denial-of-service or load testing",
              "Does not attempt to bypass authentication or access controls",
              "Active testing features are clearly labeled and require explicit user action"
            ].map((item, idx) => (
              <li key={idx} className="flex items-start gap-3 text-slate-300">
                <CheckCircle2 className="w-5 h-5 text-indigo-400 shrink-0 mt-0.5" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* How We Protect Scan Data */}
      <section>
        <h2 className="text-3xl font-bold text-slate-50 mb-8 text-center">How We Handle Scan Data</h2>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
          <div className="space-y-4 text-slate-400 leading-relaxed">
            <p>
              Authenticated scan records are associated with the user's account so the user can access Scan History and Saved Reports. Normal application access is owner-scoped, so users cannot browse another user's scan records.

Administrative dashboards use aggregate platform statistics where appropriate and do not provide a general interface for browsing individual users' scan histories.

<div className="pt-2"><Link to="/privacy-policy" className="text-indigo-400 hover:text-indigo-300 font-medium inline-flex items-center gap-1">Read our Privacy Policy &rarr;</Link></div>
            </p>
          </div>
        </div>
      </section>

      {/* Platform Security Practices */}
      <section>
        <h2 className="text-3xl font-bold text-slate-50 mb-8 text-center">Platform Security Practices</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {[
            { title: "Secure Development", desc: "The platform follows secure development practices including input validation, output encoding, and protection against common web vulnerabilities." },
            { title: "Dependency Management", desc: "We monitor and update third-party dependencies to address known security vulnerabilities." },
            { title: "Configuration Security", desc: "Sensitive values such as API keys and credentials are managed through environment-based configuration and are not exposed to the client." },
            { title: "Access Controls", desc: "User authentication is managed through a third-party authentication provider." }
          ].map((item, idx) => (
            <div key={idx} className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
              <h3 className="text-lg font-bold text-slate-50 mb-2">{item.title}</h3>
              <p className="text-sm text-slate-400 leading-relaxed">{item.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Transparency */}
      <section>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
          <div className="flex items-start gap-4 mb-4">
            <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0 mt-1" />
            <h2 className="text-2xl font-bold text-slate-50">Transparency & Limitations</h2>
          </div>
          <ul className="space-y-4 ml-10">
            {[
              "Automated scans can produce false positives (reporting issues that may not exist) and false negatives (missing issues that do exist).",
              "Scan results are informational and should be reviewed in context by qualified personnel.",
              "URLScanOnline does not guarantee that a website is secure or vulnerability-free.",
              "Scan results do not constitute a professional security audit or penetration test."
            ].map((item, idx) => (
              <li key={idx} className="flex items-start gap-3 text-slate-400">
                <div className="w-1.5 h-1.5 rounded-full bg-slate-600 mt-2.5 shrink-0" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* Contact CTA */}
      <section>
        <div className="rounded-2xl border border-indigo-500/30 bg-gradient-to-r from-indigo-950/40 via-slate-900/80 to-slate-900/40 p-8 sm:p-12 text-center">
          <h3 className="text-2xl sm:text-3xl font-bold text-slate-50 tracking-tight mb-4">
            Have security questions?
          </h3>
          <p className="text-sm text-slate-400 leading-relaxed mb-6">
            If you have questions about our security practices or want to report a vulnerability, we'd like to hear from you.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-4">
            <Link
              to="/contact"
              className="rounded-xl bg-indigo-600 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-indigo-600/30 hover:bg-indigo-500 transition-all"
            >
              Contact Us
            </Link>
            <Link
              to="/responsible-disclosure"
              className="rounded-xl border border-slate-700 bg-slate-900/80 px-6 py-3 text-sm font-semibold text-slate-300 hover:text-slate-50 hover:border-slate-600 transition-all"
            >
              Responsible Disclosure
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
};

export default SecurityTrust;
