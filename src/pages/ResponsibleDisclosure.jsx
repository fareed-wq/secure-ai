import React, { useEffect } from 'react';
import { ArrowLeft, Shield, Mail, CheckCircle2, Search } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useSEO } from '../hooks/useSEO';

const ResponsibleDisclosure = () => {
  useSEO({ title: 'Responsible Disclosure | URLScanOnline', description: 'Information for security researchers on how to report vulnerabilities in our platform.', path: '/responsible-disclosure' });

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
            Security
          </div>
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-black text-slate-50 mb-6 tracking-tight">
            Responsible Disclosure
          </h1>
          <p className="text-lg md:text-xl text-slate-400 leading-relaxed">
            We value the security research community and welcome reports of vulnerabilities found in URLScanOnline.
          </p>
        </div>
      </section>

      {/* Reporting a Vulnerability */}
      <section>
        <div className="rounded-3xl border border-slate-800 bg-slate-900 p-8 md:p-12">
          <div className="flex items-start gap-4 mb-6">
            <div className="w-10 h-10 rounded-lg border border-indigo-500/30 bg-indigo-500/10 flex items-center justify-center text-indigo-400 shrink-0">
              <Mail className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-3xl font-bold text-slate-50 mb-4">Reporting a Vulnerability</h2>
              <p className="text-slate-400 leading-relaxed mb-4">
                If you discover a security vulnerability in URLScanOnline (the platform itself, not in websites scanned by the tool), we encourage you to report it responsibly.
              </p>
            </div>
          </div>

          <div className="bg-slate-950 rounded-2xl border border-slate-800 p-6 mb-6">
            <p className="text-slate-300 font-medium mb-2">Security contact:</p>
            <a href="mailto:contact@urlscanonline.com" className="text-indigo-400 hover:underline underline-offset-2 text-lg font-semibold">
              contact@urlscanonline.com
            </a>
            <p className="text-sm text-slate-500 mt-2">
              Please include "Security Vulnerability" in the subject line.
            </p>
          </div>

          <div>
            <p className="text-slate-400 leading-relaxed mb-4">When reporting, please include:</p>
            <ul className="space-y-3">
              {[
                "A clear description of the vulnerability",
                "Steps to reproduce the issue",
                "Potential impact or severity assessment",
                "Your contact information for follow-up"
              ].map((item, idx) => (
                <li key={idx} className="flex items-start gap-3 text-slate-300">
                  <CheckCircle2 className="w-5 h-5 text-indigo-400 shrink-0 mt-0.5" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      {/* What We Ask */}
      <section>
        <h2 className="text-3xl font-bold text-slate-50 mb-8 text-center">What We Ask</h2>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
          <ul className="space-y-4 text-slate-400 leading-relaxed">
            {[
              "Do not publicly disclose the vulnerability before we have had a reasonable opportunity to investigate and address it.",
              "Do not access, modify, or delete data belonging to other users.",
              "Do not perform testing that could disrupt the service for other users.",
              "Act in good faith and avoid actions that could cause harm to URLScanOnline or its users."
            ].map((item, idx) => (
              <li key={idx} className="flex items-start gap-3">
                <div className="w-1.5 h-1.5 rounded-full bg-slate-600 mt-2.5 shrink-0" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* Our Response Process */}
      <section>
        <h2 className="text-3xl font-bold text-slate-50 mb-8 text-center">Our Response Process</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {[
            { step: "1", title: "Acknowledgment", desc: "We will acknowledge receipt of your report within a reasonable timeframe." },
            { step: "2", title: "Investigation", desc: "We will investigate and assess the reported vulnerability to determine its validity and impact." },
            { step: "3", title: "Remediation", desc: "We will work to address confirmed vulnerabilities in a timely manner." },
            { step: "4", title: "Communication", desc: "We will keep you informed of our progress where possible and appropriate." }
          ].map((item, idx) => (
            <div key={idx} className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
              <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400 text-sm font-bold mb-4">
                {item.step}
              </div>
              <h3 className="text-lg font-bold text-slate-50 mb-2">{item.title}</h3>
              <p className="text-sm text-slate-400 leading-relaxed">{item.desc}</p>
            </div>
          ))}
        </div>
        <p className="text-sm text-slate-500 text-center mt-6">
          We do not currently operate a formal bug bounty program, but we appreciate and acknowledge responsible security research.
        </p>
      </section>

      {/* Scope */}
      <section>
        <h2 className="text-3xl font-bold text-slate-50 mb-8 text-center">Scope</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
            <div className="flex items-center gap-3 mb-4">
              <Search className="w-5 h-5 text-indigo-400" />
              <h3 className="text-xl font-bold text-slate-50">In Scope</h3>
            </div>
            <ul className="space-y-3 text-slate-400">
              {[
                "URLScanOnline web application",
                "API endpoints",
                "Authentication and authorization mechanisms"
              ].map((item, idx) => (
                <li key={idx} className="flex items-start gap-3">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
            <div className="flex items-center gap-3 mb-4">
              <Shield className="w-5 h-5 text-slate-500" />
              <h3 className="text-xl font-bold text-slate-50">Out of Scope</h3>
            </div>
            <ul className="space-y-3 text-slate-400">
              {[
                "Third-party services and integrations",
                "Social engineering attacks",
                "Physical security",
                "Denial-of-service testing"
              ].map((item, idx) => (
                <li key={idx} className="flex items-start gap-3">
                  <div className="w-1.5 h-1.5 rounded-full bg-slate-600 mt-2.5 shrink-0" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      {/* Contact */}
      <section>
        <div className="rounded-2xl border border-indigo-500/30 bg-gradient-to-r from-indigo-950/40 via-slate-900/80 to-slate-900/40 p-8 sm:p-12 text-center">
          <h3 className="text-2xl sm:text-3xl font-bold text-slate-50 tracking-tight mb-4">
            Ready to report?
          </h3>
          <p className="text-sm text-slate-400 leading-relaxed mb-6">
            Send security reports to{' '}
            <a href="mailto:contact@urlscanonline.com" className="text-indigo-400 hover:underline underline-offset-2">
              contact@urlscanonline.com
            </a>
          </p>
          <Link
            to="/contact"
            className="rounded-xl border border-slate-700 bg-slate-900/80 px-6 py-3 text-sm font-semibold text-slate-300 hover:text-slate-50 hover:border-slate-600 transition-all inline-block"
          >
            General Inquiries
          </Link>
        </div>
      </section>
    </div>
  );
};

export default ResponsibleDisclosure;
