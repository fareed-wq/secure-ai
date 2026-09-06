import React, { useEffect } from 'react';
import { ArrowLeft, FileText, Shield, AlertTriangle } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useSEO } from '../hooks/useSEO';

const TermsOfService = () => {
  useSEO({ title: 'Terms of Service | URLScanOnline', description: 'Read the terms governing the use of URLScanOnline and our scanning rules of engagement.', path: '/terms' });

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
            <FileText className="w-4 h-4" />
            Legal
          </div>
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-black text-slate-50 mb-6 tracking-tight">
            Terms of Service
          </h1>
          <p className="text-lg md:text-xl text-slate-400 leading-relaxed">
            Please read these terms carefully before using URLScanOnline.
          </p>
          <p className="text-sm text-slate-500 mt-4">Last updated: August 2026</p>
        </div>
      </section>

      {/* Acceptance of Terms */}
      <section>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
          <h2 className="text-2xl font-bold text-slate-50 mb-4">1. Acceptance of Terms</h2>
          <p className="text-slate-400 leading-relaxed">
            By accessing or using URLScanOnline, you agree to be bound by these Terms of Service. If you do not agree to these terms, do not use the service.
          </p>
        </div>
      </section>

      {/* Service Description */}
      <section>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
          <h2 className="text-2xl font-bold text-slate-50 mb-4">2. Service Description</h2>
          <p className="text-slate-400 leading-relaxed">
            URLScanOnline provides automated website security scanning and assessment services. The service provides Basic passive scanning, Advanced bounded low-impact checks, and manual security testing only under explicit authorization and separate scope.
            </p>
            <p className="text-slate-400 leading-relaxed mt-4">
              Use of personal and scan-related data is also governed by our <Link to="/privacy-policy" className="text-indigo-400 hover:text-indigo-300">Privacy Policy</Link>.
          </p>
        </div>
      </section>

      {/* Authorization Requirement - highlighted */}
      <section>
        <div className="rounded-2xl border border-indigo-500/30 bg-slate-900/50 p-8">
          <div className="flex items-start gap-4 mb-4">
            <div className="w-10 h-10 rounded-lg border border-indigo-500/30 bg-indigo-500/10 flex items-center justify-center text-indigo-400 shrink-0">
              <Shield className="w-5 h-5" />
            </div>
            <h2 className="text-2xl font-bold text-slate-50">3. Authorization Requirement</h2>
          </div>
          <div className="space-y-4 text-slate-400 leading-relaxed ml-14">
            <p className="font-medium text-slate-300">
              You must only scan websites and systems that you own or have explicit written authorization to assess.
            </p>
            <p>
              Scanning websites without proper authorization may violate applicable laws and regulations, including computer fraud and abuse statutes. You are solely responsible for ensuring that you have the necessary rights and permissions before initiating any scan.
            </p>
            <p>
              URLScanOnline is not responsible for any unauthorized use of the scanning service by its users.
            </p>
          </div>
        </div>
      </section>

      {/* Acceptable Use */}
      <section>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
          <h2 className="text-2xl font-bold text-slate-50 mb-4">4. Acceptable Use</h2>
          <p className="text-slate-400 leading-relaxed mb-4">
            You agree to use URLScanOnline for legitimate security assessment purposes only. You must not:
          </p>
          <ul className="space-y-3 text-slate-400">
            {[
              "Scan systems or websites without proper authorization",
              "Attempt to disrupt, overload, or interfere with the service",
              "Reverse-engineer, decompile, or disassemble the scanning engine",
              "Resell or redistribute scan results commercially without permission",
              "Use scan results to exploit vulnerabilities discovered in target websites",
              "Use the service in any manner that violates applicable laws or regulations",
              "Attempt to obtain passwords, authentication tokens, or other credentials through credential theft or harvesting",
              "Distribute malware or malicious content through the use of the service",
              "Use URLScanOnline to facilitate attacks, unauthorized access, or harmful activity against third-party systems"
            ].map((item, idx) => (
              <li key={idx} className="flex items-start gap-3">
                <div className="w-1.5 h-1.5 rounded-full bg-slate-600 mt-2.5 shrink-0" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* User Responsibilities */}
      <section>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
          <h2 className="text-2xl font-bold text-slate-50 mb-4">5. User Responsibilities</h2>
          <p className="text-slate-400 leading-relaxed mb-4">
            As a user of URLScanOnline, you are responsible for:
          </p>
          <ul className="space-y-3 text-slate-400">
            {[
              "Ensuring you have authorization to scan any target website or system",
              "Reviewing scan results in context and with appropriate judgment",
              "Taking appropriate action on identified security issues",
              "Maintaining the confidentiality of your account credentials",
              "Complying with all applicable laws and regulations in your jurisdiction"
            ].map((item, idx) => (
              <li key={idx} className="flex items-start gap-3">
                <div className="w-1.5 h-1.5 rounded-full bg-slate-600 mt-2.5 shrink-0" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* Scan Accuracy Disclaimer */}
      <section>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
          <div className="flex items-start gap-4 mb-4">
            <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0 mt-1" />
            <h2 className="text-2xl font-bold text-slate-50">6. Scan Accuracy Disclaimer</h2>
          </div>
          <div className="space-y-4 text-slate-400 leading-relaxed">
            <p>
              Automated security scans can produce <strong className="text-slate-300">false positives</strong> (reporting issues that may not exist) and <strong className="text-slate-300">false negatives</strong> (missing issues that do exist).
            </p>
            <p>
              Scan results are informational and do not constitute a professional security audit, penetration test, or compliance assessment. URLScanOnline does not guarantee that any website is secure or vulnerability-free.
            </p>
            <p>
              Results should be reviewed by qualified personnel and considered alongside other security measures appropriate to your environment.
            </p>
          </div>
        </div>
      </section>

      {/* Limitation of Liability */}
      <section>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
          <h2 className="text-2xl font-bold text-slate-50 mb-4">7. Limitation of Liability</h2>
          <div className="space-y-4 text-slate-400 leading-relaxed">
            <p>
              URLScanOnline is provided <strong className="text-slate-300">"as is"</strong> and <strong className="text-slate-300">"as available"</strong> without warranties of any kind, whether express or implied. To the fullest extent permitted by law, we are not liable for:
            </p>
            <ul className="space-y-3">
              {[
                "Actions taken or not taken based on scan results",
                "Damages arising from use of or inability to use the service",
                "Inaccuracies, errors, or omissions in scan results",
                "Service interruptions, downtime, or data loss",
                "Unauthorized access resulting from user credential compromise"
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

      {/* Changes to Terms */}
      <section>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
          <h2 className="text-2xl font-bold text-slate-50 mb-4">8. Changes to Terms</h2>
          <p className="text-slate-400 leading-relaxed">
            We may update these Terms of Service from time to time. Changes will be reflected by updating the "Last updated" date at the top of this page. Continued use of the service after changes are posted constitutes acceptance of the updated terms.
          </p>
        </div>
      </section>

      {/* Contact */}
      <section className="max-w-4xl mx-auto px-4 md:px-0 text-center">
        <p className="text-slate-400">
          Questions about these terms? Reach us at{' '}
          <a href="mailto:contact@urlscanonline.com" className="text-indigo-400 hover:underline underline-offset-2">
            contact@urlscanonline.com
          </a>
        </p>
      </section>
    </div>
  );
};

export default TermsOfService;
