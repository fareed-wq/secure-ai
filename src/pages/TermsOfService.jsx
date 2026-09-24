import React, { useEffect } from 'react';
import { ArrowLeft, FileText, Shield, AlertTriangle, ChevronRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import OnThisPage from '../components/ui/OnThisPage';
import { useSEO } from '../hooks/useSEO';

const TermsOfService = () => {
  useSEO({ title: 'Terms of Service | URLScannerOnline', description: 'Read the terms governing the use of URLScannerOnline and our scanning rules of engagement.', path: '/terms' });

  const sections = [
    { id: 'acceptance', label: '1. Acceptance of Terms' },
    { id: 'who-we-are', label: '2. Who We Are' },
    { id: 'service-description', label: '3. Service Description' },
    { id: 'authorization', label: '4. Authorization Requirement' },
    { id: 'acceptable-use', label: '5. Acceptable Use' },
    { id: 'accounts', label: '6. User Accounts' },
    { id: 'submitted-info', label: '7. Submitted Information' },
    { id: 'intellectual-property', label: '8. Intellectual Property' },
    { id: 'third-party', label: '9. Third-Party Services' },
    { id: 'availability', label: '10. Service Availability' },
    { id: 'termination', label: '11. Suspension and Termination' },
    { id: 'disclaimer', label: '12. Scan Accuracy Disclaimer' },
    { id: 'liability', label: '13. Limitation of Liability' },
    { id: 'governing-law', label: '14. Governing Law' },
    { id: 'changes', label: '15. Changes to Terms' }
  ];

  return (
    <div className="flex-1 w-full max-w-6xl mx-auto p-4 sm:p-6 lg:p-8 overflow-y-auto pb-24">
      <nav className="flex items-center text-sm font-medium text-slate-400 mb-6 space-x-2">
        <Link to="/trust-policy" className="hover:text-indigo-400 transition-colors">Trust & Policy</Link>
        <ChevronRight size={14} className="text-slate-600" />
        <span className="text-slate-200" aria-current="page">Terms of Service</span>
      </nav>
      <div className="flex flex-col lg:flex-row gap-12 mt-8">
        <div className="flex-1 lg:w-3/4 space-y-12">
          <div className="lg:hidden">
            <OnThisPage sections={sections} />
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
                Please read these terms carefully before using URLScannerOnline.
              </p>

            </div>
          </section>

          {/* Acceptance of Terms */}
          <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
              <h2 id="acceptance" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">1. Acceptance of Terms</h2>
              <p className="text-slate-400 leading-relaxed">
                By accessing or using URLScannerOnline, you agree to be bound by these Terms of Service. If you do not agree to these terms, do not use the service.
              </p>
            </div>
          </section>

          {/* Who We Are */}
          <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
              <h2 id="who-we-are" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">2. Who We Are</h2>
              <p className="text-slate-400 leading-relaxed">
                In these terms, "we," "us," or "our" refers to URLScannerOnline.
              </p>
            </div>
          </section>

          {/* Service Description */}
          <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
              <h2 id="service-description" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">3. Service Description</h2>
              <p className="text-slate-400 leading-relaxed">
                URLScannerOnline provides automated website security scanning and assessment services. The service provides basic passive scanning and advanced bounded low-impact checks, reporting on security findings, scores, and severity levels.
              </p>
              <p className="text-slate-400 leading-relaxed mt-4">
                Supported features include unauthenticated guest scans, authenticated user accounts, Scan History, Compare functionality, scheduled scans, and email or PDF security reports.
              </p>
              <p className="text-slate-400 leading-relaxed mt-4">
                Use of personal and scan-related data is also governed by our <Link to="/privacy" className="text-indigo-400 hover:text-indigo-300">Privacy Policy</Link>.
              </p>
            </div>
          </section>

          {/* Authorization Requirement */}
          <section>
            <div className="rounded-2xl border border-indigo-500/30 bg-slate-900/50 p-8">
              <div className="flex items-start gap-4 mb-4">
                <div className="w-10 h-10 rounded-lg border border-indigo-500/30 bg-indigo-500/10 flex items-center justify-center text-indigo-400 shrink-0">
                  <Shield className="w-5 h-5" />
                </div>
                <h2 id="authorization" className="text-2xl font-bold text-slate-50 scroll-mt-24">4. Authorization Requirement</h2>
              </div>
              <div className="space-y-4 text-slate-400 leading-relaxed ml-14">
                <p className="font-medium text-slate-300">
                  You must only scan websites and systems that you own or have explicit written authorization to assess.
                </p>
                <p>
                  Scanning websites without proper authorization may violate applicable laws and regulations, including computer fraud and abuse statutes. You are solely responsible for ensuring that you have the necessary rights and permissions before initiating any scan.
                </p>
                <p>
                  URLScannerOnline is not responsible for any unauthorized use of the scanning service by its users.
                </p>
              </div>
            </div>
          </section>

          {/* Acceptable Use */}
          <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
              <h2 id="acceptable-use" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">5. Acceptable Use</h2>
              <p className="text-slate-400 leading-relaxed mb-4">
                You agree to use URLScannerOnline for legitimate security assessment purposes only. You must not:
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
                  "Use URLScannerOnline to facilitate attacks, unauthorized access, or harmful activity against third-party systems"
                ].map((item, idx) => (
                  <li key={idx} className="flex items-start gap-3">
                    <div className="w-1.5 h-1.5 rounded-full bg-slate-600 mt-2.5 shrink-0" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </section>

          {/* User Accounts */}
          <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
              <h2 id="accounts" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">6. User Accounts</h2>
              <p className="text-slate-400 leading-relaxed mb-4">
                As a user of URLScannerOnline, you are responsible for:
              </p>
              <ul className="space-y-3 text-slate-400">
                {[
                  "Providing accurate and complete registration information",
                  "Maintaining the confidentiality and security of your account credentials",
                  "All activity that occurs under your account",
                  "Notifying us immediately of any suspected unauthorized access",
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

          {/* Submitted Information */}
          <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
              <h2 id="submitted-info" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">7. Submitted Information</h2>
              <p className="text-slate-400 leading-relaxed mb-4">
                You retain ownership of any target URLs, scan requests, or support submissions you provide to URLScannerOnline. You are responsible for ensuring you have the necessary rights and authorizations to submit this information.
              </p>
              <p className="text-slate-400 leading-relaxed">
                By submitting information, you grant URLScannerOnline the limited rights reasonably necessary to perform the requested service, operate the platform, and provide scan reports. For information on our privacy and data processing practices, please see our <Link to="/privacy" className="text-indigo-400 hover:text-indigo-300">Privacy Policy</Link>.
              </p>
            </div>
          </section>

          {/* Intellectual Property */}
          <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
              <h2 id="intellectual-property" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">8. Intellectual Property</h2>
              <p className="text-slate-400 leading-relaxed mb-4">
                The URLScannerOnline software, platform, branding, and original materials are protected by applicable intellectual property laws and remain the exclusive property of URLScannerOnline.
              </p>
              <p className="text-slate-400 leading-relaxed">
                We do not claim ownership of the contents of third-party target websites, nor do we claim ownership of your user-submitted information merely because it was processed by our service.
              </p>
            </div>
          </section>

          {/* Third-Party Services */}
          <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
              <h2 id="third-party" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">9. Third-Party Services</h2>
              <p className="text-slate-400 leading-relaxed">
                URLScannerOnline relies on third-party infrastructure providers to operate the service, including Supabase, Vercel, Resend, and Upstash/QStash.
              </p>
            </div>
          </section>

          {/* Service Availability */}
          <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
              <h2 id="availability" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">10. Service Availability</h2>
              <p className="text-slate-400 leading-relaxed">
                While we strive to provide reliable service, URLScannerOnline's availability is not guaranteed to be uninterrupted. Outages or maintenance may occur. We reserve the right to modify, add, or remove features at any time. We may also suspend or limit the service where reasonably necessary for security, maintenance, abuse prevention, or legal reasons.
              </p>
            </div>
          </section>

          {/* Suspension and Termination */}
          <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
              <h2 id="termination" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">11. Suspension and Termination</h2>
              <p className="text-slate-400 leading-relaxed mb-4">
                You may stop using URLScannerOnline and delete your account at any time. Account deletion will remove your remaining application-owned data in accordance with our <Link to="/privacy" className="text-indigo-400 hover:text-indigo-300">Privacy Policy</Link>.
              </p>
              <p className="text-slate-400 leading-relaxed">
                We reserve the right to suspend or terminate your access to the service if we reasonably believe you have violated these Terms, engaged in unauthorized or abusive activity, or to comply with legal requirements.
              </p>
            </div>
          </section>

          {/* Scan Accuracy Disclaimer */}
          <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
              <div className="flex items-start gap-4 mb-4">
                <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0 mt-1" />
                <h2 id="disclaimer" className="text-2xl font-bold text-slate-50 scroll-mt-24">12. Scan Accuracy Disclaimer</h2>
              </div>
              <div className="space-y-4 text-slate-400 leading-relaxed">
                <p>
                  Automated security scans can produce <strong className="text-slate-300">false positives</strong> (reporting issues that may not exist) and <strong className="text-slate-300">false negatives</strong> (missing issues that do exist).
                </p>
                <p>
                  Scan results are informational and do not constitute a professional security audit, penetration test, or compliance assessment. URLScannerOnline does not guarantee that any website is secure or vulnerability-free.
                </p>
                <p>
                  Results should be reviewed by qualified personnel and considered alongside other security measures appropriate to your environment. You are responsible for interpreting and taking appropriate action on identified security issues.
                </p>
              </div>
            </div>
          </section>

          {/* Limitation of Liability */}
          <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
              <h2 id="liability" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">13. Limitation of Liability</h2>
              <div className="space-y-4 text-slate-400 leading-relaxed">
                <p>
                  URLScannerOnline is provided <strong className="text-slate-300">"as is"</strong> and <strong className="text-slate-300">"as available"</strong> without warranties of any kind, whether express or implied. To the fullest extent permitted by law, we are not liable for:
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

          {/* Governing Law */}
          <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
              <h2 id="governing-law" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">14. Governing Law and Jurisdiction</h2>
              <p className="text-slate-400 leading-relaxed">
                These Terms are subject to applicable law and any mandatory rights or protections that apply to you under the laws of your place of residence.
              </p>
            </div>
          </section>

          {/* Changes to Terms */}
          <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
              <h2 id="changes" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">15. Changes to Terms</h2>
              <p className="text-slate-400 leading-relaxed">
                We may update these Terms of Service from time to time. Continued use of the service after changes are posted constitutes acceptance of the updated terms.
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
        <div className="hidden lg:block lg:w-1/4">
          <div className="sticky top-8">
            <OnThisPage sections={sections} />
          </div>
        </div>
      </div>
    </div>
  );
};

export default TermsOfService;
