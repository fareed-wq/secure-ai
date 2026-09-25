import React, { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Shield, ChevronRight } from 'lucide-react';
import OnThisPage from '../components/ui/OnThisPage';
import { useSEO } from '../hooks/useSEO';

const Privacy = () => {
  useSEO({ title: 'Privacy Policy | URLScannerOnline', description: 'Read our Privacy Policy to understand how URLScannerOnline processes and protects your data.', path: '/privacy' });

  const sections = [
    { id: 'who-we-are', label: '1. Who We Are' },
    { id: 'scope', label: '2. Scope' },
    { id: 'information-we-collect', label: '3. Information We Collect' },
    { id: 'information-we-do-not-intentionally-collect', label: '4. Information We Do Not Intentionally Collect' },
    { id: 'how-we-use-information', label: '5. How We Use Information' },
    { id: 'guest-scans', label: '6. Guest Scans' },
    { id: 'accounts-and-scan-history', label: '7. Accounts and Scan History' },
    { id: 'scheduled-scans-and-email-reports', label: '8. Scheduled Scans and Email Reports' },
    { id: 'contact-and-support-requests', label: '9. Contact and Support Requests' },
    { id: 'browser-storage-and-cookies', label: '10. Browser Storage and Cookies' },
    { id: 'third-party-service-providers', label: '11. Third-Party Service Providers' },
    { id: 'international-data-processing-and-transfers', label: '12. International Data Processing and Transfers' },
    { id: 'data-retention', label: '13. Data Retention' },
    { id: 'data-deletion', label: '14. Data Deletion' },
    { id: 'security-measures', label: '15. Security Measures' },
    { id: 'personal-data-incidents-and-breaches', label: '16. Personal Data Incidents and Breaches' },
    { id: 'your-privacy-rights', label: '17. Your Privacy Rights' },
    { id: 'saudi-arabia-specific-information', label: '18. Saudi Arabia-Specific Information' },
    { id: 'india-specific-information', label: '19. India-Specific Information' },
    { id: 'how-to-submit-a-privacy-request-or-grievance', label: '20. How to Submit a Privacy Request or Grievance' },
    { id: 'changes-to-this-privacy-policy', label: '21. Changes to This Privacy Policy' },
    { id: 'contact-information', label: '22. Contact Information' }
  ];


  return (
    <div className="flex-1 w-full max-w-6xl mx-auto p-4 sm:p-6 lg:p-8 overflow-y-auto pb-24">
      <nav className="flex items-center text-sm font-medium text-slate-400 mb-6 space-x-2">
        <Link to="/trust-policy" className="hover:text-indigo-400 transition-colors">Trust & Policy</Link>
        <ChevronRight size={14} className="text-slate-600" />
        <span className="text-slate-200" aria-current="page">Privacy Policy</span>
      </nav>
      <div className="flex flex-col lg:flex-row gap-12 mt-8">
        <div className="flex-1 lg:w-3/4 space-y-12">
          <div className="lg:hidden">
            <OnThisPage sections={sections} />
          </div>

          <section className="relative overflow-hidden rounded-3xl bg-slate-900 border border-slate-800 p-8 md:p-16 text-center mb-8">
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-full max-w-4xl opacity-30 pointer-events-none">
              <div className="absolute inset-0 bg-gradient-to-r from-indigo-500/20 via-purple-500/20 to-blue-500/20 blur-3xl rounded-full transform -translate-y-1/2" />
            </div>
            <div className="relative z-10 max-w-3xl mx-auto">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 text-blue-400 text-sm font-semibold mb-6">
                <Shield className="w-4 h-4" />
                Privacy
              </div>
              <h1 className="text-4xl md:text-5xl lg:text-6xl font-black text-slate-50 mb-6 tracking-tight">
                Privacy Policy for URLScannerOnline
              </h1>
            </div>
          </section>


        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="who-we-are" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">1. Who We Are</h2>
          <p>
            In this policy, &ldquo;we,&rdquo; &ldquo;us,&rdquo; or &ldquo;our&rdquo; refers to URLScannerOnline.
          </p>
          <p>
            Where applicable under privacy laws, we act as the controller, Data Fiduciary, or equivalent responsible entity for personal data processed through our services.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="scope" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">2. Scope</h2>
          <p>
            This Privacy Policy applies to users of URLScannerOnline and describes how we collect, use, process, store, disclose, retain, and delete information associated with the service.
          </p>
          <p>
            It covers guest scans, registered accounts, Scan History, Compare, scheduled scans, email reports, and direct communications.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="information-we-collect" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">3. Information We Collect</h2>
          <p>We may process:</p>

          <h3 className="text-xl font-semibold text-slate-200 mt-6">Account information</h3>
          <ul className="list-disc pl-6 space-y-2">
            <li>email address</li>
            <li>authentication information handled through Supabase</li>
            <li>phone number (mandatory for registration, stored in Supabase Auth, international formats supported and normalized)</li>
            <li>account/user identifier</li>
          </ul>

          <h3 className="text-xl font-semibold text-slate-200 mt-6">Security-scanning information</h3>
          <ul className="list-disc pl-6 space-y-2">
            <li>target URLs submitted for scanning</li>
            <li>scan results</li>
            <li>findings</li>
            <li>technical evidence</li>
            <li>detected technologies</li>
            <li>security-intelligence information</li>
            <li>severity, priority, and scores</li>
            <li>scan timestamps</li>
            <li>scan/report mode information</li>
          </ul>

          <h3 className="text-xl font-semibold text-slate-200 mt-6">Scheduled-scan information</h3>
          <ul className="list-disc pl-6 space-y-2">
            <li>scheduled scan targets</li>
            <li>schedule configuration</li>
            <li>execution status and related metadata</li>
          </ul>

          <h3 className="text-xl font-semibold text-slate-200 mt-6">Contact/support information</h3>
          <ul className="list-disc pl-6 space-y-2">
            <li>name</li>
            <li>email address</li>
            <li>topic</li>
            <li>URL, when provided</li>
            <li>message contents</li>
          </ul>

          <p className="mt-4">
            Some technical information generated by a scan may contain personal data if such information is present in the target website, its responses, headers, content, or related technical material.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="information-we-do-not-intentionally-collect" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">4. Information We Do Not Intentionally Collect</h2>
          <p>
            We do not intentionally request sensitive personal data, financial information, or government identification numbers as part of normal account registration or security scanning.
          </p>
          <p>
            We do not currently operate third-party advertising trackers, marketing analytics pixels, or cross-site tracking software.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="how-we-use-information" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">5. How We Use Information</h2>
          <p>We use information as necessary to:</p>
          <ul className="list-disc pl-6 space-y-2">
            <li>create and maintain user accounts</li>
            <li>deliver a one-time verification code by email during registration to verify your email address</li>
            <li>allow authorized administrators to access account information (including email and phone number) to operate the service</li>
            <li>authenticate users</li>
            <li>perform website security scans</li>
            <li>generate technical reports</li>
            <li>provide Scan History and Compare</li>
            <li>operate scheduled scans</li>
            <li>deliver requested scheduled reports</li>
            <li>respond to support/contact requests</li>
            <li>maintain security, reliability, and operational integrity</li>
            <li>comply with applicable legal obligations where required</li>
          </ul>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="guest-scans" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">6. Guest Scans</h2>
          <p>Guest users may perform unauthenticated scans.</p>
          <p>Guest scan results are not stored as authenticated database history.</p>
          <p>
            Guest scan state may be temporarily stored in browser <code>sessionStorage</code> so the result can survive a page refresh during the browsing session.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="accounts-and-scan-history" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">7. Accounts and Scan History</h2>
          <p>
            Authenticated scan results are stored in the application's Supabase database so users can access Scan History and Compare.
          </p>
          <p>
            Authenticated scan history is protected by application/database access controls and is intended to be accessible only to the authenticated account that owns the scans.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="scheduled-scans-and-email-reports" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">8. Scheduled Scans and Email Reports</h2>
          <p>Authenticated users may configure recurring scans.</p>
          <p>
            Schedule information is stored in the application's database and background scheduling services are used to trigger scheduled jobs.
          </p>
          <p>Completed scheduled scans are stored in the user's Scan History.</p>
          <p>
            When email reporting is enabled, report information may be sent to the user's email address through our email service provider. Generated PDF reports may contain scan findings, technical evidence, and related report information.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="contact-and-support-requests" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">9. Contact and Support Requests</h2>
          <p>
            When you submit a contact or support request, the information you provide is used to review your request, communicate with you, and provide support.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="browser-storage-and-cookies" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">10. Browser Storage and Cookies</h2>
          <p>The application uses browser storage as part of normal operation.</p>
          <ul className="list-disc pl-6 space-y-2">
            <li><code>sessionStorage</code> may store guest scan state.</li>
            <li><code>localStorage</code> may be used by the authentication flow for session-related information.</li>
            <li>Authentication and infrastructure providers may use cookies or similar technologies that are necessary for authentication, security, networking, or service operation.</li>
          </ul>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="third-party-service-providers" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">11. Third-Party Service Providers</h2>
          <p>URLScannerOnline uses service providers that support the operation of the service, including:</p>

          <h3 className="text-xl font-semibold text-slate-200 mt-4">Supabase</h3>
          <ul className="list-disc pl-6 space-y-2">
            <li>authentication</li>
            <li>PostgreSQL database storage</li>
            <li>access-control mechanisms</li>
          </ul>

          <h3 className="text-xl font-semibold text-slate-200 mt-4">Vercel</h3>
          <ul className="list-disc pl-6 space-y-2">
            <li>application hosting</li>
            <li>frontend/backend infrastructure</li>
          </ul>

          <h3 className="text-xl font-semibold text-slate-200 mt-4">Resend</h3>
          <ul className="list-disc pl-6 space-y-2">
            <li>transactional email (including one-time verification codes)</li>
            <li>scheduled scan report delivery</li>
          </ul>

          <h3 className="text-xl font-semibold text-slate-200 mt-4">Upstash/QStash</h3>
          <ul className="list-disc pl-6 space-y-2">
            <li>background job orchestration</li>
            <li>scheduled scan triggering</li>
          </ul>

          <p className="mt-4">
            These providers process information only as necessary for the services they provide to URLScannerOnline, subject to their applicable agreements, privacy practices, and security measures.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="international-data-processing-and-transfers" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">12. International Data Processing and Transfers</h2>
          <p>
            URLScannerOnline uses cloud and service providers that may process information outside your country of residence, including outside Saudi Arabia and India.
          </p>
          <p>
            Where personal data is transferred internationally, we seek to use transfer mechanisms and safeguards required by applicable data-protection laws.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="data-retention" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">13. Data Retention</h2>
          <p>
            For authenticated accounts, scan results are retained while the account remains active because Scan History and Compare are ongoing features of the service. Your phone number is stored in Supabase Auth and remains associated with your active account until account deletion or another legitimate deletion process applies.
          </p>
          <p>
            Users may delete individual scans, selected scans, or all scan history through the available account controls.
          </p>
          <p>Users may also permanently delete their account.</p>
          <p>
            We may retain limited records where retention is required or permitted by applicable law, or where necessary for legitimate operational, security, dispute-resolution, or legal purposes.
          </p>
          <p>
            Third-party providers may retain limited logs, backups, or transactional records according to their own applicable policies and contractual arrangements.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="data-deletion" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">14. Data Deletion</h2>
          <p>Users can:</p>
          <ul className="list-disc pl-6 space-y-2">
            <li>delete individual scans</li>
            <li>delete selected scans</li>
            <li>delete all scan history</li>
            <li>permanently delete their account</li>
          </ul>
          <p>
            Account deletion removes the associated authentication account (including your phone number) and the user's remaining application-owned account data through the application's account-deletion and database cascade cleanup mechanisms.
          </p>
          <p>
            Third-party provider records, backups, security logs, or transactional records may remain subject to those providers' applicable retention policies and legal obligations.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="security-measures" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">15. Security Measures</h2>
          <p>
            We use technical and organizational measures designed to protect information, including where applicable:
          </p>
          <ul className="list-disc pl-6 space-y-2">
            <li>HTTPS/TLS for data in transit</li>
            <li>authenticated access</li>
            <li>JWT-based authentication</li>
            <li>database Row-Level Security</li>
            <li>user-scoped access controls</li>
            <li>server-side handling of privileged credentials</li>
          </ul>
          <p>No system can guarantee absolute security.</p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="personal-data-incidents-and-breaches" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">16. Personal Data Incidents and Breaches</h2>
          <p>
            We maintain procedures for assessing and responding to suspected security incidents.
          </p>
          <p>
            Where applicable law requires notification following a personal-data breach, we will take steps to notify affected individuals and relevant authorities within the applicable legal requirements.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="your-privacy-rights" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">17. Your Privacy Rights</h2>
          <p>
            Depending on your jurisdiction and applicable law, you may have rights concerning your personal data, including rights to:
          </p>
          <ul className="list-disc pl-6 space-y-2">
            <li>obtain information about processing</li>
            <li>access or obtain information about personal data</li>
            <li>request correction of inaccurate data</li>
            <li>request deletion or erasure where applicable</li>
            <li>exercise other rights provided by applicable law</li>
            <li>submit privacy-related complaints or grievances</li>
          </ul>
          <p>
            Some rights can be exercised directly through account controls, while other requests may be submitted through our privacy contact channel.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="saudi-arabia-specific-information" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">18. Saudi Arabia-Specific Information</h2>
          <p>
            For users subject to the Saudi Personal Data Protection Law and applicable regulations:
          </p>
          <p>
            We provide information about our processing activities through this Privacy Policy and support applicable data-subject rights in accordance with the law.
          </p>
          <p>
            Personal data (including collected phone numbers and emails) may be processed outside Saudi Arabia through our service providers. International transfers are handled subject to applicable Saudi requirements and safeguards.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="india-specific-information" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">19. India-Specific Information</h2>
          <p>
            For users subject to India's Digital Personal Data Protection Act, 2023 and applicable rules:
          </p>
          <p>
            URLScannerOnline may act as a Data Fiduciary and relevant service providers may act as Data Processors, where those terms apply.
          </p>
          <p>
            Privacy and data-protection obligations may apply according to the scope and commencement of the applicable provisions.
          </p>
          <p>
            Users may exercise applicable Data Principal rights and use our grievance/privacy contact mechanism.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="how-to-submit-a-privacy-request-or-grievance" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">20. How to Submit a Privacy Request or Grievance</h2>
          <p>
            For privacy requests, questions, or grievances, contact:
          </p>
          <p>
            <code>contact@urlscanonline.com</code>
          </p>
          <p>
            Requests will be handled according to applicable law and the information reasonably necessary to verify and process the request.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="changes-to-this-privacy-policy" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">21. Changes to This Privacy Policy</h2>
          <p>
            We may update this Privacy Policy when our services, processing practices, service providers, or applicable legal requirements change.
          </p>
            </div>
          </section>

        <section>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 space-y-4 text-slate-400 leading-relaxed">
              <h2 id="contact-information" className="text-2xl font-bold text-slate-50 mb-4 scroll-mt-24">22. Contact Information</h2>
          <p><strong>Email:</strong> <code>contact@urlscanonline.com</code></p>
            </div>

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

export default Privacy;
