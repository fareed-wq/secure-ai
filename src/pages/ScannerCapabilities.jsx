import React from 'react';
import { ChevronRight, History, CalendarClock, ArrowRightLeft } from 'lucide-react';
import { useSEO } from '../hooks/useSEO';
import { Link } from 'react-router-dom';

const ScannerCapabilities = () => {
  useSEO({
    title: 'Website Security Scanner Capabilities | URLScanOnline',
    description: 'Compare URLScanOnline Basic and Advanced website security scans, including security checks, scan history, comparison tools and upcoming scheduled scans.',
    path: '/services/scanner-capabilities'
  });

  return (
    <div className="space-y-12 pb-12 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-8">

      {/* BREADCRUMB */}
      <nav className="flex items-center text-sm font-medium text-slate-400 mb-6 space-x-2">
        <Link to="/services" className="hover:text-indigo-400 transition-colors">Services</Link>
        <ChevronRight size={14} className="text-slate-600" />
        <span className="text-slate-200">Scanner Capabilities</span>
      </nav>

      {/* SECTION 1: SCANNER CAPABILITIES */}
      <section className="relative overflow-hidden rounded-3xl bg-slate-900 border border-slate-800 p-8 md:p-12 lg:p-16">
        <div className="relative z-10">
          <div className="mb-10">
            <h1 className="text-4xl md:text-5xl font-black text-slate-50 mb-6 tracking-tight">
              Scanner Capabilities
            </h1>
            <p className="text-lg text-slate-400 max-w-3xl leading-relaxed">
              Compare our Basic and Advanced scanning modes, review past results, compare
              security changes over time, and understand when deeper manual security testing
              may be appropriate.
            </p>
            <p className="mt-4 text-slate-400 max-w-3xl leading-relaxed">
              URLScanOnline is designed as a passive-first, low-impact security scanner.
              Basic scans focus on passive observations, while Advanced scans perform
              additional bounded, non-destructive checks. The scanner does not exploit
              vulnerabilities, brute-force credentials, or perform destructive testing.
            </p>
          </div>

          {/* BASIC VS ADVANCED COMPARISON */}
          <div className="mb-12 overflow-x-auto border border-slate-800 rounded-2xl bg-slate-950/50">
            <table className="w-full text-left border-collapse min-w-[600px]">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950">
                  <th className="py-4 px-6 text-slate-200 font-semibold w-1/2">Capability</th>
                  <th className="py-4 px-6 text-slate-200 font-semibold text-center">Basic Scan</th>
                  <th className="py-4 px-6 text-indigo-300 font-semibold text-center bg-indigo-900/10">Advanced Scan</th>
                </tr>
              </thead>
              <tbody className="text-slate-400 text-sm">
                <tr className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                  <td className="py-3 px-6">HTTP Security Headers</td>
                  <td className="py-3 px-6 text-center text-emerald-400">✓</td>
                  <td className="py-3 px-6 text-center text-emerald-400 bg-indigo-900/10">✓</td>
                </tr>
                <tr className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                  <td className="py-3 px-6">Cookie & Session Security</td>
                  <td className="py-3 px-6 text-center text-emerald-400">✓</td>
                  <td className="py-3 px-6 text-center text-emerald-400 bg-indigo-900/10">✓</td>
                </tr>
                <tr className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                  <td className="py-3 px-6">Content Security Policy (CSP) Analysis</td>
                  <td className="py-3 px-6 text-center text-emerald-400">✓</td>
                  <td className="py-3 px-6 text-center text-emerald-400 bg-indigo-900/10">✓</td>
                </tr>
                <tr className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                  <td className="py-3 px-6">Technology Fingerprinting</td>
                  <td className="py-3 px-6 text-center text-emerald-400">✓</td>
                  <td className="py-3 px-6 text-center text-emerald-400 bg-indigo-900/10">✓</td>
                </tr>
                <tr className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                  <td className="py-3 px-6">Mixed Content Detection</td>
                  <td className="py-3 px-6 text-center text-emerald-400">✓</td>
                  <td className="py-3 px-6 text-center text-emerald-400 bg-indigo-900/10">✓</td>
                </tr>
                <tr className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                  <td className="py-3 px-6">Information Exposure</td>
                  <td className="py-3 px-6 text-center text-emerald-400">✓</td>
                  <td className="py-3 px-6 text-center text-emerald-400 bg-indigo-900/10">Enhanced</td>
                </tr>
                <tr className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                  <td className="py-3 px-6">TLS / HTTPS Security</td>
                  <td className="py-3 px-6 text-center text-slate-600">—</td>
                  <td className="py-3 px-6 text-center text-emerald-400 bg-indigo-900/10">✓</td>
                </tr>
                <tr className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                  <td className="py-3 px-6">DNS & Email Security</td>
                  <td className="py-3 px-6 text-center text-slate-600">—</td>
                  <td className="py-3 px-6 text-center text-emerald-400 bg-indigo-900/10">✓</td>
                </tr>
                <tr className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                  <td className="py-3 px-6">CORS Configuration</td>
                  <td className="py-3 px-6 text-center text-slate-600">—</td>
                  <td className="py-3 px-6 text-center text-emerald-400 bg-indigo-900/10">✓</td>
                </tr>
                <tr className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                  <td className="py-3 px-6">API / Application Surface</td>
                  <td className="py-3 px-6 text-center text-slate-600">—</td>
                  <td className="py-3 px-6 text-center text-emerald-400 bg-indigo-900/10">✓</td>
                </tr>
                <tr className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                  <td className="py-3 px-6">Sensitive File Exposure</td>
                  <td className="py-3 px-6 text-center text-slate-600">—</td>
                  <td className="py-3 px-6 text-center text-emerald-400 bg-indigo-900/10">✓</td>
                </tr>
                <tr className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                  <td className="py-3 px-6">Subdomain / Infrastructure Discovery</td>
                  <td className="py-3 px-6 text-center text-slate-600">—</td>
                  <td className="py-3 px-6 text-center text-emerald-400 bg-indigo-900/10">✓</td>
                </tr>
                <tr className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                  <td className="py-3 px-6">robots.txt / sitemap / security.txt</td>
                  <td className="py-3 px-6 text-center text-slate-600">—</td>
                  <td className="py-3 px-6 text-center text-emerald-400 bg-indigo-900/10">✓</td>
                </tr>
                <tr className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                  <td className="py-3 px-6">JavaScript / Client-Side Security</td>
                  <td className="py-3 px-6 text-center text-slate-600">—</td>
                  <td className="py-3 px-6 text-center text-emerald-400 bg-indigo-900/10">✓</td>
                </tr>
                <tr className="hover:bg-slate-800/20 transition-colors">
                  <td className="py-3 px-6">Network Service Exposure</td>
                  <td className="py-3 px-6 text-center text-slate-600">—</td>
                  <td className="py-3 px-6 text-center text-emerald-400 bg-indigo-900/10">✓</td>
                </tr>
              </tbody>
            </table>
          </div>

          {/* FEATURE CARDS */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
            {/* Scan History */}
            <div className="bg-slate-950/50 border border-slate-800 rounded-xl p-6 hover:border-indigo-500/50 transition-colors flex flex-col">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-indigo-500/10 rounded-lg text-indigo-400">
                  <History size={20} />
                </div>
                <h3 className="text-lg font-bold text-slate-50">Scan History</h3>
              </div>
              <p className="text-slate-400 text-sm leading-relaxed flex-1">
                Keep track of previous security scans. Review earlier results, revisit
                findings, and see how scan results change as configurations are updated.
              </p>
              <div className="mt-6 pt-4 border-t border-slate-800 flex items-center text-xs font-mono text-slate-500 uppercase">
                Find it in:
                <span className="ml-2 text-indigo-400 flex items-center">
                  Dashboard <ChevronRight size={12} className="mx-1" /> View Scan History
                </span>
              </div>
            </div>

            {/* Compare Scans */}
            <div className="bg-slate-950/50 border border-slate-800 rounded-xl p-6 hover:border-indigo-500/50 transition-colors flex flex-col">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-indigo-500/10 rounded-lg text-indigo-400">
                  <ArrowRightLeft size={20} />
                </div>
                <h3 className="text-lg font-bold text-slate-50">Compare Scans</h3>
              </div>
              <p className="text-slate-400 text-sm leading-relaxed flex-1">
                Compare two scan results side by side. Quickly identify what improved, what
                changed, and which findings are still present between different scans of the
                same website.
              </p>
              <div className="mt-6 pt-4 border-t border-slate-800 flex items-center text-xs font-mono text-slate-500 uppercase">
                Find it in:
                <span className="ml-2 text-indigo-400 flex items-center">
                  Scan History <ChevronRight size={12} className="mx-1" /> Compare Selected
                </span>
              </div>
            </div>

            {/* Scheduled Scans & Email Reports */}
            <div className="bg-slate-950/30 border border-slate-800/50 border-dashed rounded-xl p-6 relative flex flex-col">
              <div className="absolute -top-3 -right-3 bg-purple-500 text-white text-[10px] font-bold uppercase tracking-wider py-1 px-3 rounded-full shadow-lg">
                Coming Soon
              </div>
              <div className="flex items-center gap-3 mb-4 opacity-70">
                <div className="p-2 bg-slate-800 rounded-lg text-slate-400">
                  <CalendarClock size={20} />
                </div>
                <h3 className="text-lg font-bold text-slate-50">Scheduled Scans & Email Reports</h3>
              </div>
              <p className="text-slate-500 text-sm leading-relaxed flex-1 opacity-80">
                Automated scheduled security checks are coming soon. Schedule recurring scans
                and receive security reports by email, making it easier to keep track of
                configuration changes without manually starting every scan.
              </p>
            </div>
          </div>

          {/* MANUAL SECURITY TESTING */}
          <div className="mt-8 pt-8 border-t border-slate-800/80">
            <h2 className="text-2xl font-bold text-slate-50 mb-4">Need Deeper Security Testing?</h2>
            <p className="text-slate-400 mb-4">
              URLScanOnline is designed for passive-first and low-impact security
              assessment. Automated scanning is useful for identifying exposed security
              signals, configuration weaknesses, and areas that deserve further
              investigation, but it does not replace a complete manual security assessment.
            </p>
            <p className="text-slate-400">
              If you find our scans and reports useful and require deeper testing, we can
              also perform advanced manual security testing of your website or application.
              This is carried out only with your explicit written authorization, an agreed
              testing scope, and any separately provided access required for the assessment.
            </p>
            <p className="text-slate-400 mt-4 mb-8">
              Manual testing can investigate issues that automated scanning cannot safely
              prove and can support further security hardening and implementation of
              appropriate defenses.
            </p>
            <Link to="/contact" className="inline-flex items-center gap-2 px-6 py-3 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium transition-colors">
              Request a Manual Security Assessment
              <ChevronRight size={16} />
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
};

export default ScannerCapabilities;
