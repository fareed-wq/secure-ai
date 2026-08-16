import React, { useEffect } from 'react';
import { Shield, Lock, Users, Zap, Globe, Code2, MessageCircle, CheckCircle2 } from 'lucide-react';
import { Link } from 'react-router-dom';

const About = () => {
  useEffect(() => {
    document.title = "About | URLScannerOnline";
  }, []);

  return (
    <div className="space-y-16 pb-12">
      {/* Hero Section */}
      <section className="relative overflow-hidden rounded-3xl bg-slate-900 border border-slate-800 p-8 md:p-16 text-center">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-full max-w-4xl opacity-30 pointer-events-none">
          <div className="absolute inset-0 bg-gradient-to-r from-indigo-500/20 via-purple-500/20 to-blue-500/20 blur-3xl rounded-full transform -translate-y-1/2" />
        </div>

        <div className="relative z-10 max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 text-indigo-400 text-sm font-semibold mb-6">
            <Shield className="w-4 h-4" />
            Our Mission
          </div>
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-black text-slate-50 mb-6 tracking-tight">
            Making website security <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-purple-400">easier to understand.</span>
          </h1>
          <p className="text-lg md:text-xl text-slate-400 leading-relaxed">
            URLScannerOnline helps website owners, developers, and security teams identify common security weaknesses, configuration issues, and exposure risks through practical, actionable security assessments.
          </p>
        </div>
      </section>

      {/* Core Values / Features Grid */}
      <section className="max-w-6xl mx-auto px-4 md:px-0">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold text-slate-50 mb-4">Core Principles</h2>
          <p className="text-slate-400 max-w-2xl mx-auto">
            Everything we build is guided by these foundational pillars of security engineering.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 transition-all duration-200 hover:-translate-y-1 hover:border-indigo-500/40 hover:bg-slate-900/80 hover:shadow-xl hover:shadow-indigo-500/5">
            <div className="w-10 h-10 rounded-lg border border-indigo-500/30 bg-indigo-500/10 flex items-center justify-center text-indigo-400 mb-4">
              <Zap className="w-5 h-5" />
            </div>
            <h3 className="text-xl font-bold text-slate-50 mb-3">Fast & Practical</h3>
            <p className="text-slate-400 leading-relaxed">
              Our scanning engine analyzes multiple website security signals efficiently, helping you identify important security issues without unnecessary complexity or excessive traffic.
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 transition-all duration-200 hover:-translate-y-1 hover:border-indigo-500/40 hover:bg-slate-900/80 hover:shadow-xl hover:shadow-indigo-500/5">
            <div className="w-10 h-10 rounded-lg border border-indigo-500/30 bg-indigo-500/10 flex items-center justify-center text-indigo-400 mb-4">
              <Lock className="w-5 h-5" />
            </div>
            <h3 className="text-xl font-bold text-slate-50 mb-3">Privacy & Responsible Testing</h3>
            <p className="text-slate-400 leading-relaxed mb-2">
              Our Passive Scan is designed to minimize impact on live websites. It analyzes publicly accessible security signals without attempting to exploit vulnerabilities or perform intrusive attacks.
            </p>
            <p className="text-slate-400 leading-relaxed text-sm">
              Active Security Testing is available separately for users who explicitly choose additional testing and understand the associated risks.
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 transition-all duration-200 hover:-translate-y-1 hover:border-indigo-500/40 hover:bg-slate-900/80 hover:shadow-xl hover:shadow-indigo-500/5">
            <div className="w-10 h-10 rounded-lg border border-indigo-500/30 bg-indigo-500/10 flex items-center justify-center text-indigo-400 mb-4">
              <Users className="w-5 h-5" />
            </div>
            <h3 className="text-xl font-bold text-slate-50 mb-3">Actionable Clarity</h3>
            <p className="text-slate-400 leading-relaxed">
              We turn technical security findings into clear explanations, evidence, severity levels, and practical remediation guidance so developers and business teams can understand what needs attention.
            </p>
          </div>
        </div>
      </section>

      {/* Built for practical website security / What URLScannerOnline Does */}
      <section className="max-w-6xl mx-auto px-4 md:px-0">
        <div className="bg-slate-900 border border-slate-800 rounded-3xl overflow-hidden flex flex-col md:flex-row">
          <div className="md:w-1/2 p-8 md:p-12 lg:p-16 flex flex-col justify-center">
            <h2 className="text-3xl font-bold text-slate-50 mb-6">Built for practical website security</h2>
            <div className="space-y-4 text-slate-400 leading-relaxed">
              <p>
                Website security can be difficult to understand. Security tools often produce technical findings that are difficult for website owners and development teams to prioritize.
              </p>
              <p>
                URLScannerOnline was created to make website security assessment simpler. We analyze publicly accessible security signals, identify potential weaknesses and misconfigurations, and explain what they mean and how they can be addressed.
              </p>
              <p>
                Our goal is simple: help more people understand the security posture of their websites without requiring deep security expertise.
              </p>
            </div>
          </div>
          <div className="md:w-1/2 bg-slate-950 p-8 md:p-12 border-t md:border-t-0 md:border-l border-slate-800">
            <h3 className="text-2xl font-bold text-slate-50 mb-6">What URLScannerOnline Does</h3>
            <ul className="space-y-4">
              {[
                "Security configuration analysis",
                "Security header analysis",
                "TLS and security checks",
                "Information exposure detection",
                "Vulnerability indicators",
                "Evidence and remediation guidance",
                "Simple and technical security reports"
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

      {/* Built for teams of every size */}
      <section className="max-w-6xl mx-auto px-4 md:px-0">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold text-slate-50 mb-4">Built for teams of every size</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
            <h3 className="text-lg font-bold text-slate-50 mb-2">Website Owners</h3>
            <p className="text-sm text-slate-400">Understand common security weaknesses without needing a security background.</p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
            <h3 className="text-lg font-bold text-slate-50 mb-2">Developers</h3>
            <p className="text-sm text-slate-400">Identify security misconfigurations and prioritize remediation before they become larger problems.</p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
            <h3 className="text-lg font-bold text-slate-50 mb-2">Security Teams</h3>
            <p className="text-sm text-slate-400">Quickly assess publicly visible security signals and use the results as an additional layer in your security workflow.</p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
            <h3 className="text-lg font-bold text-slate-50 mb-2">Businesses</h3>
            <p className="text-sm text-slate-400">Get understandable security reports that can be shared with technical and non-technical stakeholders.</p>
          </div>
        </div>
      </section>

      {/* Passive vs Active Testing Section */}
      <section className="max-w-6xl mx-auto px-4 md:px-0">
        <div className="rounded-3xl border border-slate-800 bg-slate-900 p-8 md:p-12">
          <h2 className="text-3xl font-bold text-slate-50 mb-8 text-center">Choose the level of testing you need</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="bg-slate-950 p-6 rounded-2xl border border-slate-800">
              <h3 className="text-xl font-bold text-indigo-400 mb-3">PASSIVE SECURITY ASSESSMENT</h3>
              <p className="text-slate-400">
                Designed for low-impact assessment of publicly accessible security signals. It does not attempt to exploit vulnerabilities and is suitable for routine checks and production environments.
              </p>
            </div>
            <div className="bg-slate-950 p-6 rounded-2xl border border-slate-800">
              <h3 className="text-xl font-bold text-purple-400 mb-3">ACTIVE SECURITY TESTING</h3>
              <p className="text-slate-400">
                Performs additional security tests that generate more requests and may have greater impact on the target environment. Use only on systems you own or are authorized to test.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Trust / Transparency Section */}
      <section className="max-w-4xl mx-auto px-4 md:px-0">
        <div className="text-center mb-8">
          <h2 className="text-3xl font-bold text-slate-50">What we don't claim</h2>
        </div>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
          <ul className="space-y-4">
            {[
              "We do not guarantee that a website is completely secure.",
              "We do not replace a professional penetration test.",
              "We do not claim to detect every possible vulnerability.",
              "Passive scanning does not exploit vulnerabilities.",
              "Security findings should be reviewed in context."
            ].map((item, idx) => (
              <li key={idx} className="flex items-start gap-3 text-slate-300">
                <span className="text-slate-600 font-bold mt-0.5">•</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* Bottom Call To Action Banner */}
      <section className="max-w-6xl mx-auto px-4 md:px-0">
        <div className="rounded-2xl border border-indigo-500/30 bg-gradient-to-r from-indigo-950/40 via-slate-900/80 to-slate-900/40 p-8 sm:p-12 text-center relative overflow-hidden">
          <div className="relative z-10 max-w-2xl mx-auto space-y-4">
            <h3 className="text-2xl sm:text-3xl font-bold text-slate-50 tracking-tight">
              Ready to check your website's security posture?
            </h3>
            <p className="text-sm text-slate-400 leading-relaxed">
              Run a fast, non-intrusive security assessment and get actionable findings in seconds.
            </p>
            <div className="pt-2 flex flex-wrap items-center justify-center gap-4">
              <Link className="rounded-xl bg-indigo-600 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-indigo-600/30 hover:bg-indigo-500 transition-all" to="/scan">
                Start Free Scan
              </Link>
              <Link className="rounded-xl border border-slate-700 bg-slate-900/80 px-6 py-3 text-sm font-semibold text-slate-300 hover:text-slate-50 hover:border-slate-600 transition-all" to="/services">
                Explore Services
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Footer / Connect */}
      <section className="text-center pt-8">
        <h3 className="text-xl font-bold text-slate-50 mb-6">Connect with us</h3>
        <div className="flex justify-center gap-4">
          <a
            href="mailto:contact@urlscanonline.com"
            title="Email Support"
            aria-label="Email Support"
            className="p-3 bg-slate-900 border border-slate-800 rounded-full hover:bg-slate-800 transition-colors text-slate-400 hover:text-slate-50"
          >
            <MessageCircle className="w-5 h-5" />
          </a>
          <button
            title="GitHub Repository"
            aria-label="GitHub Repository"
            className="p-3 bg-slate-900 border border-slate-800 rounded-full hover:bg-slate-800 transition-colors text-slate-400 hover:text-slate-50"
          >
            <Code2 className="w-5 h-5" />
          </button>
          <button
            title="Documentation"
            aria-label="Documentation"
            className="p-3 bg-slate-900 border border-slate-800 rounded-full hover:bg-slate-800 transition-colors text-slate-400 hover:text-slate-50"
          >
            <Globe className="w-5 h-5" />
          </button>
        </div>
      </section>
    </div>
  );
};

export default About;
