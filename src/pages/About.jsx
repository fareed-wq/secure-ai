import React from 'react';
import { Shield, Lock, Users, Zap, Globe, Code2, MessageCircle } from 'lucide-react';

const About = () => {
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
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-black text-white mb-6 tracking-tight">
            Making enterprise security <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-purple-400">accessible to everyone.</span>
          </h1>
          <p className="text-lg md:text-xl text-slate-400 leading-relaxed">
            We believe that every website, regardless of size, deserves top-tier defense mechanisms. 
            Our platform simplifies complex vulnerability data into actionable, plain-English insights.
          </p>
        </div>
      </section>

      {/* Core Values / Features Grid */}
      <section className="max-w-6xl mx-auto px-4 md:px-0">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold text-white mb-4">Core Principles</h2>
          <p className="text-slate-400 max-w-2xl mx-auto">
            Everything we build is guided by these foundational pillars of security engineering.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <div className="bg-slate-900/50 border border-slate-800 p-8 rounded-2xl">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-xl flex items-center justify-center mb-6">
              <Zap className="w-6 h-6 text-indigo-400" />
            </div>
            <h3 className="text-xl font-bold text-white mb-3">Lightning Fast</h3>
            <p className="text-slate-400 leading-relaxed">
              Our distributed scanning engine analyzes hundreds of vectors in seconds, giving you immediate feedback on your security posture.
            </p>
          </div>

          <div className="bg-slate-900/50 border border-slate-800 p-8 rounded-2xl">
            <div className="w-12 h-12 bg-emerald-500/10 rounded-xl flex items-center justify-center mb-6">
              <Lock className="w-6 h-6 text-emerald-400" />
            </div>
            <h3 className="text-xl font-bold text-white mb-3">Privacy First</h3>
            <p className="text-slate-400 leading-relaxed">
              We don't sell your data. We don't perform invasive intrusive scans. Our methodology relies entirely on passive, public-facing signals.
            </p>
          </div>

          <div className="bg-slate-900/50 border border-slate-800 p-8 rounded-2xl">
            <div className="w-12 h-12 bg-blue-500/10 rounded-xl flex items-center justify-center mb-6">
              <Users className="w-6 h-6 text-blue-400" />
            </div>
            <h3 className="text-xl font-bold text-white mb-3">Actionable Clarity</h3>
            <p className="text-slate-400 leading-relaxed">
              We translate cryptic headers and cipher suites into simple, business-oriented language so your entire team can understand the risks.
            </p>
          </div>
        </div>
      </section>

      {/* Team / Story Section */}
      <section className="max-w-6xl mx-auto px-4 md:px-0">
        <div className="bg-slate-900 border border-slate-800 rounded-3xl overflow-hidden flex flex-col md:flex-row">
          <div className="md:w-1/2 p-8 md:p-12 lg:p-16 flex flex-col justify-center">
            <h2 className="text-3xl font-bold text-white mb-6">Built by engineers, for the modern web.</h2>
            <div className="space-y-4 text-slate-400 leading-relaxed">
              <p>
                Secure AI was born out of frustration. Traditional security scanners are either too expensive, 
                too difficult to configure, or spit out 300-page PDF reports that nobody actually reads.
              </p>
              <p>
                We wanted a tool that developers and business owners could use together. A tool that provides 
                instant visibility into a website's health without requiring a PhD in cryptography.
              </p>
            </div>
          </div>
          <div className="md:w-1/2 bg-slate-950 flex items-center justify-center p-12 border-l border-slate-800">
            <div className="grid grid-cols-2 gap-8 text-center">
              <div>
                <div className="text-4xl font-black text-white mb-2">5M+</div>
                <div className="text-sm text-slate-500 font-medium uppercase tracking-wider">URLs Scanned</div>
              </div>
              <div>
                <div className="text-4xl font-black text-white mb-2">99.9%</div>
                <div className="text-sm text-slate-500 font-medium uppercase tracking-wider">Uptime</div>
              </div>
              <div>
                <div className="text-4xl font-black text-white mb-2">24/7</div>
                <div className="text-sm text-slate-500 font-medium uppercase tracking-wider">Monitoring</div>
              </div>
              <div>
                <div className="text-4xl font-black text-white mb-2">Zero</div>
                <div className="text-sm text-slate-500 font-medium uppercase tracking-wider">Intrusive Payloads</div>
              </div>
            </div>
          </div>
        </div>
      </section>
      
      {/* Footer / Connect */}
      <section className="text-center pt-8">
        <h3 className="text-xl font-bold text-white mb-6">Connect with us</h3>
        <div className="flex justify-center gap-4">
          <button className="p-3 bg-slate-900 border border-slate-800 rounded-full hover:bg-slate-800 transition-colors text-slate-400 hover:text-white">
            <Code2 className="w-5 h-5" />
          </button>
          <button className="p-3 bg-slate-900 border border-slate-800 rounded-full hover:bg-slate-800 transition-colors text-slate-400 hover:text-white">
            <MessageCircle className="w-5 h-5" />
          </button>
          <button className="p-3 bg-slate-900 border border-slate-800 rounded-full hover:bg-slate-800 transition-colors text-slate-400 hover:text-white">
            <Globe className="w-5 h-5" />
          </button>
        </div>
      </section>
    </div>
  );
};

export default About;
