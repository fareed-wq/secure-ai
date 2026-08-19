import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, FileText, AlertTriangle, ChevronRight } from 'lucide-react';

const TrustAndPolicy = () => {
  return (
    <div className="flex-1 w-full max-w-7xl mx-auto p-4 sm:p-6 lg:p-8 overflow-y-auto space-y-12 pb-24">
      {/* Header Section */}
      <section className="max-w-4xl pt-8 pb-4">
        <h1 className="text-4xl font-bold text-slate-50 mb-4 tracking-tight">Trust & Policy</h1>
        <p className="text-lg text-slate-400">
          Our commitment to security, transparency, and responsible operations.
        </p>
      </section>

      {/* Cards Section */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Link 
          to="/security-trust"
          className="group flex flex-col bg-slate-900 border border-slate-800 rounded-2xl p-6 hover:bg-slate-800/80 hover:border-slate-700 transition-all cursor-pointer"
        >
          <div className="w-12 h-12 rounded-full bg-indigo-500/10 flex items-center justify-center text-indigo-400 mb-6 group-hover:scale-110 transition-transform">
            <Shield size={24} />
          </div>
          <h2 className="text-xl font-bold text-slate-50 mb-3 flex items-center justify-between">
            Security & Trust
            <ChevronRight className="w-5 h-5 text-slate-500 group-hover:text-slate-300 transition-colors" />
          </h2>
          <p className="text-slate-400 text-sm leading-relaxed">
            Learn about how we secure our infrastructure, handle user data, and design our scanner safely.
          </p>
        </Link>

        <Link 
          to="/terms"
          className="group flex flex-col bg-slate-900 border border-slate-800 rounded-2xl p-6 hover:bg-slate-800/80 hover:border-slate-700 transition-all cursor-pointer"
        >
          <div className="w-12 h-12 rounded-full bg-emerald-500/10 flex items-center justify-center text-emerald-400 mb-6 group-hover:scale-110 transition-transform">
            <FileText size={24} />
          </div>
          <h2 className="text-xl font-bold text-slate-50 mb-3 flex items-center justify-between">
            Terms of Service
            <ChevronRight className="w-5 h-5 text-slate-500 group-hover:text-slate-300 transition-colors" />
          </h2>
          <p className="text-slate-400 text-sm leading-relaxed">
            Read the terms governing the use of URLScannerOnline and our scanning rules of engagement.
          </p>
        </Link>

        <Link 
          to="/responsible-disclosure"
          className="group flex flex-col bg-slate-900 border border-slate-800 rounded-2xl p-6 hover:bg-slate-800/80 hover:border-slate-700 transition-all cursor-pointer"
        >
          <div className="w-12 h-12 rounded-full bg-amber-500/10 flex items-center justify-center text-amber-400 mb-6 group-hover:scale-110 transition-transform">
            <AlertTriangle size={24} />
          </div>
          <h2 className="text-xl font-bold text-slate-50 mb-3 flex items-center justify-between">
            Responsible Disclosure
            <ChevronRight className="w-5 h-5 text-slate-500 group-hover:text-slate-300 transition-colors" />
          </h2>
          <p className="text-slate-400 text-sm leading-relaxed">
            Report security vulnerabilities to our team. We welcome responsible research.
          </p>
        </Link>
      </section>
    </div>
  );
};

export default TrustAndPolicy;
