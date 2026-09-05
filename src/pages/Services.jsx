import React from 'react';
import { Shield, Activity, ArrowRight } from 'lucide-react';
import { useSEO } from '../hooks/useSEO';
import { Link } from 'react-router-dom';

const Services = () => {
  useSEO({
    title: 'Security Services | URLScanOnline',
    description: 'Explore URLScanOnline scanner capabilities and security audit and assessment services.',
    path: '/services'
  });

  return (
    <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-12 pb-24">
      <div className="mb-12">
        <h1 className="text-4xl md:text-5xl font-black text-slate-50 mb-4 tracking-tight">
          Security Services
        </h1>
        <p className="text-lg text-slate-400 max-w-3xl">
          Choose between automated website security scanning and deeper security assessment services.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* CARD 1 */}
        <Link to="/services/scanner-capabilities" className="group flex flex-col justify-between relative overflow-hidden rounded-3xl bg-slate-900 border border-slate-800 p-8 md:p-10 hover:border-indigo-500/50 hover:bg-slate-800/50 transition-all min-h-[230px]">
          <div>
            <div className="p-3 bg-indigo-500/10 rounded-xl inline-block mb-6 group-hover:bg-indigo-500/20 transition-colors">
              <Activity className="w-8 h-8 text-indigo-400" />
            </div>
            <h2 className="text-2xl font-bold text-slate-50 mb-4 tracking-tight">Scanner Capabilities</h2>
            <p className="text-slate-400 leading-relaxed mb-8">
              Explore URLScanOnline's Basic and Advanced security scans, compare their coverage, review scan history and comparison tools, and see upcoming scanning features.
            </p>
          </div>
          <div className="flex items-center text-indigo-400 font-medium group-hover:text-indigo-300 transition-colors">
            Explore Scanner Capabilities <ArrowRight className="ml-2 w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </div>
        </Link>

        {/* CARD 2 */}
        <Link to="/services/security-audits" className="group flex flex-col justify-between relative overflow-hidden rounded-3xl bg-slate-900 border border-slate-800 p-8 md:p-10 hover:border-indigo-500/50 hover:bg-slate-800/50 transition-all min-h-[230px]">
          <div>
            <div className="p-3 bg-indigo-500/10 rounded-xl inline-block mb-6 group-hover:bg-indigo-500/20 transition-colors">
              <Shield className="w-8 h-8 text-indigo-400" />
            </div>
            <h2 className="text-2xl font-bold text-slate-50 mb-4 tracking-tight">Security Audits & Assessments</h2>
            <p className="text-slate-400 leading-relaxed mb-8">
              Explore our broader security assessment areas, including web, application, network, encryption, cookie, email, domain and configuration security.
            </p>
          </div>
          <div className="flex items-center text-indigo-400 font-medium group-hover:text-indigo-300 transition-colors">
            Explore Security Audits <ArrowRight className="ml-2 w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </div>
        </Link>
      </div>
    </div>
  );
};

export default Services;
