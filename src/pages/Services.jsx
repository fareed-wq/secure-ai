import React from 'react';
import { Shield, Activity, ArrowRight } from 'lucide-react';
import { useSEO } from '../hooks/useSEO';
import { Link } from 'react-router-dom';

const Services = () => {
  useSEO({
    title: 'Security Services | URLScannerOnline',
    description: 'Explore URLScannerOnline scanner capabilities and security audit and assessment services.',
    path: '/services'
  });

  const capabilities = [
    {
      title: "Scanner Capabilities",
      description: "Explore URLScannerOnline's Basic and Advanced security scans, compare their coverage, review scan history and comparison tools, and manage scheduled scans.",
      icon: Activity,
      link: "/services/scanner-capabilities"
    },
    {
      title: "Security Audits & Assessments",
      description: "Explore our broader security assessment areas, including web, application, network, encryption, cookie, email, domain and configuration security.",
      icon: Shield,
      link: "/services/security-audits"
    }
  ];

  return (
    <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-12 pb-24">
      <div className="mb-12">
        <h1 className="services-title text-4xl md:text-5xl font-black text-slate-50 mb-4 tracking-tight">
          Security Services
        </h1>
        <p className="services-subtitle text-lg text-slate-400 max-w-3xl">
          Choose between automated website security scanning and deeper security assessment services.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {capabilities.map((cap, i) => {
          const Icon = cap.icon;
          return (
            <div key={i} className="services-card group flex flex-col justify-between relative overflow-hidden rounded-3xl bg-slate-900 border border-slate-800 p-8 hover:border-indigo-500/50 hover:bg-slate-800/50 transition-all focus-within:ring-2 focus-within:ring-indigo-500 focus-within:ring-offset-2 focus-within:ring-offset-slate-900">
              <div>
                <div className="p-3 bg-indigo-500/10 rounded-xl inline-block mb-6 group-hover:bg-indigo-500/20 transition-colors">
                  <Icon className="w-8 h-8 text-indigo-400" />
                </div>
                <h2 className="text-2xl font-bold text-slate-50 mb-4 tracking-tight">{cap.title}</h2>
                <p className="text-slate-400 leading-relaxed mb-8">
                  {cap.description}
                </p>
              </div>
              <div className="flex items-center text-indigo-400 font-medium group-hover:text-indigo-300 transition-colors mt-auto">
                <Link
                  to={cap.link}
                  className="focus:outline-none after:absolute after:inset-0"
                  aria-label={ "Explore " + cap.title }
                >
                  Explore <ArrowRight className="inline-block ml-1 w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </Link>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default Services;
