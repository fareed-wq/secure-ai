import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Search, Lock, EyeOff, Mail, Globe, FileCheck, Key, XCircle, ChevronRight } from 'lucide-react';
import { TRANSLATIONS, CATEGORY_METADATA } from '../config/translations';
import { useSEO } from '../hooks/useSEO';
import { Link } from 'react-router-dom';

const IconMap = {
  Lock,
  Shield,
  EyeOff,
  Mail,
  Globe,
  FileCheck,
  Key
};

const getImpactStyles = (impact) => {
  const normalized = (impact || 'Medium').toLowerCase();
  if (normalized.includes('high') || normalized.includes('critical')) {
    return 'border-rose-500/30 bg-rose-500/10 text-rose-400';
  }
  if (normalized.includes('low') || normalized.includes('info')) {
    return 'border-indigo-500/30 bg-indigo-500/10 text-indigo-400';
  }
  return 'border-amber-500/30 bg-amber-500/10 text-amber-400';
};

const SecurityAudits = () => {
  useSEO({
    title: 'Security Audits & Assessments | URLScanOnline',
    description: 'Explore security audit and assessment areas covering websites, applications, networks, encryption, cookies, email, domains and security configurations.',
    path: '/services/security-audits'
  });
  const [searchTerm, setSearchTerm] = useState('');
  const [activeCategory, setActiveCategory] = useState('all');

  const allUniqueChecks = Object.values(TRANSLATIONS).reduce((acc, curr) => {
    if (!acc.find(i => i.name === curr.name)) acc.push(curr);
    return acc;
  }, []);
  const totalAuditCount = allUniqueChecks.length;

  const categoryCounts = {};
  allUniqueChecks.forEach(service => {
    categoryCounts[service.category] = (categoryCounts[service.category] || 0) + 1;
  });
  const categoryCount = Object.keys(categoryCounts).length;

  const servicesByCategory = allUniqueChecks.reduce((acc, service) => {
    if (activeCategory !== 'all' && service.category !== activeCategory) {
      return acc;
    }
    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      if (!service.name.toLowerCase().includes(searchLower) &&
          !service.problem.toLowerCase().includes(searchLower) &&
          !service.category.toLowerCase().includes(searchLower)) {
        return acc;
      }
    }
    if (!acc[service.category]) {
      acc[service.category] = [];
    }
    const exists = acc[service.category].find(s => s.name === service.name);
    if (!exists) {
      acc[service.category].push(service);
    }
    return acc;
  }, {});

  const handleClearFilters = () => {
    setSearchTerm('');
    setActiveCategory('all');
  };

  return (
    <div className="space-y-12 pb-12 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-8">

      {/* BREADCRUMB */}
      <nav className="flex items-center text-sm font-medium text-slate-400 mb-6 space-x-2">
        <Link to="/services" className="hover:text-indigo-400 transition-colors">Services</Link>
        <ChevronRight size={14} className="text-slate-600" />
        <span className="text-slate-200">Security Audits & Assessments</span>
      </nav>

      {/* SECTION 2: SECURITY AUDITS & ASSESSMENTS */}
      <section className="relative overflow-hidden rounded-3xl bg-slate-900 border border-slate-800 p-8 md:p-12 lg:p-16">
        <div className="absolute top-0 right-0 -mt-16 -mr-16 text-indigo-500/10">
          <Shield className="w-64 h-64" />
        </div>

        <div className="relative z-10 max-w-3xl">
          <div className="inline-flex items-center gap-2 rounded-full border border-indigo-500/30 bg-indigo-500/10 px-3.5 py-1 text-xs font-mono text-indigo-400 mb-4">
            <span className="w-2 h-2 rounded-full bg-indigo-500 animate-pulse"></span>
            ⚡ {totalAuditCount} Potential Findings across {categoryCount} Security Domains
          </div>

          <h2 className="text-4xl md:text-5xl font-black text-slate-50 mb-6 tracking-tight">
            Security Audits & Assessments
          </h2>
          <p className="text-lg text-slate-400 mb-10 max-w-2xl">
            Explore the security checks, configurations, and assessment areas covered by
            our security services. Below is a comprehensive catalog of security areas and
            potential findings that can be evaluated during our assessments.
          </p>

          <div className="relative max-w-xl mb-6">
            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
              <Search className="h-5 w-5 text-slate-500" />
            </div>
            <input
              type="text"
              placeholder="Search checks, e.g. 'Cookie', 'Encryption', 'DNS'..."
              className="w-full bg-slate-950/50 border border-slate-700/50 text-slate-50 placeholder-slate-500 rounded-xl pl-11 pr-4 py-4 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 transition-all"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setActiveCategory('all')}
              className={`px-4 py-1.5 rounded-full text-sm font-medium transition-colors ${
                activeCategory === 'all'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-500/20'
                  : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-50 hover:border-slate-700'
              }`}
            >
              All Audits ({totalAuditCount})
            </button>
            {Object.keys(categoryCounts).map(cat => (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`px-4 py-1.5 rounded-full text-sm font-medium transition-colors ${
                  activeCategory === cat
                    ? 'bg-indigo-600 text-white shadow-md shadow-indigo-500/20'
                    : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-50 hover:border-slate-700'
                }`}
              >
                {CATEGORY_METADATA[cat]?.title || cat} ({categoryCounts[cat]})
              </button>
            ))}
          </div>
        </div>
      </section>

      {Object.keys(servicesByCategory).length === 0 ? (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="flex flex-col items-center justify-center py-24 px-4 bg-slate-900/50 border border-slate-800/80 rounded-2xl text-center"
        >
          <div className="w-16 h-16 bg-slate-800 rounded-full flex items-center justify-center mb-6">
            <Search className="w-8 h-8 text-slate-500" />
          </div>
          <h3 className="text-xl font-bold text-slate-50 mb-2">No matching security checks found</h3>
          <p className="text-slate-400 max-w-md mb-8">
            We couldn't find any audits matching "{searchTerm}" in the selected category. Try adjusting your search terms.
          </p>
          <button
            onClick={handleClearFilters}
            className="flex items-center gap-2 px-6 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium transition-colors"
          >
            <XCircle className="w-4 h-4" />
            Clear Filters
          </button>
        </motion.div>
      ) : (
        <div className="space-y-8">
          <AnimatePresence mode="popLayout">
            {Object.keys(servicesByCategory).map((categoryKey) => {
              const meta = CATEGORY_METADATA[categoryKey] || {
                title: categoryKey,
                icon: "Shield",
                description: "Security checks and verifications."
              };
              const CategoryIcon = IconMap[meta.icon] || Shield;
              const services = servicesByCategory[categoryKey];

              return (
                <motion.section
                  key={categoryKey}
                  layout
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  transition={{ duration: 0.3 }}
                >
                  <div className="flex items-center justify-between border-b border-slate-800/60 pb-3 mb-6 mt-12">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-slate-800/50">
                        <CategoryIcon className="w-5 h-5 text-indigo-400" />
                      </div>
                      <div>
                        <h2 className="text-xl font-bold text-slate-50 tracking-tight">{meta.title}</h2>
                      </div>
                    </div>
                    <div className="px-3 py-1 rounded bg-slate-800/50 text-[10px] font-mono text-slate-400 uppercase tracking-widest">
                      [ {services.length} AUDIT{services.length !== 1 && 'S'} ]
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                    {services.map((service, i) => (
                      <div
                        key={i}
                        className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 transition-all duration-200 hover:-translate-y-1 hover:border-indigo-500/40 hover:bg-slate-900/90 hover:shadow-xl hover:shadow-indigo-500/5 flex flex-col justify-between group"
                      >
                        <div>
                          <div className="flex items-start justify-between mb-3">
                            <h3 className="text-base font-semibold text-slate-50 tracking-tight group-hover:text-indigo-200 transition-colors">
                              {service.name}
                            </h3>
                            <span className={`shrink-0 ml-3 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide border ${getImpactStyles(service.impact)}`}>
                              {service.impact || 'High'}
                            </span>
                          </div>
                          <p className="text-xs text-slate-400 leading-relaxed my-3">
                            {service.why}
                          </p>
                        </div>

                        <div className="pt-4 mt-auto border-t border-slate-800/50">
                          <span className="text-[10px] font-medium text-slate-500 uppercase tracking-wider block mb-1">
                            Observation:
                          </span>
                          <p className="text-[11px] text-slate-300 font-mono">
                            {service.problem}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </motion.section>
              );
            })}
          </AnimatePresence>
        </div>
      )}
    </div>
  );
};

export default SecurityAudits;
