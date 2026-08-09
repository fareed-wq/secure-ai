import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, Search, Lock, EyeOff, Mail, Globe, FileCheck, Key } from 'lucide-react';
import { TRANSLATIONS, CATEGORY_METADATA } from '../config/translations';

// Map icon strings to actual Lucide components
const IconMap = {
  Lock: Lock,
  Shield: Shield,
  EyeOff: EyeOff,
  Mail: Mail,
  Globe: Globe,
  FileCheck: FileCheck,
  Key: Key
};

const Services = () => {
  const [searchTerm, setSearchTerm] = useState('');

  // Group translations by category
  const servicesByCategory = Object.values(TRANSLATIONS).reduce((acc, service) => {
    // If we have a search term, filter the services
    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      if (!service.name.toLowerCase().includes(searchLower) && 
          !service.problem.toLowerCase().includes(searchLower) &&
          !service.category.toLowerCase().includes(searchLower)) {
        return acc; // Skip if it doesn't match
      }
    }

    if (!acc[service.category]) {
      acc[service.category] = [];
    }
    
    // De-duplicate by name (since some technical findings map to the same business explanation)
    const exists = acc[service.category].find(s => s.name === service.name);
    if (!exists) {
      acc[service.category].push(service);
    }
    
    return acc;
  }, {});

  return (
    <div className="space-y-12 pb-12">
      {/* Hero Section */}
      <section className="relative overflow-hidden rounded-3xl bg-slate-900 border border-slate-800 p-8 md:p-12 lg:p-16">
        <div className="absolute top-0 right-0 -mt-16 -mr-16 text-indigo-500/10">
          <Shield className="w-64 h-64" />
        </div>
        
        <div className="relative z-10 max-w-3xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 text-indigo-400 text-sm font-semibold mb-6">
            <span className="w-2 h-2 rounded-full bg-indigo-500 animate-pulse"></span>
            Dynamic Scanner Capabilities
          </div>
          <h1 className="text-4xl md:text-5xl font-black text-white mb-6 tracking-tight">
            Comprehensive Security Posture Audits
          </h1>
          <p className="text-lg text-slate-400 mb-10 max-w-2xl">
            Our automated engine continuously checks your infrastructure against industry standards. 
            Below are the exact security checks and verifications our scanner performs.
          </p>
          
          <div className="relative max-w-xl">
            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
              <Search className="h-5 w-5 text-slate-500" />
            </div>
            <input
              type="text"
              placeholder="Search checks, e.g. 'Cookie', 'Encryption', 'DNS'..."
              className="w-full bg-slate-950/50 border border-slate-700/50 text-white placeholder-slate-500 rounded-xl pl-11 pr-4 py-4 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 transition-all"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
        </div>
      </section>

      {/* Dynamic Categories */}
      {Object.keys(servicesByCategory).length === 0 ? (
        <div className="text-center py-20">
          <p className="text-slate-400 text-lg">No checks match your search query.</p>
        </div>
      ) : (
        <div className="space-y-16">
          {Object.keys(servicesByCategory).map((categoryKey, index) => {
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
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                className="space-y-6"
              >
                {/* Category Header */}
                <div className="flex items-center gap-4 border-b border-slate-800 pb-4">
                  <div className="p-3 rounded-xl bg-slate-800/50">
                    <CategoryIcon className="w-6 h-6 text-indigo-400" />
                  </div>
                  <div>
                    <h2 className="text-2xl font-bold text-white">{meta.title}</h2>
                    <p className="text-slate-400 text-sm mt-1">{meta.description}</p>
                  </div>
                </div>

                {/* Cards Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                  {services.map((service, i) => (
                    <div 
                      key={i} 
                      className="bg-slate-900/50 border border-slate-800 rounded-xl p-6 hover:bg-slate-800/50 transition-colors group"
                    >
                      <h3 className="text-lg font-bold text-slate-200 mb-2 group-hover:text-white transition-colors">
                        {service.name}
                      </h3>
                      <p className="text-sm text-slate-400 mb-4 line-clamp-3">
                        {service.why}
                      </p>
                      <div className="pt-4 border-t border-slate-800/50">
                        <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">
                          Scans for:
                        </span>
                        <p className="text-sm text-slate-300 mt-1 line-clamp-2">
                          {service.problem}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </motion.section>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default Services;
