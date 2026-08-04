import React from 'react';
import { motion } from 'framer-motion';
import { PieChart, Terminal, CheckCircle2, Clock } from 'lucide-react';

const ModeSelection = ({ onSelectMode }) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="max-w-5xl mx-auto space-y-12 mt-12"
    >
      <div className="text-center space-y-4">
        <h2 className="text-4xl font-extrabold text-white tracking-tight">Scan Complete</h2>
        <p className="text-lg text-slate-400 max-w-2xl mx-auto">
          We've successfully analyzed your security posture. How would you like to view the results?
          You can toggle between these modes at any time.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 px-4">
        {/* Simple Report Card */}
        <motion.div
          whileHover={{ y: -5 }}
          className="relative group cursor-pointer"
          onClick={() => onSelectMode('simple')}
        >
          <div className="absolute -inset-0.5 bg-gradient-to-r from-emerald-500 to-indigo-500 rounded-3xl blur opacity-25 group-hover:opacity-75 transition duration-500"></div>
          <div className="relative h-full bg-slate-900 border border-slate-800 p-8 rounded-3xl flex flex-col hover:border-emerald-500/50 transition-colors">
            <div className="absolute top-0 right-0 -mt-3 mr-6 bg-emerald-500 text-slate-950 text-xs font-bold px-3 py-1 rounded-full shadow-lg">
              RECOMMENDED
            </div>
            
            <div className="flex items-center gap-4 mb-6">
              <div className="p-4 bg-emerald-500/10 rounded-2xl">
                <PieChart className="w-10 h-10 text-emerald-400" />
              </div>
              <div>
                <h3 className="text-2xl font-bold text-white">Simple Report</h3>
                <div className="flex items-center gap-2 text-sm text-slate-400 mt-1">
                  <Clock className="w-4 h-4" /> 3 min read
                </div>
              </div>
            </div>

            <p className="text-slate-300 mb-8 leading-relaxed">
              A business-focused executive summary. Translates complex vulnerabilities into clear business risks and easy-to-follow remediation steps.
            </p>

            <div className="space-y-3 mb-8 flex-1">
              {['No technical jargon', 'Business impact analysis', 'Prioritized action items', 'Great for founders & managers'].map((feature, i) => (
                <div key={i} className="flex items-start gap-3">
                  <CheckCircle2 className="w-5 h-5 text-emerald-500 shrink-0 mt-0.5" />
                  <span className="text-slate-300 text-sm">{feature}</span>
                </div>
              ))}
            </div>

            <button className="w-full py-4 bg-slate-800 group-hover:bg-emerald-600 text-white rounded-xl font-bold transition-colors">
              View Simple Report
            </button>
          </div>
        </motion.div>

        {/* Technical Report Card */}
        <motion.div
          whileHover={{ y: -5 }}
          className="relative group cursor-pointer"
          onClick={() => onSelectMode('technical')}
        >
          <div className="absolute -inset-0.5 bg-gradient-to-r from-blue-500 to-purple-500 rounded-3xl blur opacity-25 group-hover:opacity-75 transition duration-500"></div>
          <div className="relative h-full bg-slate-900 border border-slate-800 p-8 rounded-3xl flex flex-col hover:border-blue-500/50 transition-colors">
            
            <div className="flex items-center gap-4 mb-6">
              <div className="p-4 bg-blue-500/10 rounded-2xl">
                <Terminal className="w-10 h-10 text-blue-400" />
              </div>
              <div>
                <h3 className="text-2xl font-bold text-white">Technical Report</h3>
                <div className="flex items-center gap-2 text-sm text-slate-400 mt-1">
                  <Clock className="w-4 h-4" /> 10+ min read
                </div>
              </div>
            </div>

            <p className="text-slate-300 mb-8 leading-relaxed">
              A comprehensive engineering breakdown. Provides raw payloads, HTTP headers, TLS handshake details, and OWASP Top 10 mappings.
            </p>

            <div className="space-y-3 mb-8 flex-1">
              {['Raw finding evidence', 'OWASP category mapping', 'Detailed technical descriptions', 'Built for Developers & DevOps'].map((feature, i) => (
                <div key={i} className="flex items-start gap-3">
                  <CheckCircle2 className="w-5 h-5 text-blue-500 shrink-0 mt-0.5" />
                  <span className="text-slate-300 text-sm">{feature}</span>
                </div>
              ))}
            </div>

            <button className="w-full py-4 bg-slate-800 group-hover:bg-blue-600 text-white rounded-xl font-bold transition-colors">
              View Technical Report
            </button>
          </div>
        </motion.div>
      </div>
    </motion.div>
  );
};

export default ModeSelection;
