import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldAlert, ShieldCheck, Filter, Search, ChevronDown, ChevronUp } from 'lucide-react';

const TechnicalReport = ({ reportData }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [expandedIssues, setExpandedIssues] = useState({});

  const toggleExpand = (idx) => {
    setExpandedIssues(prev => ({ ...prev, [idx]: !prev[idx] }));
  };

  const findings = reportData?.findings || [];
  const passed = findings.filter(f => f.severity === 'Passed');
  
  let issues = findings.filter(f => f.severity !== 'Passed').sort((a, b) => {
    const weights = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };
    return (weights[b.severity] || 0) - (weights[a.severity] || 0);
  });

  if (severityFilter !== 'All') {
    issues = issues.filter(f => f.severity === severityFilter);
  }

  if (searchTerm) {
    const term = searchTerm.toLowerCase();
    issues = issues.filter(f => 
      f.name.toLowerCase().includes(term) || 
      f.description.toLowerCase().includes(term) || 
      (f.evidence && f.evidence.toLowerCase().includes(term)) ||
      (f.owasp && f.owasp.toLowerCase().includes(term))
    );
  }

  const severityColors = {
    'Critical': 'bg-red-950 border-red-900 text-red-200',
    'High': 'bg-red-500/10 border-red-500/20 text-red-400',
    'Medium': 'bg-orange-500/10 border-orange-500/20 text-orange-400',
    'Low': 'bg-yellow-500/10 border-yellow-500/20 text-yellow-400',
    'Informational': 'bg-blue-500/10 border-blue-500/20 text-blue-400',
  };

  const severityDotColors = {
    'Critical': 'bg-red-500',
    'High': 'bg-red-500',
    'Medium': 'bg-orange-500',
    'Low': 'bg-yellow-500',
    'Informational': 'bg-blue-500',
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-8"
      id="report-content"
    >
      {/* Filters Toolbar */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex flex-col md:flex-row gap-4 items-center justify-between">
        <div className="relative w-full md:w-96">
          <Search className="w-5 h-5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input 
            type="text" 
            placeholder="Search raw payloads, headers, OWASP..." 
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg py-2 pl-10 pr-4 text-sm text-slate-200 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none transition-all"
          />
        </div>
        
        <div className="flex items-center gap-3 w-full md:w-auto">
          <Filter className="w-4 h-4 text-slate-500" />
          <select 
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg py-2 px-4 text-sm text-slate-200 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none appearance-none cursor-pointer flex-1 md:flex-none"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Informational">Informational</option>
          </select>
        </div>
      </div>

      {/* Issues List */}
      <div className="space-y-4">
        <div className="flex items-center gap-3 text-slate-200 mb-4 border-b border-slate-800 pb-2">
          <ShieldAlert className="w-6 h-6 text-amber-500" />
          <h3 className="font-semibold text-xl">Technical Findings ({issues.length})</h3>
        </div>
        
        {issues.length === 0 && (
          <div className="p-8 text-center text-slate-500 border border-slate-800 rounded-xl bg-slate-900/50">
            No technical findings match your filters.
          </div>
        )}

        <div className="space-y-4">
          {issues.map((item, i) => (
            <div key={i} className={`rounded-xl border overflow-hidden transition-all duration-200 ${severityColors[item.severity] || severityColors.Informational}`}>
              <div 
                className="p-5 flex justify-between items-center cursor-pointer hover:bg-black/5"
                onClick={() => toggleExpand(i)}
              >
                <div className="flex items-center gap-3">
                  <div className={`w-3 h-3 rounded-full shadow-sm ${severityDotColors[item.severity] || 'bg-slate-500'}`}></div>
                  <h4 className="font-bold text-lg leading-tight">{item.name}</h4>
                </div>
                <div className="flex items-center gap-4">
                  <span className="text-xs uppercase tracking-wider font-bold px-2 py-1 rounded bg-black/20 hidden md:block">
                    {item.severity}
                  </span>
                  {expandedIssues[i] ? <ChevronUp className="w-5 h-5 opacity-50" /> : <ChevronDown className="w-5 h-5 opacity-50" />}
                </div>
              </div>
              
              {expandedIssues[i] && (
                <div className="px-5 pb-5 pt-2 border-t border-current/10 bg-black/10">
                  <p className="text-sm opacity-90 mb-4 leading-relaxed">{item.description}</p>
                  
                  <div className="space-y-4">
                    <div>
                      <span className="text-xs font-bold uppercase tracking-widest opacity-60 mb-1 block">Raw Evidence</span>
                      <div className="text-sm bg-black/30 p-3 rounded-lg border border-black/20 font-mono break-all whitespace-pre-wrap text-slate-300">
                        {item.evidence || "No evidence provided."}
                      </div>
                    </div>
                    
                    {item.remediation && item.remediation !== "N/A" && (
                      <div>
                        <span className="text-xs font-bold uppercase tracking-widest opacity-60 mb-1 block">Remediation Directives</span>
                        <div className="text-sm bg-indigo-900/20 p-3 rounded-lg border border-indigo-500/20 text-indigo-200">
                          {item.remediation}
                        </div>
                      </div>
                    )}
                    
                    {item.owasp && item.owasp !== "N/A" && (
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold uppercase tracking-widest opacity-60">OWASP Mapping:</span>
                        <span className="text-xs bg-black/30 px-2 py-1 rounded-md font-mono">{item.owasp}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Passed Checks (Minimized by default) */}
      {passed.length > 0 && severityFilter === 'All' && (
        <div className="space-y-4 mt-12 opacity-80 hover:opacity-100 transition-opacity">
          <div className="flex items-center gap-3 text-slate-200 mb-4 border-b border-slate-800 pb-2">
            <ShieldCheck className="w-6 h-6 text-emerald-500" />
            <h3 className="font-semibold text-lg">Passed Technical Controls ({passed.length})</h3>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {passed.map((item, i) => (
              <div key={i} className="bg-emerald-500/5 border border-emerald-500/10 text-emerald-100/80 p-3 rounded-lg text-sm">
                <div className="font-bold flex items-center gap-2 mb-1 text-emerald-300">
                  <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full"></div>
                  {item.name}
                </div>
                <p className="text-xs text-emerald-200/50 leading-relaxed truncate">{item.evidence}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  );
};

export default TechnicalReport;
