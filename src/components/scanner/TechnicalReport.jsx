import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, Clock, Server, FileCode, CheckCircle, AlertTriangle, Info, Copy, Shield, ShieldAlert, ChevronDown, ChevronUp } from 'lucide-react';

const TechnicalReport = ({ reportData }) => {
  const [expandedRow, setExpandedRow] = useState(null);

  const findings = reportData?.findings || [];
  const score = reportData?.score ?? 0;
  
  // Sort findings for engineers: Critical -> High -> Medium -> Low -> Info -> Passed
  const sortedFindings = [...findings].sort((a, b) => {
    const weights = { Critical: 6, High: 5, Medium: 4, Low: 3, Informational: 2, Passed: 1 };
    return (weights[b.severity] || 0) - (weights[a.severity] || 0);
  });

  const getSeverityBadge = (severity) => {
    const styles = {
      'Critical': 'bg-red-500 text-white shadow-[0_0_10px_rgba(239,68,68,0.5)]',
      'High': 'bg-orange-500 text-white',
      'Medium': 'bg-amber-500 text-slate-900',
      'Low': 'bg-yellow-400 text-slate-900',
      'Informational': 'bg-blue-500 text-white',
      'Passed': 'bg-emerald-500 text-white'
    };
    return <span className={`px-2.5 py-1 text-[10px] font-black uppercase tracking-widest rounded-md ${styles[severity] || 'bg-slate-700 text-white'}`}>{severity}</span>;
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-8 font-sans" id="report-content">
      
      {/* 1. Technical Metadata Table */}
      <div className="bg-[#0D1117] border border-slate-800 rounded-xl overflow-hidden font-mono text-sm">
        <div className="bg-slate-900 px-6 py-3 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2 text-slate-300 font-bold">
            <Terminal className="w-4 h-4 text-indigo-400" />
            <span>SCAN_METADATA // {reportData?.url}</span>
          </div>
          <div className="text-emerald-400 font-bold">STATUS: COMPLETED</div>
        </div>
        <div className="grid grid-cols-2 gap-1 p-4 bg-[#0D1117]">
          <div className="p-3 bg-slate-900/50 rounded-lg border border-slate-800/50">
            <div className="text-slate-500 text-[10px] uppercase tracking-widest mb-1">Target Resolved</div>
            <div className="text-indigo-300">{reportData?.url?.replace('https://', '')}</div>
          </div>
          <div className="p-3 bg-slate-900/50 rounded-lg border border-slate-800/50">
            <div className="text-slate-500 text-[10px] uppercase tracking-widest mb-1">Total Findings</div>
            <div className="text-slate-300">{findings.length} Artifacts</div>
          </div>
        </div>
      </div>

      {/* 2. Vulnerability Matrix Table */}
      <div className="bg-[#0D1117] border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
        <div className="bg-slate-900 px-6 py-4 border-b border-slate-800 flex items-center gap-3">
          <FileCode className="w-5 h-5 text-indigo-400" />
          <h3 className="font-bold text-white text-lg">Detailed Vulnerability Matrix</h3>
        </div>
        
        <div className="w-full overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-900/50 border-b border-slate-800 text-xs font-bold text-slate-500 uppercase tracking-widest">
                <th className="px-6 py-4">Severity</th>
                <th className="px-6 py-4 w-1/3">Vulnerability / Check Name</th>
                <th className="px-6 py-4">OWASP Map</th>
                <th className="px-6 py-4 text-center">Confidence</th>
                <th className="px-6 py-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {sortedFindings.map((finding, idx) => (
                <React.Fragment key={idx}>
                  <tr 
                    onClick={() => setExpandedRow(expandedRow === idx ? null : idx)}
                    className={`cursor-pointer hover:bg-slate-800/20 transition-colors ${expandedRow === idx ? 'bg-slate-800/30' : ''}`}
                  >
                    <td className="px-6 py-4 whitespace-nowrap">
                      {getSeverityBadge(finding.severity)}
                    </td>
                    <td className="px-6 py-4 font-bold text-slate-200">
                      {finding.name}
                    </td>
                    <td className="px-6 py-4">
                      {finding.owasp && finding.owasp !== "N/A" ? (
                        <span className="px-2 py-1 bg-slate-800 text-slate-300 text-xs font-mono rounded border border-slate-700">{finding.owasp}</span>
                      ) : (
                        <span className="text-slate-600 text-xs">-</span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-center">
                      <span className="text-slate-400 text-xs font-mono">{finding.confidence || '100%'}</span>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button className="text-slate-500 hover:text-white transition-colors">
                        {expandedRow === idx ? <ChevronUp className="w-5 h-5 inline" /> : <ChevronDown className="w-5 h-5 inline" />}
                      </button>
                    </td>
                  </tr>
                  
                  {/* Expanded Accordion Details */}
                  <AnimatePresence>
                    {expandedRow === idx && (
                      <tr>
                        <td colSpan={5} className="p-0 border-b-2 border-indigo-500/50">
                          <motion.div 
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            className="bg-[#0a0d12] overflow-hidden"
                          >
                            <div className="p-8 grid grid-cols-1 lg:grid-cols-3 gap-8">
                              
                              <div className="lg:col-span-2 space-y-6">
                                <div>
                                  <div className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">Technical Description</div>
                                  <p className="text-slate-300 leading-relaxed text-sm">{finding.description}</p>
                                </div>

                                {finding.evidence && finding.evidence !== "N/A" && (
                                  <div>
                                    <div className="flex items-center justify-between mb-2">
                                      <div className="text-xs font-bold text-slate-500 uppercase tracking-widest">Raw Evidence / Payload</div>
                                      <button onClick={() => copyToClipboard(finding.evidence)} className="text-slate-500 hover:text-indigo-400 text-xs flex items-center gap-1 transition-colors">
                                        <Copy className="w-3 h-3" /> Copy
                                      </button>
                                    </div>
                                    <pre className="bg-[#05070a] border border-slate-800 p-4 rounded-lg text-emerald-400 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap leading-relaxed shadow-inner">
                                      {finding.evidence}
                                    </pre>
                                  </div>
                                )}
                              </div>

                              <div className="space-y-6">
                                {finding.remediation && finding.remediation !== "N/A" && (
                                  <div className="bg-indigo-950/20 border border-indigo-900/50 rounded-xl p-5">
                                    <div className="text-xs font-bold text-indigo-400 uppercase tracking-widest mb-2 flex items-center gap-2">
                                      <Shield className="w-4 h-4" /> Remediation Directive
                                    </div>
                                    <p className="text-indigo-200/80 text-sm leading-relaxed">
                                      {finding.remediation}
                                    </p>
                                  </div>
                                )}
                                
                                <div className="space-y-3">
                                  <div className="flex justify-between items-center text-xs border-b border-slate-800 pb-2">
                                    <span className="text-slate-500">Scanner Module</span>
                                    <span className="font-mono text-slate-300">{finding.module || 'HeuristicEngine'}</span>
                                  </div>
                                  <div className="flex justify-between items-center text-xs border-b border-slate-800 pb-2">
                                    <span className="text-slate-500">Affected Component</span>
                                    <span className="font-mono text-slate-300">HTTP Response Headers</span>
                                  </div>
                                </div>
                              </div>

                            </div>
                          </motion.div>
                        </td>
                      </tr>
                    )}
                  </AnimatePresence>
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </motion.div>
  );
};

export default TechnicalReport;
