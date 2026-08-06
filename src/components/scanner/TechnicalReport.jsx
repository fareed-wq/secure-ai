import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, Clock, Server, FileCode, CheckCircle, AlertTriangle, Info, Copy, Shield, ShieldAlert, ChevronDown, ChevronUp, Layers, Check, XCircle } from 'lucide-react';


const TechnicalReport = ({ reportData }) => {
  const [expandedRow, setExpandedRow] = useState(null);
  const [activeView, setActiveView] = useState('vulnerabilities'); // 'vulnerabilities' | 'compliance'
  const [snippetTabs, setSnippetTabs] = useState({}); // { findingIndex: 'nginx' }

  const findings = reportData?.findings || [];
  const score = reportData?.score ?? 0;
  
  const sortedFindings = [...findings].sort((a, b) => {
    const weights = { Critical: 6, High: 5, Medium: 4, Low: 3, Informational: 2, Passed: 1 };
    return (weights[b.severity] || 0) - (weights[a.severity] || 0);
  });

  const getSeverityBadge = (severity) => {
    const styles = {
      'Critical': 'bg-red-950 text-red-400 border border-red-800',
      'High': 'bg-rose-900/60 text-rose-300 border border-rose-700',
      'Medium': 'bg-amber-950/80 text-amber-400 border border-amber-700',
      'Low': 'bg-sky-950 text-sky-400 border border-sky-800',
      'Informational': 'bg-blue-500 text-white border border-blue-600',
      'Passed': 'bg-emerald-500 text-white border border-emerald-600'
    };
    return <span className={`px-2.5 py-1 text-[10px] font-black uppercase tracking-widest rounded-md ${styles[severity] || 'bg-slate-700 text-white border border-slate-600'}`}>{severity}</span>;
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };



  const handleSnippetTabChange = (findingIdx, tab) => {
    setSnippetTabs(prev => ({ ...prev, [findingIdx]: tab }));
  };

  return (
    <div className="space-y-8" id="report-content">
      <style>{`
        @media print {
          body, html, #report-content { background: white !important; color: #0f172a !important; }
          * { border-color: #e2e8f0 !important; }
          .bg-\\[\\#0D1117\\], .bg-slate-900, .bg-slate-900\\/50, .bg-slate-800 { background: white !important; box-shadow: none !important; }
          .text-white, .text-slate-200, .text-slate-300 { color: #0f172a !important; }
          .text-slate-400, .text-slate-500 { color: #475569 !important; }
          .shadow-2xl, .shadow-xl, .shadow-inner { box-shadow: none !important; }
          .text-indigo-400 { color: #4338ca !important; }
          .text-emerald-400 { color: #059669 !important; }
          .text-red-500, .text-red-400 { color: #dc2626 !important; }
          .text-orange-500, .text-orange-400 { color: #ea580c !important; }
          .text-amber-500, .text-amber-400 { color: #d97706 !important; }
        }
      `}</style>
      
      {/* 1. Technical Metadata Table */}
      <div className="bg-[#0D1117] border border-slate-800 rounded-xl overflow-hidden font-mono text-sm shadow-2xl">
        <div className="bg-slate-900 px-6 py-3 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2 text-slate-300 font-bold">
            <Terminal className="w-4 h-4 text-indigo-400" />
            <span>SCAN_METADATA // {reportData?.url}</span>
          </div>
          <div className="text-emerald-400 font-bold">STATUS: COMPLETED</div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-3 p-4 bg-[#0D1117]">
          {/* Card 1: IP Address & Location */}
          <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
            <div className="text-slate-400 text-xs font-mono tracking-wider mb-1">IP ADDRESS & LOCATION</div>
            <div className="text-slate-100 font-bold text-sm">{reportData?.metadata?.ip_address || reportData?.ip_address || 'N/A'}</div>
            <div className="text-slate-400 text-xs mt-1">{reportData?.metadata?.location_or_cdn || reportData?.location_or_cdn || 'CDN / Cloud'}</div>
          </div>
          
          {/* Card 2: HTTP Status & Server Banner */}
          <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
            <div className="text-slate-400 text-xs font-mono tracking-wider mb-1">HTTP STATUS & SERVER</div>
            <div className="text-slate-100 font-bold text-sm">{reportData?.metadata?.http_status || '200 OK'}</div>
            <div className="text-slate-400 text-xs mt-1">{
              (reportData?.metadata?.server_header || reportData?.server_header) 
                ? (String(reportData?.metadata?.server_header || reportData?.server_header).startsWith("Server:") 
                   ? (reportData?.metadata?.server_header || reportData?.server_header) 
                   : `Server: ${reportData?.metadata?.server_header || reportData?.server_header}`)
                : 'Server: Hidden'
            }</div>
          </div>
          
          {/* Card 3: SSL/TLS Certificate Quick-Check */}
          <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
            <div className="text-slate-400 text-xs font-mono tracking-wider mb-1">SSL/TLS CERTIFICATE</div>
            <div className="text-slate-100 font-bold text-sm">{reportData?.metadata?.ssl_issuer || reportData?.ssl_issuer || 'Valid SSL'}</div>
            <div className="text-slate-400 text-xs mt-1">{reportData?.metadata?.ssl_days_left || reportData?.ssl_days_left || 'Active'}</div>
          </div>
        </div>
      </div>



      {/* 3. Tab Switcher: Vulnerabilities vs Compliance */}
      <div className="flex bg-[#0D1117] border border-slate-800 p-1 rounded-xl w-full max-w-md mx-auto shadow-xl print:hidden">
        <button
          onClick={() => setActiveView('vulnerabilities')}
          className={`flex-1 py-2 text-sm font-bold rounded-lg transition-all ${activeView === 'vulnerabilities' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'}`}
        >
          Vulnerabilities
        </button>
        <button
          onClick={() => setActiveView('compliance')}
          className={`flex-1 py-2 text-sm font-bold rounded-lg transition-all ${activeView === 'compliance' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'}`}
        >
          Compliance Readiness
        </button>
      </div>

      {/* 4. Main Content Area */}
      <AnimatePresence mode="wait">
        {activeView === 'vulnerabilities' && (
          <motion.div key="vulnerabilities" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}>
            <div className="bg-[#0D1117] border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
              <div className="bg-slate-900 px-6 py-4 border-b border-slate-800 flex items-center gap-3">
                <FileCode className="w-5 h-5 text-indigo-400" />
                <h3 className="font-bold text-white text-lg">Detailed Vulnerability Matrix</h3>
              </div>
              
              <div className="w-full overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-900/50 border-b border-slate-800 text-xs font-bold text-slate-500 uppercase tracking-widest">
                      <th className="px-6 py-4" style={{ width: '12%' }}>Severity</th>
                      <th className="px-6 py-4" style={{ width: '35%' }}>Vulnerability / Check Name</th>
                      <th className="px-6 py-4" style={{ width: '25%' }}>OWASP Map</th>
                      <th className="px-6 py-4 text-center" style={{ width: '15%' }}>Confidence</th>
                      <th className="px-6 py-4 text-right print:hidden" style={{ width: '13%' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {sortedFindings.map((finding, idx) => {
                      const activeTab = snippetTabs[idx] || (finding.remediation_snippets ? Object.keys(finding.remediation_snippets)[0] : null);
                      
                      return (
                        <React.Fragment key={idx}>
                          <tr 
                            onClick={() => setExpandedRow(expandedRow === idx ? null : idx)}
                            className={`cursor-pointer hover:bg-slate-800/20 transition-colors ${expandedRow === idx ? 'bg-slate-800/30' : ''}`}
                          >
                            <td className="px-6 py-4 whitespace-nowrap">
                              {getSeverityBadge(finding.severity)}
                            </td>
                            <td className="px-6 py-4 font-bold text-slate-200 align-top">
                              <div>{finding.name}</div>
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
                            <td className="px-6 py-4 text-right print:hidden align-top">
                              <button className="text-slate-500 hover:text-white transition-colors">
                                {expandedRow === idx ? <ChevronUp className="w-5 h-5 inline" /> : <ChevronDown className="w-5 h-5 inline" />}
                              </button>
                            </td>
                          </tr>
                          
                          {/* Print-only row for full-width code snippet */}
                          {finding.remediation_snippets?.nginx && (
                            <tr className="hidden print:table-row">
                              <td colSpan={5} className="px-6 pb-6 pt-0 w-full block">
                                <div className="bg-slate-50 p-4 rounded border border-slate-200 w-full block">
                                  <div className="text-[10px] font-bold text-slate-500 uppercase mb-1">Remediation Snippet (Nginx/Server)</div>
                                  <pre className="text-slate-800 font-mono text-[10px] whitespace-pre-wrap">{finding.remediation_snippets.nginx}</pre>
                                </div>
                              </td>
                            </tr>
                          )}
                          
                          <AnimatePresence>
                            {expandedRow === idx && (
                              <tr className="print:hidden">
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

                                        {finding.impact && finding.impact !== "N/A" && (
                                          <div>
                                            <div className="text-xs font-bold text-rose-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                                              <span>⚠️</span> Security Impact & Risk
                                            </div>
                                            <p className="text-rose-200/80 leading-relaxed text-sm">{finding.impact}</p>
                                          </div>
                                        )}

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

                                        {/* Tabbed Code Snippets */}
                                        {finding.remediation_snippets && Object.keys(finding.remediation_snippets).length > 0 && (
                                          <div className="mt-6">
                                            <div className="mb-4">
                                              <h4 className="text-sm font-bold text-slate-200 flex items-center gap-2 mb-1">
                                                <span>🛠️</span> QUICK FIX / REMEDIATION SNIPPET
                                              </h4>
                                              <p className="text-xs text-slate-400">
                                                Select your web server or hosting platform below to copy the required configuration code:
                                              </p>
                                            </div>
                                            <div className="border border-slate-800 rounded-xl overflow-hidden bg-[#0D1117]">
                                            <div className="flex items-center bg-slate-900 border-b border-slate-800 overflow-x-auto">
                                              {Object.keys(finding.remediation_snippets).map(platform => (
                                                <button
                                                  key={platform}
                                                  onClick={(e) => { e.stopPropagation(); handleSnippetTabChange(idx, platform); }}
                                                  className={`px-4 py-2 text-xs font-mono uppercase tracking-wider transition-colors ${activeTab === platform ? 'bg-indigo-900/40 text-indigo-300 border-b-2 border-indigo-500' : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/50'}`}
                                                >
                                                  {platform}
                                                </button>
                                              ))}
                                              <div className="ml-auto pr-3">
                                                <button onClick={() => copyToClipboard(finding.remediation_snippets[activeTab])} className="text-slate-500 hover:text-white text-xs flex items-center gap-1 transition-colors">
                                                  <Copy className="w-3 h-3" /> Copy Code
                                                </button>
                                              </div>
                                            </div>
                                            <div className="p-4 bg-[#0a0d12]">
                                              <pre className="text-indigo-200 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap leading-relaxed">
                                                {finding.remediation_snippets[activeTab]}
                                              </pre>
                                            </div>
                                            </div>
                                          </div>
                                        )}
                                      </div>

                                      <div className="space-y-6">
                                        {finding.remediation && finding.remediation !== "N/A" && (
                                          <div className="bg-indigo-950/20 border border-indigo-900/50 rounded-xl p-5">
                                            <div className="flex justify-between items-center mb-2">
                                              <div className="text-xs font-bold text-indigo-400 uppercase tracking-widest flex items-center gap-2">
                                                <Shield className="w-4 h-4" /> Remediation Directive
                                              </div>
                                              <button onClick={() => copyToClipboard(finding.remediation)} className="text-indigo-400 hover:text-indigo-300 text-xs flex items-center gap-1 transition-colors">
                                                <Copy className="w-3 h-3" /> Copy Directive
                                              </button>
                                            </div>
                                            <p className="text-indigo-200/80 font-mono text-sm leading-relaxed p-3 bg-indigo-950/40 rounded-lg border border-indigo-900/30">
                                              {finding.remediation}
                                            </p>
                                          </div>
                                        )}
                                        
                                        <div className="space-y-3">
                                          <div className="flex justify-between items-center text-xs border-b border-slate-800 pb-2">
                                            <span className="text-slate-500">Category</span>
                                            <span className="font-mono text-slate-300 uppercase">{finding.category || 'N/A'}</span>
                                          </div>
                                          <div className="flex justify-between items-center text-xs border-b border-slate-800 pb-2">
                                            <span className="text-slate-500">Scanner Module</span>
                                            <span className="font-mono text-slate-300">{finding.module || 'HeuristicEngine'}</span>
                                          </div>
                                          {finding.cvss && (
                                            <div className="flex justify-between items-center text-xs border-b border-slate-800 pb-2">
                                              <span className="text-slate-500">CVSS v3.1</span>
                                              <span className="font-mono text-rose-400 font-bold">{finding.cvss}</span>
                                            </div>
                                          )}
                                        </div>
                                      </div>

                                    </div>
                                  </motion.div>
                                </td>
                              </tr>
                            )}
                          </AnimatePresence>
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </motion.div>
        )}

        {activeView === 'compliance' && reportData?.technical_compliance && (
          <motion.div key="compliance" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} className="space-y-6">
            <div className="bg-[#0D1117] border border-slate-800 rounded-xl p-6 shadow-2xl">
              <div className="flex items-center gap-3 mb-6">
                <ShieldAlert className="w-5 h-5 text-indigo-400" />
                <h3 className="font-bold text-white text-lg">Technical Compliance Readiness</h3>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                
                {/* PCI-DSS */}
                <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5">
                  <div className="flex justify-between items-center mb-4 border-b border-slate-800 pb-3">
                    <h4 className="font-bold text-slate-200 text-sm">PCI-DSS 4.0</h4>
                    <span className={`px-2 py-1 text-[10px] font-bold uppercase tracking-wider rounded-md ${reportData.technical_compliance.pci_dss_4_0?.status === 'Compliant' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
                      {reportData.technical_compliance.pci_dss_4_0?.status || 'Unknown'}
                    </span>
                  </div>
                  
                  <div className="space-y-4">
                    <div>
                      <div className="text-xs font-bold text-red-400 mb-2 flex items-center gap-1"><XCircle className="w-3 h-3" /> Failed Controls</div>
                      <ul className="text-xs text-slate-300 space-y-1 ml-4 list-disc marker:text-slate-600">
                        {(reportData.technical_compliance.pci_dss_4_0?.failed_controls || []).map((c, i) => <li key={i}>{c}</li>)}
                        {reportData.technical_compliance.pci_dss_4_0?.failed_controls?.length === 0 && <li className="text-slate-500">None</li>}
                      </ul>
                    </div>
                    <div>
                      <div className="text-xs font-bold text-emerald-400 mb-2 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Passed Controls</div>
                      <ul className="text-xs text-slate-300 space-y-1 ml-4 list-disc marker:text-slate-600">
                        {(reportData.technical_compliance.pci_dss_4_0?.passed_controls || []).map((c, i) => <li key={i}>{c}</li>)}
                        {reportData.technical_compliance.pci_dss_4_0?.passed_controls?.length === 0 && <li className="text-slate-500">None</li>}
                      </ul>
                    </div>
                  </div>
                </div>

                {/* NIST SP 800-53 */}
                <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5">
                  <div className="flex justify-between items-center mb-4 border-b border-slate-800 pb-3">
                    <h4 className="font-bold text-slate-200 text-sm">NIST SP 800-53</h4>
                    <span className={`px-2 py-1 text-[10px] font-bold uppercase tracking-wider rounded-md ${reportData.technical_compliance.nist_sp_800_53?.status === 'Compliant' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
                      {reportData.technical_compliance.nist_sp_800_53?.status || 'Unknown'}
                    </span>
                  </div>
                  
                  <div className="space-y-4">
                    <div>
                      <div className="text-xs font-bold text-red-400 mb-2 flex items-center gap-1"><XCircle className="w-3 h-3" /> Failed Controls</div>
                      <ul className="text-xs text-slate-300 space-y-1 ml-4 list-disc marker:text-slate-600">
                        {(reportData.technical_compliance.nist_sp_800_53?.failed_controls || []).map((c, i) => <li key={i}>{c}</li>)}
                        {reportData.technical_compliance.nist_sp_800_53?.failed_controls?.length === 0 && <li className="text-slate-500">None</li>}
                      </ul>
                    </div>
                    <div>
                      <div className="text-xs font-bold text-emerald-400 mb-2 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Passed Controls</div>
                      <ul className="text-xs text-slate-300 space-y-1 ml-4 list-disc marker:text-slate-600">
                        {(reportData.technical_compliance.nist_sp_800_53?.passed_controls || []).map((c, i) => <li key={i}>{c}</li>)}
                        {reportData.technical_compliance.nist_sp_800_53?.passed_controls?.length === 0 && <li className="text-slate-500">None</li>}
                      </ul>
                    </div>
                  </div>
                </div>

                {/* ISO 27001 */}
                <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5">
                  <div className="flex justify-between items-center mb-4 border-b border-slate-800 pb-3">
                    <h4 className="font-bold text-slate-200 text-sm">ISO 27001</h4>
                    <span className={`px-2 py-1 text-[10px] font-bold uppercase tracking-wider rounded-md ${reportData.technical_compliance.iso_27001?.status === 'Compliant' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
                      {reportData.technical_compliance.iso_27001?.status || 'Unknown'}
                    </span>
                  </div>
                  
                  <div className="space-y-4">
                    <div>
                      <div className="text-xs font-bold text-red-400 mb-2 flex items-center gap-1"><XCircle className="w-3 h-3" /> Failed Controls</div>
                      <ul className="text-xs text-slate-300 space-y-1 ml-4 list-disc marker:text-slate-600">
                        {(reportData.technical_compliance.iso_27001?.failed_controls || []).map((c, i) => <li key={i}>{c}</li>)}
                        {reportData.technical_compliance.iso_27001?.failed_controls?.length === 0 && <li className="text-slate-500">None</li>}
                      </ul>
                    </div>
                    <div>
                      <div className="text-xs font-bold text-emerald-400 mb-2 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Passed Controls</div>
                      <ul className="text-xs text-slate-300 space-y-1 ml-4 list-disc marker:text-slate-600">
                        {(reportData.technical_compliance.iso_27001?.passed_controls || []).map((c, i) => <li key={i}>{c}</li>)}
                        {reportData.technical_compliance.iso_27001?.passed_controls?.length === 0 && <li className="text-slate-500">None</li>}
                      </ul>
                    </div>
                  </div>
                </div>

              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* 5. Final Recommendation */}
      <div className="text-center mt-12 py-12 border-t border-slate-800">
        <h3 className="text-2xl font-black text-white mb-4">Ready to improve your score?</h3>
        <p className="text-slate-400 text-lg max-w-2xl mx-auto">
          Interested in advanced testing? Let's chat on WhatsApp!
        </p>
      </div>

    </div>
  );
};

export default TechnicalReport;
