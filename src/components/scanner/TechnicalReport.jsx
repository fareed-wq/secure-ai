import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, Clock, Server, FileCode, CheckCircle, AlertTriangle, Info, Copy, Shield, ShieldAlert, ChevronDown, ChevronUp, Layers, Check, XCircle, Globe, Activity, Lock, ShieldCheck } from 'lucide-react';


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
      'Critical': 'bg-red-950 text-red-400 border border-red-800 font-bold px-2 py-0.5 rounded text-xs',
      'High': 'bg-red-600 text-white font-bold px-2.5 py-1 rounded text-xs shadow-sm',
      'Medium': 'bg-orange-500 text-white font-bold px-2.5 py-1 rounded text-xs shadow-sm',
      'Low': 'bg-yellow-400 text-black font-bold px-2.5 py-1 rounded text-xs shadow-sm',
      'Informational': 'bg-blue-600 text-white font-bold px-2.5 py-1 rounded text-xs shadow-sm',
      'Passed': 'bg-emerald-500 text-black font-bold px-2.5 py-1 rounded text-xs shadow-sm'
    };
    return <span className={`uppercase tracking-widest ${styles[severity] || 'bg-slate-700 text-white font-bold px-2.5 py-1 rounded text-xs shadow-sm'}`}>{severity}</span>;
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
      
      {/* 1. Technical Metadata Table HUD */}
      <div className="report-section bg-slate-950/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-xl shadow-2xl relative overflow-hidden">
        
        {/* Top Header Bar */}
        <div className="flex items-center gap-3 mb-2">
          <span className="font-mono text-xs font-bold text-cyan-400 tracking-wider">›_ SCAN_METADATA</span>
          <span className="text-slate-600 font-mono text-xs">/</span>
          <div className="flex items-center gap-2">
            <div className="bg-emerald-500 animate-pulse w-2 h-2 rounded-full"></div>
            <span className="font-mono text-xs text-slate-300">{reportData?.url}</span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mt-4">
          
          {/* Card 1: Network & Edge Security */}
          <div className="bg-slate-900/60 border border-slate-800/80 hover:border-slate-700/80 rounded-xl p-4.5 flex flex-col justify-between transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/5 p-4">
            <div>
              <div className="flex items-center gap-1.5 mb-2">
                <Globe className="w-3.5 h-3.5 text-slate-400" />
                <div className="text-slate-400 text-xs font-mono uppercase tracking-wider font-semibold">IP ADDRESS & LOCATION</div>
              </div>
              <div className="font-mono text-lg font-bold text-white tracking-tight truncate">{reportData?.metadata?.ip_address || reportData?.ip_address || 'N/A'}</div>
              <div className="text-xs text-slate-400 mt-1 truncate mb-3">{reportData?.metadata?.location_or_cdn || reportData?.location_or_cdn || 'CDN / Cloud'}</div>
            </div>
            <div>
              <span className="px-2.5 py-1 text-[11px] font-mono font-bold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 rounded-md uppercase tracking-wider inline-block">
                {reportData?.metadata?.waf_cdn_detection || 'DIRECT ORIGIN'}
              </span>
            </div>
          </div>
          
          {/* Card 2: HTTP & Performance */}
          <div className="bg-slate-900/60 border border-slate-800/80 hover:border-slate-700/80 rounded-xl p-4.5 flex flex-col justify-between transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/5 p-4">
            <div>
              <div className="flex items-center gap-1.5 mb-2">
                <Activity className="w-3.5 h-3.5 text-slate-400" />
                <div className="text-slate-400 text-xs font-mono uppercase tracking-wider font-semibold">HTTP STATUS & SERVER</div>
              </div>
              <div 
                className="font-mono text-sm font-bold text-white tracking-tight leading-tight break-words line-clamp-2 cursor-help"
                title={reportData?.metadata?.http_status || '200 OK'}
              >
                {reportData?.metadata?.http_status || '200 OK'}
              </div>
              <div className="text-xs text-slate-400 mt-1 truncate mb-3">{
                (reportData?.metadata?.server_header || reportData?.server_header) 
                  ? (String(reportData?.metadata?.server_header || reportData?.server_header).startsWith("Server:") 
                     ? (reportData?.metadata?.server_header || reportData?.server_header) 
                     : `Server: ${reportData?.metadata?.server_header || reportData?.server_header}`)
                  : 'Server: Hidden'
              }</div>
            </div>
            <div>
              <span className={`px-2.5 py-1 text-[11px] font-mono font-bold rounded-md uppercase tracking-wider inline-block border ${reportData?.metadata?.performance_rating === 'Optimal Latency' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : reportData?.metadata?.performance_rating === 'Average Latency' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' : 'bg-rose-500/10 text-rose-400 border-rose-500/30'}`}>
                {reportData?.metadata?.performance_rating || 'OPTIMAL LATENCY'}
              </span>
            </div>
          </div>
          
          {/* Card 3: SSL/TLS Certificate */}
          <div className="bg-slate-900/60 border border-slate-800/80 hover:border-slate-700/80 rounded-xl p-4.5 flex flex-col justify-between transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/5 p-4">
            <div>
              <div className="flex items-center gap-1.5 mb-2">
                <Lock className="w-3.5 h-3.5 text-slate-400" />
                <div className="text-slate-400 text-xs font-mono uppercase tracking-wider font-semibold">SSL/TLS ENCRYPTION</div>
              </div>
              <div 
                className="font-mono text-sm font-bold text-white tracking-tight leading-tight break-words line-clamp-2 cursor-help"
                title={reportData?.metadata?.ssl_issuer || reportData?.ssl_issuer || 'Valid SSL'}
              >
                {reportData?.metadata?.ssl_issuer || reportData?.ssl_issuer || 'Valid SSL'}
              </div>
              <div className="text-xs text-slate-400 mt-1 truncate mb-3">
                {reportData?.metadata?.tls_version || 'TLS'} · <span className={
                  reportData?.metadata?.ssl_days_left_int < 14 ? "text-rose-400 font-semibold" :
                  reportData?.metadata?.ssl_days_left_int <= 30 ? "text-amber-400 font-semibold" :
                  "text-emerald-400 font-semibold"
                }>{reportData?.metadata?.ssl_days_left || reportData?.ssl_days_left || 'Active'}</span>
              </div>
            </div>
            <div>
              <span className={`px-2.5 py-1 text-[11px] font-mono font-bold rounded-md uppercase tracking-wider inline-block border ${
                reportData?.metadata?.ssl_days_left_int < 0 ? 'bg-red-500/10 text-red-500 border-red-500/30' :
                reportData?.metadata?.ssl_days_left_int <= 30 ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' : 
                'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
              }`}>
                {reportData?.metadata?.ssl_days_left_int < 0 ? 'EXPIRED' : reportData?.metadata?.ssl_days_left_int <= 30 ? 'RENEWAL IMMINENT' : 'VALID CERTIFICATE'}
              </span>
            </div>
          </div>

          {/* Card 4: Traffic & Protocol Posture */}
          <div className="bg-slate-900/60 border border-slate-800/80 hover:border-slate-700/80 rounded-xl p-4.5 flex flex-col justify-between transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/5 p-4">
            <div>
              <div className="flex items-center gap-1.5 mb-2">
                <ShieldCheck className="w-3.5 h-3.5 text-slate-400" />
                <div className="text-slate-400 text-xs font-mono uppercase tracking-wider font-semibold">SECURITY & PROTOCOL</div>
              </div>
              <div className="font-mono text-lg font-bold text-white tracking-tight truncate">{reportData?.metadata?.https_enforced || 'HTTPS Status Unknown'}</div>
              <div className="text-xs text-slate-400 mt-1 truncate mb-3">
                {reportData?.metadata?.http_protocol || 'HTTP/1.1'} · {reportData?.metadata?.ipv6_supported ? 'IPv6 Supported' : 'IPv4 Only'}
              </div>
            </div>
            <div>
              <span className={`px-2.5 py-1 text-[11px] font-mono font-bold rounded-md uppercase tracking-wider inline-block border ${(reportData?.metadata?.clean_redirect === 'Clean 301 Redirect' || reportData?.metadata?.clean_redirect === 'Direct Secure') ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-rose-500/10 text-rose-400 border-rose-500/30'}`}>
                {reportData?.metadata?.clean_redirect || 'DIRECT SECURE'}
              </span>
            </div>
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
            <div className="report-section bg-[#0D1117] border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
              <div className="bg-slate-900 px-6 py-4 border-b border-slate-800 flex items-center gap-3">
                <FileCode className="w-5 h-5 text-indigo-400" />
                <h3 className="font-bold text-white text-lg">Detailed Vulnerability Matrix</h3>
              </div>
              
              <div className="w-full overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-900/50 border-b border-slate-800 text-xs font-bold text-slate-500 uppercase tracking-widest">
                      <th className="px-6 py-4" style={{ width: '15%' }}>Severity</th>
                      <th className="px-6 py-4" style={{ width: '45%' }}>Vulnerability / Check Name</th>
                      <th className="px-6 py-4" style={{ width: '25%' }}>OWASP Map</th>
                      <th className="px-6 py-4 text-right print:hidden" style={{ width: '15%' }}>Action</th>
                    </tr>
                  </thead>
                    {sortedFindings.map((finding, idx) => {
                      const activeTab = snippetTabs[idx] || (finding.remediation_snippets ? Object.keys(finding.remediation_snippets)[0] : null);
                      
                      return (
                        <tbody key={idx} className="finding-card divide-y divide-slate-800/50">
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
                                <span className="bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 px-2.5 py-1 rounded-md text-xs hover:bg-indigo-500/20 cursor-pointer">{finding.owasp}</span>
                              ) : (
                                <span className="text-slate-600 text-xs">-</span>
                              )}
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
                                            <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed shadow-inner">
                                              {`[-] HTTP Response Header Audit\n[!] Target: ${finding.name} -> [NOT FOUND]\n\n${finding.evidence}`}
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
                                                  className={`px-4 py-1.5 text-xs font-mono uppercase tracking-wider transition-colors m-1 ${activeTab === platform ? 'bg-indigo-600 text-white font-medium rounded-md shadow-sm' : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/50 rounded-md'}`}
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
                                            <div className="bg-slate-950 border-t-0 border border-slate-800/80 rounded-b-lg p-4">
                                              <pre className="text-emerald-400 font-mono text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed">
                                                {finding.remediation_snippets[activeTab]}
                                              </pre>
                                            </div>
                                            </div>
                                          </div>
                                        )}
                                      </div>

                                      <div className="space-y-6">
                                        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col gap-3 h-full">
                                          {finding.remediation && finding.remediation !== "N/A" && (
                                            <>
                                              <div className="text-xs font-bold text-indigo-400 uppercase tracking-widest mb-2 flex items-center gap-2">
                                                <Shield className="w-4 h-4" /> Remediation Directive
                                              </div>
                                              <p className="text-slate-300 text-sm leading-relaxed mb-4">
                                                {finding.remediation}
                                              </p>
                                            </>
                                          )}
                                          
                                          <div className="space-y-3 mt-auto pt-4 border-t border-slate-800/80">
                                            <div className="flex justify-between items-center text-xs">
                                              <span className="text-slate-500">Category</span>
                                              <span className="font-mono text-slate-300 uppercase">{finding.category || 'HTTP_HEADERS'}</span>
                                            </div>
                                            <div className="flex justify-between items-center text-xs">
                                              <span className="text-slate-500">Scanner Module</span>
                                              <span className="font-mono text-slate-300">{finding.module || 'SecurityHeaders'}</span>
                                            </div>
                                            {finding.cvss && (
                                              <div className="flex items-center justify-between text-xs text-slate-400">
                                                <span>CVSS v3.1 Score:</span>
                                                <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 font-bold">{finding.cvss}</span>
                                              </div>
                                            )}
                                          </div>
                                        </div>
                                      </div>

                                    </div>
                                  </motion.div>
                                </td>
                              </tr>
                            )}
                          </AnimatePresence>
                        </tbody>
                      );
                    })}
                  </table>
              </div>
            </div>
          </motion.div>
        )}

        {activeView === 'compliance' && reportData?.technical_compliance && (
          <motion.div key="compliance" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}>
            <div className="report-section grid grid-cols-1 gap-6">
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
                    <span className={`px-2 py-1 text-[10px] font-bold uppercase tracking-wider rounded-md border ${reportData.technical_compliance.pci_dss_4_0?.status === 'Compliant' ? 'bg-emerald-950/80 text-emerald-400 border-emerald-800' : 'bg-red-500/20 text-red-400 border-red-500/20'}`}>
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
                    <span className={`px-2 py-1 text-[10px] font-bold uppercase tracking-wider rounded-md border ${reportData.technical_compliance.nist_sp_800_53?.status === 'Compliant' ? 'bg-emerald-950/80 text-emerald-400 border-emerald-800' : 'bg-red-500/20 text-red-400 border-red-500/20'}`}>
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
                    <span className={`px-2 py-1 text-[10px] font-bold uppercase tracking-wider rounded-md border ${reportData.technical_compliance.iso_27001?.status === 'Compliant' ? 'bg-emerald-950/80 text-emerald-400 border-emerald-800' : 'bg-red-500/20 text-red-400 border-red-500/20'}`}>
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
