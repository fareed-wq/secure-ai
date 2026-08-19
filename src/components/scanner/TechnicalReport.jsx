import React, { useState } from 'react';
import { Terminal, CheckCircle, Copy, Shield, ShieldAlert, ChevronDown, ChevronUp, XCircle, Globe, Activity, Lock, ShieldCheck } from 'lucide-react';
import { RemediationSnippetBox } from './RemediationSnippetBox';


const TechnicalReport = ({ reportData }) => {
  const [expandedRow, setExpandedRow] = useState(null);
  const [activeView, setActiveView] = useState('vulnerabilities'); // 'vulnerabilities' | 'compliance'
  const [snippetTabs, setSnippetTabs] = useState({}); // { findingIndex: 'nginx' }

  const findings = reportData?.findings || [];

  const sortedFindings = [...findings].sort((a, b) => {
    const weights = { Critical: 6, High: 5, Medium: 4, Low: 3, Informational: 2, Passed: 1 };
    return (weights[b.severity] || 0) - (weights[a.severity] || 0);
  });

  const domainGroups = [
    { key: 'transport_tls', label: 'Transport & TLS Security', icon: <Lock className="w-4 h-4 text-cyan-400" /> },
    { key: 'browser_defense', label: 'Browser Defense Headers', icon: <Shield className="w-4 h-4 text-indigo-400" /> },
    { key: 'api_surface', label: 'API & Application Surface', icon: <Terminal className="w-4 h-4 text-amber-400" /> },
    { key: 'email_domain', label: 'Email & Domain Trust', icon: <Globe className="w-4 h-4 text-emerald-400" /> },
  ];

  const getSeverityBadge = (severity) => {
    const styles = {
      'Critical': 'bg-red-950 text-red-400 border border-red-800 font-bold px-2 py-0.5 rounded text-xs',
      'High': 'bg-red-600 text-white font-bold px-2.5 py-1 rounded text-xs shadow-sm',
      'Medium': 'bg-orange-500 text-white font-bold px-2.5 py-1 rounded text-xs shadow-sm',
      'Low': 'bg-yellow-400 text-black font-bold px-2.5 py-1 rounded text-xs shadow-sm',
      'Informational': 'bg-blue-600 text-white font-bold px-2.5 py-1 rounded text-xs shadow-sm',
      'Passed': 'bg-emerald-500 text-black font-bold px-2.5 py-1 rounded text-xs shadow-sm'
    };
    return <span className={`uppercase tracking-widest ${styles[severity] || 'bg-slate-700 text-slate-50 font-bold px-2.5 py-1 rounded text-xs shadow-sm'}`}>{severity}</span>;
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="technical-report space-y-8" id="report-content">
      <style>{`
        @media print {
          body, html, #report-content { background: white !important; color: #0f172a !important; }
          * { border-color: #e2e8f0 !important; }
          .bg-\\[\\#0D1117\\], .bg-slate-900, .bg-slate-900\\/50, .bg-slate-800 { background: white !important; box-shadow: none !important; }
          .text-slate-50, .text-slate-200, .text-slate-300 { color: #0f172a !important; }
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
      <div className="technical-section report-section bg-slate-950/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-xl shadow-2xl relative overflow-hidden">

        {/* Top Header Bar */}
        <div className="flex items-center gap-3 mb-2">
          <span className="font-mono text-xs font-bold text-cyan-400 tracking-wider">›_ SCAN_METADATA</span>
          <span className="text-slate-600 font-mono text-xs">/</span>
          <div className="flex items-center gap-2">
            <div className="bg-emerald-500 animate-pulse w-2 h-2 rounded-full"></div>
            <span className="font-mono text-xs text-slate-300">{reportData?.url}</span>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 w-full">

          {/* Card 1: Network & Edge Security */}
          <div className="technical-metadata w-full min-w-0 h-full min-h-[150px] p-4 bg-slate-900/60 border border-slate-800 hover:border-slate-700/80 rounded-xl flex flex-col justify-between transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/5">
            <div>
              <div className="flex items-center gap-2 text-[11px] font-bold font-mono tracking-wider text-slate-400 uppercase h-5">
                <Globe className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                IP ADDRESS & LOCATION
              </div>
              <div className="text-sm sm:text-base font-bold text-slate-100 font-mono break-all mt-2">
                {reportData?.metadata?.ip_address || 'N/A'}
              </div>
              <div className="text-xs text-slate-400 truncate mt-0.5 h-5 flex items-center">
                {reportData?.metadata?.location_or_cdn || 'Unknown Location'}
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-1.5 mt-auto pt-2 w-full">
              <span className="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-mono font-semibold tracking-wider whitespace-nowrap shrink-0 max-w-full overflow-hidden text-ellipsis border bg-indigo-500/10 text-indigo-400 border-indigo-500/20 uppercase">
                {reportData?.metadata?.waf_cdn_detection || 'Routing Unknown'}
              </span>
              {reportData?.metadata?.whois?.age && reportData?.metadata?.whois?.age !== 'Unknown' && (
                <span
                  className="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-mono font-semibold tracking-wider whitespace-nowrap shrink-0 max-w-full overflow-hidden text-ellipsis border bg-slate-800/80 text-slate-400 border-slate-700/80 uppercase cursor-help"
                  title={reportData?.metadata?.whois?.registrar !== 'Unknown' ? `Registrar: ${reportData.metadata.whois.registrar}` : 'WHOIS Data'}
                >
                  {reportData.metadata.whois.age}
                </span>
              )}
            </div>
          </div>

          {/* Card 2: HTTP & Performance */}
          <div className="technical-metadata w-full min-w-0 h-full min-h-[150px] p-4 bg-slate-900/60 border border-slate-800 hover:border-slate-700/80 rounded-xl flex flex-col justify-between transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/5">
            <div>
              <div className="flex items-center gap-2 text-[11px] font-bold font-mono tracking-wider text-slate-400 uppercase h-5">
                <Activity className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                HTTP STATUS & SERVER
              </div>
              <div
                className="text-sm sm:text-base font-bold text-slate-100 font-mono break-all mt-2 cursor-help"
                title={reportData?.metadata?.http_status != null && reportData?.metadata?.http_status !== 0 ? reportData.metadata.http_status : 'Status Unknown'}
              >
                {reportData?.metadata?.http_status != null && reportData?.metadata?.http_status !== 0 ? reportData.metadata.http_status : 'Status Unknown'}
              </div>
              <div className="text-xs text-slate-400 truncate mt-0.5 h-5 flex items-center">
                {(reportData?.metadata?.server_header)
                  ? (String(reportData?.metadata?.server_header).startsWith("Server:")
                     ? (reportData?.metadata?.server_header)
                     : `Server: ${reportData?.metadata?.server_header}`)
                  : 'Server: Hidden'
                }
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-1.5 mt-auto pt-2 w-full">
              <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-mono font-semibold tracking-wider whitespace-nowrap shrink-0 max-w-full overflow-hidden text-ellipsis uppercase border ${
                reportData?.metadata?.performance_rating === 'NO HTTP RESPONSE' ? 'bg-slate-500/10 text-slate-400 border-slate-500/30' :
                reportData?.metadata?.performance_rating === 'REQUEST TIMEOUT' ? 'bg-slate-500/10 text-slate-400 border-slate-500/30' :
                reportData?.metadata?.performance_rating === 'Optimal Latency' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' :
                reportData?.metadata?.performance_rating === 'Average Latency' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
                (reportData?.metadata?.performance_rating === 'High Latency' || reportData?.metadata?.performance_rating === 'SERVER ERROR' || reportData?.metadata?.performance_rating === 'CLIENT ERROR' || reportData?.metadata?.performance_rating === 'TIMEOUT') ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' : 'bg-slate-500/10 text-slate-400 border-slate-500/30'
              }`}>
                {reportData?.metadata?.performance_rating || 'Latency Unknown'}
              </span>
            </div>
          </div>

          {/* Card 3: SSL/TLS Certificate */}
          <div className="technical-metadata w-full min-w-0 h-full min-h-[150px] p-4 bg-slate-900/60 border border-slate-800 hover:border-slate-700/80 rounded-xl flex flex-col justify-between transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/5">
            <div>
              <div className="flex items-center gap-2 text-[11px] font-bold font-mono tracking-wider text-slate-400 uppercase h-5">
                <Lock className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                SSL/TLS ENCRYPTION
              </div>
              <div
                className="text-sm sm:text-base font-bold text-slate-100 font-mono break-all mt-2 cursor-help"
                title={reportData?.metadata?.ssl_issuer || 'Unknown Issuer'}
              >
                {reportData?.metadata?.ssl_issuer || 'Unknown Issuer'}
              </div>
              <div className="text-xs text-slate-400 truncate mt-0.5 h-5 flex items-center">
                {reportData?.metadata?.tls_version || 'TLS'} · <span className={`ml-1 ${
                  reportData?.metadata?.ssl_days_left_int < 14 ? "text-rose-400 font-semibold" :
                  reportData?.metadata?.ssl_days_left_int <= 30 ? "text-amber-400 font-semibold" :
                  "text-emerald-400 font-semibold"
                }`}>{reportData?.metadata?.ssl_days_left || 'Unknown Status'}</span>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-1.5 mt-auto pt-2 w-full">
              <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-mono font-semibold tracking-wider whitespace-nowrap shrink-0 max-w-full overflow-hidden text-ellipsis uppercase border ${
                reportData?.metadata?.ssl_badge === 'EXPIRED' ? 'bg-red-500/10 text-red-400 border-red-500/30' :
                reportData?.metadata?.ssl_badge === 'RENEWAL IMMINENT' ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' :
                reportData?.metadata?.ssl_badge === 'VALID CERTIFICATE (UNTRUSTED)' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
                reportData?.metadata?.ssl_badge === 'VALID CERTIFICATE' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' :
                'bg-slate-500/10 text-slate-400 border-slate-500/30'
              }`}>
                {reportData?.metadata?.ssl_badge || 'SSL Unknown'}
              </span>
            </div>
          </div>

          {/* Card 4: Traffic & Protocol Posture */}
          <div className="technical-metadata w-full min-w-0 h-full min-h-[150px] p-4 bg-slate-900/60 border border-slate-800 hover:border-slate-700/80 rounded-xl flex flex-col justify-between transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/5">
            <div>
              <div className="flex items-center gap-2 text-[11px] font-bold font-mono tracking-wider text-slate-400 uppercase h-5">
                <ShieldCheck className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                SECURITY & PROTOCOL
              </div>
              <div className="text-sm sm:text-base font-bold text-slate-100 font-mono break-all mt-2">
                {reportData?.metadata?.https_enforced ?? 'HTTPS Status Unknown'}
              </div>
              <div className="text-xs text-slate-400 truncate mt-0.5 h-5 flex items-center">
                {reportData?.metadata?.http_protocol || 'HTTP/1.1'} · {reportData?.metadata?.ipv6_supported ? 'IPv6 Supported' : 'IPv4 Only'}
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-1.5 mt-auto pt-2 w-full">
              <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-mono font-semibold tracking-wider whitespace-nowrap shrink-0 max-w-full overflow-hidden text-ellipsis uppercase border ${reportData?.metadata?.clean_redirect === 'Clean 301 Redirect' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : (reportData?.metadata?.clean_redirect === 'Direct Request' || reportData?.metadata?.clean_redirect === 'Routing Unknown') ? 'bg-slate-500/10 text-slate-400 border-slate-500/30' : 'bg-rose-500/10 text-rose-400 border-rose-500/30'}`}>
                {reportData?.metadata?.clean_redirect || 'Routing Unknown'}
              </span>
            </div>
          </div>

        </div>
      </div>



      {/* 3. Tab Switcher: Vulnerabilities vs Compliance */}
      <div className="flex bg-slate-950 border border-slate-800 p-1 rounded-xl w-full max-w-md mx-auto shadow-xl print:hidden">
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
      <div>
        {activeView === 'vulnerabilities' && (
          <div className="w-full max-w-full overflow-hidden space-y-6">
            {domainGroups.map((group) => {
              const groupFindings = sortedFindings.filter(f => f.domain === group.key);
              if (groupFindings.length === 0) return null;

              return (
                <div key={group.key} className="technical-section report-section bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
                  <div className="bg-slate-900 px-6 py-4 border-b border-slate-800 flex items-center gap-3">
                    {group.icon}
                    <h2 className="font-bold text-slate-50 text-lg">{group.label}</h2>
                  </div>

                  <div className="w-full overflow-x-auto">
                    <table className="technical-findings-table w-full text-left border-collapse">
                      <thead>
                        <tr className="bg-slate-900/50 border-b border-slate-800 text-xs font-bold text-slate-500 uppercase tracking-widest">
                          <th className="px-6 py-4" style={{ width: '15%' }}>Severity</th>
                          <th className="px-6 py-4" style={{ width: '45%' }}>Vulnerability / Check Name</th>
                          <th className="px-6 py-4" style={{ width: '25%' }}>OWASP Map</th>
                          <th className="px-6 py-4 text-right print:hidden" style={{ width: '15%' }}>Action</th>
                        </tr>
                      </thead>
                      {groupFindings.map((finding) => {
                        const idx = sortedFindings.indexOf(finding);

                        return (
                          <tbody key={idx} className="finding-card divide-y divide-slate-800/50 border-b border-slate-700/40 last:border-b-0">
                            <tr
                              onClick={() => setExpandedRow(expandedRow === idx ? null : idx)}
                              className={`technical-finding-row ${finding.severity === 'Passed' ? 'technical-passed-row' : ''} cursor-pointer hover:bg-slate-800/20 transition-colors ${expandedRow === idx ? 'bg-slate-800/30' : ''}`}
                            >
                            <td className="px-6 py-4 whitespace-nowrap">
                              {getSeverityBadge(finding.severity)}
                            </td>
                            <td className="px-6 py-4 font-bold text-slate-200 align-top">
                              <div>{finding.name}</div>
                            </td>
                            <td className="px-6 py-4">
                              {finding.owasp && finding.owasp !== "N/A" ? (
                                <span className="technical-owasp-badge bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 px-2.5 py-1 rounded-md text-xs hover:bg-indigo-500/20 cursor-pointer">{finding.owasp}</span>
                              ) : (
                                <span className="technical-owasp-badge-none text-slate-600 text-xs">-</span>
                              )}
                            </td>
                            <td className="px-6 py-4 text-right print:hidden align-top">
                              <button aria-label={expandedRow === idx ? "Collapse Details" : "Expand Details"} className="text-slate-500 hover:text-slate-50 transition-colors">
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

                          {expandedRow === idx && (
                              <tr className="technical-finding-expanded print:hidden">
                                <td colSpan={5} className="p-0 border-b-2 border-indigo-500/50">
                                  <div
                                    className="bg-slate-950 overflow-hidden transition-all duration-300"
                                  >
                                    <div className="p-8 grid grid-cols-1 lg:grid-cols-3 gap-8">

                                      <div className="lg:col-span-2 space-y-6">
                                        <div>
                                          <div className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">Technical Description</div>
                                          <p className="technical-description text-slate-300 leading-relaxed text-sm">{finding.description}</p>
                                        </div>

                                        {finding.impact && finding.impact !== "N/A" && (
                                          <div>
                                            <div className="text-xs font-bold text-rose-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                                              <span>⚠️</span> Security Impact & Risk
                                            </div>
                                            <p className="technical-risk-text text-rose-200/80 leading-relaxed text-sm">{finding.impact}</p>
                                          </div>
                                        )}

                                        {finding.confidence && finding.confidence !== "N/A" && (
                                          (() => {
                                            const lowerConf = finding.confidence.toString().toLowerCase();
                                            let level = 'medium';
                                            if (lowerConf.includes('high')) level = 'high';
                                            else if (lowerConf.includes('low')) level = 'low';
                                            else if (lowerConf.includes('%')) {
                                              const num = parseInt(lowerConf.replace(/[^0-9]/g, ''), 10);
                                              if (!isNaN(num)) {
                                                if (num >= 80) level = 'high';
                                                else if (num <= 40) level = 'low';
                                              }
                                            }

                                            let colorClass = 'text-amber-300';
                                            if (level === 'high') colorClass = 'text-emerald-400';
                                            else if (level === 'low') colorClass = 'text-slate-400';

                                            return (
                                              <div>
                                                <div className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-1">Confidence Score</div>
                                                <div className={`technical-confidence ${colorClass} font-bold mb-4`}>{finding.confidence}</div>
                                              </div>
                                            );
                                          })()
                                        )}

                                        {finding.evidence && finding.evidence !== "N/A" && (
                                          <div>
                                            <div className="flex items-center justify-between mb-2">
                                              <div className="text-xs font-bold text-slate-500 uppercase tracking-widest">Raw Evidence</div>
                                              <button onClick={() => copyToClipboard(typeof finding.evidence === 'string' ? finding.evidence : JSON.stringify(finding.evidence))} className="text-slate-500 hover:text-indigo-400 text-xs flex items-center gap-1 transition-colors">
                                                <Copy className="w-3 h-3" /> Copy
                                              </button>
                                            </div>
                                            {typeof finding.evidence === 'object' && finding.evidence.request_path ? (
                                              <div className="technical-evidence bg-slate-950 border border-slate-700/50 rounded-lg p-4 font-mono text-sm">
                                                <div className="text-cyan-400 mb-2">
                                                  GET {finding.evidence.request_path} • Status: {finding.evidence.status_code} • {finding.evidence.content_type}
                                                </div>
                                                {finding.evidence.proof_snippet && (
                                                  <div className="text-slate-300 border-t border-slate-700/50 pt-2 mt-2">
                                                    Proof: {finding.evidence.proof_snippet}
                                                  </div>
                                                )}
                                              </div>
                                            ) : (
                                              <pre className="technical-evidence bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed shadow-inner">
                                                {typeof finding.evidence === 'object' && finding.evidence.raw ? finding.evidence.raw : (typeof finding.evidence === 'string' ? finding.evidence : JSON.stringify(finding.evidence))}
                                              </pre>
                                            )}
                                          </div>
                                        )}

                                        <RemediationSnippetBox findingName={finding.name} />
                                      </div>

                                      <div className="space-y-6">
                                        <div className="technical-remediation-panel bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col gap-3 h-full">
                                          {finding.severity === 'Passed' ? (
                                            <div className="flex flex-col items-center justify-center p-6 text-center rounded-lg bg-emerald-950/20 border border-emerald-800/30 my-auto">
                                              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-400 mb-2">
                                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                                                </svg>
                                              </div>
                                              <span className="text-xs font-semibold uppercase tracking-wider text-emerald-400">
                                                Security Control Verified
                                              </span>
                                              <p className="mt-1 text-xs text-slate-400">
                                                This configuration complies with security standards. No action required.
                                              </p>
                                            </div>
                                          ) : finding.remediation && finding.remediation !== "N/A" ? (
                                            <>
                                              <div className="text-xs font-bold text-indigo-400 uppercase tracking-widest mb-2 flex items-center gap-2">
                                                <Shield className="w-4 h-4" /> Remediation Directive
                                              </div>
                                              <p className="text-slate-300 text-sm leading-relaxed mb-4">
                                                {finding.remediation}
                                              </p>
                                            </>
                                          ) : null}

                                          <div className="space-y-3 mt-auto pt-4 border-t border-slate-800/80">
                                            <div className="flex justify-between items-center text-xs">
                                              <span className="text-slate-500">Category</span>
                                              <span className="font-mono text-slate-300 uppercase">{finding.category}</span>
                                            </div>
                                            <div className="flex justify-between items-center text-xs">
                                              <span className="text-slate-500">Scanner Module</span>
                                              <span className="font-mono text-slate-300">{finding.module}</span>
                                            </div>
                                            {finding.cvss && (
                                              <div className="flex items-center justify-between text-xs text-slate-400">
                                                <span>CVSS v3.1 (Severity Default):</span>
                                                <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 font-bold">{finding.cvss}</span>
                                              </div>
                                            )}
                                          </div>
                                        </div>
                                      </div>

                                    </div>
                                  </div>
                                </td>
                              </tr>
                            )}
                        </tbody>
                      );
                    })}
                    </table>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {activeView === 'compliance' && reportData?.technical_compliance && (
          <div className="w-full max-w-full overflow-hidden">
            <div className="technical-section report-section grid grid-cols-1 gap-6">
            <div className="technical-compliance-section bg-slate-950 border border-slate-800 rounded-xl p-6 shadow-2xl">
              <div className="flex items-center gap-3 mb-6">
                <ShieldAlert className="w-5 h-5 text-indigo-400" />
                <h2 className="font-bold text-slate-50 text-lg">Technical Compliance Readiness</h2>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

                {/* PCI-DSS */}
                <div className="technical-compliance-card bg-slate-900/50 border border-slate-800 rounded-xl p-5">
                  <div className="flex justify-between items-center mb-4 border-b border-slate-800 pb-3">
                    <h3 className="font-bold text-slate-200 text-sm">PCI-DSS 4.0</h3>
                    <span className={`px-2 py-1 text-[10px] font-bold uppercase tracking-wider rounded-md border ${reportData?.technical_compliance?.pci_dss_4_0?.status === 'Compliant' ? 'technical-compliance-compliant bg-emerald-950/80 text-emerald-400 border-emerald-800' : 'technical-compliance-action bg-red-500/20 text-red-400 border-red-500/20'}`}>
                      {reportData?.technical_compliance?.pci_dss_4_0?.status || 'Unknown'}
                    </span>
                  </div>

                  <div className="space-y-4">
                    <div>
                      <div className="technical-compliance-failed-heading text-xs font-bold text-red-400 mb-2 flex items-center gap-1"><XCircle className="w-3 h-3" /> Failed Controls</div>
                      <ul className="technical-compliance-list text-xs text-slate-300 space-y-1 ml-4 list-disc marker:text-slate-600">
                        {(reportData?.technical_compliance?.pci_dss_4_0?.failed_controls || []).map((c, i) => <li key={i}>{c}</li>)}
                        {reportData?.technical_compliance?.pci_dss_4_0?.failed_controls?.length === 0 && <li className="technical-compliance-list-item-none text-slate-500">None</li>}
                      </ul>
                    </div>
                    <div>
                      <div className="technical-compliance-passed-heading text-xs font-bold text-emerald-400 mb-2 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Passed Controls</div>
                      <ul className="technical-compliance-list text-xs text-slate-300 space-y-1 ml-4 list-disc marker:text-slate-600">
                        {(reportData?.technical_compliance?.pci_dss_4_0?.passed_controls || []).map((c, i) => <li key={i}>{c}</li>)}
                        {reportData?.technical_compliance?.pci_dss_4_0?.passed_controls?.length === 0 && <li className="technical-compliance-list-item-none text-slate-500">None</li>}
                      </ul>
                    </div>
                  </div>
                </div>

                {/* NIST SP 800-53 */}
                <div className="technical-compliance-card bg-slate-900/50 border border-slate-800 rounded-xl p-5">
                  <div className="flex justify-between items-center mb-4 border-b border-slate-800 pb-3">
                    <h3 className="font-bold text-slate-200 text-sm">NIST SP 800-53</h3>
                    <span className={`px-2 py-1 text-[10px] font-bold uppercase tracking-wider rounded-md border ${reportData?.technical_compliance?.nist_sp_800_53?.status === 'Compliant' ? 'technical-compliance-compliant bg-emerald-950/80 text-emerald-400 border-emerald-800' : 'technical-compliance-action bg-red-500/20 text-red-400 border-red-500/20'}`}>
                      {reportData?.technical_compliance?.nist_sp_800_53?.status || 'Unknown'}
                    </span>
                  </div>

                  <div className="space-y-4">
                    <div>
                      <div className="technical-compliance-failed-heading text-xs font-bold text-red-400 mb-2 flex items-center gap-1"><XCircle className="w-3 h-3" /> Failed Controls</div>
                      <ul className="technical-compliance-list text-xs text-slate-300 space-y-1 ml-4 list-disc marker:text-slate-600">
                        {(reportData?.technical_compliance?.nist_sp_800_53?.failed_controls || []).map((c, i) => <li key={i}>{c}</li>)}
                        {reportData?.technical_compliance?.nist_sp_800_53?.failed_controls?.length === 0 && <li className="technical-compliance-list-item-none text-slate-500">None</li>}
                      </ul>
                    </div>
                    <div>
                      <div className="technical-compliance-passed-heading text-xs font-bold text-emerald-400 mb-2 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Passed Controls</div>
                      <ul className="technical-compliance-list text-xs text-slate-300 space-y-1 ml-4 list-disc marker:text-slate-600">
                        {(reportData?.technical_compliance?.nist_sp_800_53?.passed_controls || []).map((c, i) => <li key={i}>{c}</li>)}
                        {reportData?.technical_compliance?.nist_sp_800_53?.passed_controls?.length === 0 && <li className="technical-compliance-list-item-none text-slate-500">None</li>}
                      </ul>
                    </div>
                  </div>
                </div>

                {/* ISO 27001 */}
                <div className="technical-compliance-card bg-slate-900/50 border border-slate-800 rounded-xl p-5">
                  <div className="flex justify-between items-center mb-4 border-b border-slate-800 pb-3">
                    <h3 className="font-bold text-slate-200 text-sm">ISO 27001</h3>
                    <span className={`px-2 py-1 text-[10px] font-bold uppercase tracking-wider rounded-md border ${reportData?.technical_compliance?.iso_27001?.status === 'Compliant' ? 'technical-compliance-compliant bg-emerald-950/80 text-emerald-400 border-emerald-800' : 'technical-compliance-action bg-red-500/20 text-red-400 border-red-500/20'}`}>
                      {reportData?.technical_compliance?.iso_27001?.status || 'Unknown'}
                    </span>
                  </div>

                  <div className="space-y-4">
                    <div>
                      <div className="technical-compliance-failed-heading text-xs font-bold text-red-400 mb-2 flex items-center gap-1"><XCircle className="w-3 h-3" /> Failed Controls</div>
                      <ul className="technical-compliance-list text-xs text-slate-300 space-y-1 ml-4 list-disc marker:text-slate-600">
                        {(reportData?.technical_compliance?.iso_27001?.failed_controls || []).map((c, i) => <li key={i}>{c}</li>)}
                        {reportData?.technical_compliance?.iso_27001?.failed_controls?.length === 0 && <li className="technical-compliance-list-item-none text-slate-500">None</li>}
                      </ul>
                    </div>
                    <div>
                      <div className="technical-compliance-passed-heading text-xs font-bold text-emerald-400 mb-2 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Passed Controls</div>
                      <ul className="technical-compliance-list text-xs text-slate-300 space-y-1 ml-4 list-disc marker:text-slate-600">
                        {(reportData?.technical_compliance?.iso_27001?.passed_controls || []).map((c, i) => <li key={i}>{c}</li>)}
                        {reportData?.technical_compliance?.iso_27001?.passed_controls?.length === 0 && <li className="technical-compliance-list-item-none text-slate-500">None</li>}
                      </ul>
                    </div>
                  </div>
                </div>

              </div>
            </div>
            </div>
          </div>
        )}
      </div>

      {/* 5. Final Recommendation */}
      <div className="text-center mt-12 py-12 border-t border-slate-800">
        <h2 className="text-2xl font-black text-slate-50 mb-4">Ready to improve your score?</h2>
        <p className="text-slate-400 text-lg max-w-2xl mx-auto">
          Interested in advanced testing? Let's chat on WhatsApp!
        </p>
      </div>

    </div>
  );
};

export default TechnicalReport;
