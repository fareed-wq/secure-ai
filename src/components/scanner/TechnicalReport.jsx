import { calculateFindingPriority, calculateCvePriority } from '../../utils/priority';
import React, { useState } from 'react';
import { Terminal, Server, Cpu, Layers, Box, CheckCircle, Copy, Shield, ShieldAlert, ChevronDown, ChevronUp, XCircle, Globe, Activity, Lock, ShieldCheck } from 'lucide-react';
import { RemediationSnippetBox } from './RemediationSnippetBox';
import { WhatWasTested } from './WhatWasTested';
import { getCapabilityLabel } from '../../lib/assessmentReporting';
import { CSPAnalysisPanel } from './CSPAnalysisPanel';


const TechnicalReport = ({ reportData }) => {
  const [expandedRow, setExpandedRow] = useState(null);
  const [expandedTechRow, setExpandedTechRow] = useState(null);
  const [activeView, setActiveView] = useState('vulnerabilities'); // 'vulnerabilities' | 'compliance'
  const [snippetTabs, setSnippetTabs] = useState({}); // { findingIndex: 'nginx' }

  const findings = reportData?.findings || [];

  const sortedFindings = [...findings].sort((a, b) => {
    const weights = { Critical: 6, High: 5, Medium: 4, Low: 3, Informational: 2, Passed: 1 };
    const weightDiff = (weights[b.severity] || 0) - (weights[a.severity] || 0);
    if (weightDiff !== 0) return weightDiff;
    const nameA = a.name || '';
    const nameB = b.name || '';
    return nameA.localeCompare(nameB);
  });

  const domainGroups = [
    { key: 'transport_tls', label: 'Transport & TLS Security', icon: <Lock className="w-4 h-4 text-cyan-400" /> },
    { key: 'browser_defense', label: 'Technical Security Findings', icon: <Shield className="w-4 h-4 text-indigo-400" /> },
    { key: 'api_surface', label: 'API & Application Surface', icon: <Terminal className="w-4 h-4 text-amber-400" /> },
    { key: 'email_domain', label: 'Email & Domain Trust', icon: <Globe className="w-4 h-4 text-emerald-400" /> },
    { key: 'network_services', label: 'Network & Service Exposure', icon: <Activity className="w-4 h-4 text-purple-400" /> },
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

  const getPriorityBadge = (priority) => {
    const styles = {
      'P1': 'text-rose-400 bg-rose-950/30 border-rose-800',
      'P2': 'text-amber-400 bg-amber-950/30 border-amber-800',
      'P3': 'text-yellow-400 bg-yellow-950/30 border-yellow-800',
      'P4': 'text-cyan-400 bg-cyan-950/30 border-cyan-800',
      'P5': 'text-violet-400 bg-violet-950/30 border-violet-800',
      'UNSCORED': 'text-slate-400 bg-slate-800 border-slate-700'
    };
    const style = styles[priority] || styles['UNSCORED'];
    return <span className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded border ${style}`}>{priority}</span>;
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
          <span className="font-mono text-xs font-bold text-cyan-400 tracking-wider">&gt;_ SCAN_METADATA</span>
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



      {/* 2. Assessment Coverage */}
      {(() => {
        const cov = reportData?.assessment_coverage;
        if (!cov) return null;
        return (
          <div className="report-section bg-slate-950/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-xl shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <span className="font-mono text-xs font-bold text-cyan-400 tracking-wider">&gt;_ ASSESSMENT_COVERAGE</span>
            </div>
            {cov.available ? (
              <div className="flex flex-col sm:flex-row items-start sm:items-center gap-6">
                <div className="text-center">
                  <div className="text-4xl font-black text-slate-50 font-mono">{Math.round(cov.percentage)}%</div>
                  <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mt-1">Coverage</div>
                </div>
                <div className="flex-1 space-y-2">
                  <div className="flex flex-wrap gap-2 text-xs font-mono">
                    <span className="px-2 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">{cov.completed_modules} Completed</span>
                    {cov.partial_modules > 0 && <span className="px-2 py-1 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">{cov.partial_modules} Partial</span>}
                    {cov.failed_modules > 0 && <span className="px-2 py-1 rounded bg-red-500/10 text-red-400 border border-red-500/20">{cov.failed_modules} Failed</span>}
                    {cov.blocked_modules > 0 && <span className="px-2 py-1 rounded bg-slate-500/10 text-slate-400 border border-slate-700">{cov.blocked_modules} Blocked</span>}
                    {cov.execution_incomplete_modules > 0 && <span className="px-2 py-1 rounded bg-slate-500/10 text-slate-400 border border-slate-700">{cov.execution_incomplete_modules} Incomplete</span>}
                    {cov.not_applicable_modules > 0 && <span className="px-2 py-1 rounded bg-slate-800/60 text-slate-500 border border-slate-800">N/A: {cov.not_applicable_modules}</span>}
                  </div>
                  <div className="text-[11px] text-slate-500">Assessment Coverage shows how much of the scanner's intended assessment completed successfully. It is separate from the security score.</div>
                </div>
              </div>
            ) : (
              <div className="text-sm text-slate-500">Assessment Coverage: Not available</div>
            )}
          </div>
        );
      })()}



      <WhatWasTested moduleExecution={reportData?.module_execution} />

      {/* 2.5. Exposure */}
      {(() => {
        const exp = reportData?.exposure;
        if (!exp) return null;

        let levelColor = "text-slate-400";
        let bgColor = "bg-slate-900";
        if (exp.level === "HIGH") { levelColor = "text-red-400"; bgColor = "bg-red-500/10 border-red-500/20"; }
        else if (exp.level === "MODERATE") { levelColor = "text-amber-400"; bgColor = "bg-amber-500/10 border-amber-500/20"; }
        else if (exp.level === "LOW") { levelColor = "text-emerald-400"; bgColor = "bg-emerald-500/10 border-emerald-500/20"; }

        return (
          <div className="report-section bg-slate-950/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-xl shadow-2xl mt-6">
            <div className="flex items-center gap-3 mb-4">
              <span className="font-mono text-xs font-bold text-cyan-400 tracking-wider">&gt;_ EXPOSURE</span>
            </div>

            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-6">
              <div className="text-center min-w-[100px]">
                <div className={`text-2xl font-black font-mono ${levelColor}`}>{exp.level}</div>
                <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mt-1">Level</div>
              </div>

              <div className="flex-1 space-y-3">
                {exp.signals && exp.signals.length > 0 && (
                  <div className="space-y-1">
                    <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Observed Signals:</div>
                    <ul className="text-xs text-slate-300 space-y-1 list-disc list-inside">
                      {exp.signals.map((sig, i) => (
                        <li key={i}>{sig}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {exp.limitations && exp.limitations.length > 0 && (
                  <div className="space-y-1 mt-2">
                    <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Limitations / Context:</div>
                    <ul className="text-xs text-slate-500 space-y-1 list-disc list-inside">
                      {exp.limitations.map((lim, i) => (
                        <li key={i}>{lim}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })()}



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
            Framework Mapping
          </button>
          <button
            onClick={() => setActiveView('technologies')}
            className={`flex-1 py-2 text-sm font-bold rounded-lg transition-all ${activeView === 'technologies' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Technologies
          </button>
      </div>

      {/* 4. Main Content Area */}
      <div>
        
          {activeView === 'technologies' && (
            <div className="w-full max-w-full overflow-hidden space-y-6">
              <div className="technical-section report-section bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
                <div className="bg-slate-900 px-6 py-4 border-b border-slate-800 flex items-center gap-3">
                  <Server className="w-4 h-4 text-sky-400" />
                  <h2 className="font-bold text-slate-50 text-lg">Detected Technologies</h2>
                </div>
                
                <div className="p-6 text-slate-300">
                  {(!reportData?.technology_identities || reportData.technology_identities.length === 0) ? (
                    <div className="text-center py-8 text-slate-500">
                      <Terminal className="w-12 h-12 mx-auto mb-3 opacity-20" />
                      <p>No deterministic technology identities were observed in this scan.</p>
                    </div>
                  ) : (
                    <div className="w-full overflow-x-auto">
                      <table className="technical-findings-table w-full text-left border-collapse">
                        <thead>
                          <tr className="bg-slate-900/50 border-b border-slate-800 text-xs font-bold text-slate-500 uppercase tracking-widest">
                            <th className="px-6 py-4">Component</th>
                            <th className="px-6 py-4">Version</th>
                            <th className="px-6 py-4">Layer</th>
                            <th className="px-6 py-4">Confidence</th>
                            <th className="px-6 py-4">Identity (CPE)</th>
                            <th className="px-6 py-4 text-right">Details</th>
                          </tr>
                        </thead>
                        <tbody>
                          {reportData.technology_identities.map((tech, idx) => {
                            const getLayerDetails = (layer) => {
                              switch(layer) {
                                case 'web_server_proxy': return { label: 'Web Server / Proxy', icon: <Globe className="w-4 h-4 text-blue-400 mr-2 inline" /> };
                                case 'application_framework': return { label: 'Application Framework', icon: <Layers className="w-4 h-4 text-purple-400 mr-2 inline" /> };
                                case 'cms': return { label: 'Content Management System', icon: <Box className="w-4 h-4 text-orange-400 mr-2 inline" /> };
                                case 'language_runtime': return { label: 'Language / Runtime', icon: <Cpu className="w-4 h-4 text-green-400 mr-2 inline" /> };
                                case 'javascript_framework': return { label: 'JavaScript Framework', icon: <Terminal className="w-4 h-4 text-yellow-400 mr-2 inline" /> };
                                default: return { label: layer ? layer.replace(/_/g, ' ') : 'Unknown Layer', icon: <Box className="w-4 h-4 text-slate-400 mr-2 inline" /> };
                              }
                            };
                            
                            const getConfBadge = (conf) => {
                              const confStr = (conf || '').toUpperCase();
                              if (confStr === 'HIGH' || confStr.includes('100%')) return <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded text-xs font-bold uppercase">High</span>;
                              if (confStr === 'MEDIUM') return <span className="bg-amber-500/10 text-amber-400 border border-amber-500/30 px-2 py-0.5 rounded text-xs font-bold uppercase">Medium</span>;
                              if (confStr === 'LOW') return <span className="bg-slate-500/10 text-slate-400 border border-slate-500/30 px-2 py-0.5 rounded text-xs font-bold uppercase">Low</span>;
                              return <span className="bg-slate-800 text-slate-400 px-2 py-0.5 rounded text-xs font-bold uppercase">{confStr || 'UNKNOWN'}</span>;
                            };
                            
                            const layerInfo = getLayerDetails(tech.layer);
                            
                            return (
                              <React.Fragment key={idx}>
                                <tr 
                                  onClick={() => setExpandedTechRow(expandedTechRow === idx ? null : idx)}
                                  className={`border-b border-slate-800/50 cursor-pointer hover:bg-slate-900/30 transition-colors ${expandedTechRow === idx ? 'bg-slate-800/30' : ''}`}
                                >
                                  <td className="px-6 py-4">
                                    <div className="font-bold text-slate-200">{tech.product}</div>
                                    {tech.vendor && <div className="text-xs text-slate-500">{tech.vendor}</div>}
                                  </td>
                                  <td className="px-6 py-4 font-mono text-sm">
                                    {tech.version && tech.version_precision !== 'UNKNOWN' ? <span className="text-sky-300">{tech.version}</span> : <span className="text-slate-600">-</span>}
                                  </td>
                                  <td className="px-6 py-4 text-sm whitespace-nowrap">
                                    {layerInfo.icon}
                                    <span className="capitalize">{layerInfo.label}</span>
                                  </td>
                                  <td className="px-6 py-4">
                                    {getConfBadge(tech.confidence)}
                                  </td>
                                  <td className="px-6 py-4 font-mono text-xs">
                                    {tech.cpe ? (
                                      <code className="bg-slate-900 border border-slate-700 text-pink-400 px-2 py-1 rounded select-all break-all">{tech.cpe}</code>
                                    ) : (
                                      <span className="text-slate-600">-</span>
                                    )}
                                  </td>
                                  <td className="px-6 py-4 text-right align-top">
                                    <div className="flex flex-col items-end gap-1">
                                      <button aria-label={expandedTechRow === idx ? "Collapse Details" : "Expand Details"} className="text-slate-500 hover:text-slate-50 transition-colors">
                                        {expandedTechRow === idx ? <ChevronUp className="w-5 h-5 inline" /> : <ChevronDown className="w-5 h-5 inline" />}
                                      </button>
                                      {tech.cves && tech.cves.length > 0 && (
                                        <span className="text-[10px] bg-rose-500/10 text-rose-400 border border-rose-500/20 px-1.5 py-0.5 rounded font-bold uppercase whitespace-nowrap">{tech.cves.length} CVEs</span>
                                      )}
                                    </div>
                                  </td>
                                </tr>
                                
                                {expandedTechRow === idx && (
                                  <tr className="technical-finding-expanded print:hidden">
                                    <td colSpan={6} className="p-0 border-b-2 border-slate-700/50">
                                      <div className="bg-slate-950 p-6 transition-all duration-300">
                                        <div className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-4">Known Vulnerabilities</div>
                                          {(() => {
                                            const status = reportData?.cve_enrichment_status;
                                            if (status === 'QUEUED' || status === 'RUNNING') {
                                              return <div className="text-amber-400 text-sm">Vulnerability intelligence is being evaluated in the background.</div>;
                                            }
                                            if (status === 'FAILED') {
                                              return <div className="text-rose-400 text-sm">Vulnerability intelligence evaluation failed. Status unavailable.</div>;
                                            }
                                            if (!tech.cves || tech.cves.length === 0) {
                                              return <div className="text-slate-500 text-sm">No associated CVEs observed.</div>;
                                            }
                                            return (
                                              <div className="space-y-3">
                                                {tech.cves.map((cve, cveIdx) => (
                                                  <div key={cveIdx} className="bg-slate-900 border border-slate-800 rounded-lg p-4">
                                                    <div className="flex items-center gap-3 mb-2">
                                                      <span className="font-mono font-bold text-rose-300 text-sm">{cve.id}</span>
                                                      {getSeverityBadge(cve.severity.charAt(0).toUpperCase() + cve.severity.slice(1).toLowerCase())}
                                                        <span className="text-[10px] uppercase font-bold text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded border border-slate-700 ml-2">
                                                          Priority: {calculateCvePriority(tech, cve)}
                                                        </span>
                                                    </div>

                                                    {(cve.kev || cve.ssvc) && (
                                                      <div className="flex flex-col gap-1.5 mb-3">
                                                        {cve.kev && (
                                                          <div className="flex items-center gap-2 text-xs bg-red-950/30 border border-red-900/30 text-red-300/80 p-2 rounded">
                                                            <ShieldAlert className="w-4 h-4 text-red-500" />
                                                            <span>
                                                              <strong className="text-red-400">CISA KEV</strong>
                                                              {cve.kev.name && ` - ${cve.kev.name}`}
                                                              {cve.kev.added && ` | Added: ${cve.kev.added}`}
                                                              {cve.kev.action && ` | Action: ${cve.kev.action}`}
                                                              {cve.kev.due && ` (Due: ${cve.kev.due})`}
                                                            </span>
                                                          </div>
                                                        )}
                                                        {cve.ssvc && (
                                                          <div className="flex items-center gap-2 text-xs bg-indigo-950/20 border border-indigo-900/20 text-indigo-300/70 p-2 rounded">
                                                            <Activity className="w-4 h-4 text-indigo-500/80" />
                                                            <span>
                                                              <strong className="text-indigo-400">{cve.ssvc.source || "CISA-ADP"} SSVC {cve.ssvc.version ? `v${cve.ssvc.version}` : ''}</strong>
                                                              {cve.ssvc.timestamp && ` (${cve.ssvc.timestamp})`}
                                                              {cve.ssvc.options && Object.entries(cve.ssvc.options).map(([k, v]) => (
                                                                <span key={k} className="ml-2 pl-2 border-l border-indigo-800/40">
                                                                  <span className="opacity-70">{k}:</span> <span className="font-mono text-[10px]">{v}</span>
                                                                </span>
                                                              ))}
                                                            </span>
                                                          </div>
                                                        )}
                                                      </div>
                                                    )}

                                                    <p className="text-slate-400 text-sm leading-relaxed">{cve.summary}</p>
                                                  </div>
                                                ))}
                                              </div>
                                            );
                                          })()}
                                      </div>
                                    </td>
                                  </tr>
                                )}
                              </React.Fragment>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeView === 'vulnerabilities' && (
          <div className="w-full max-w-full overflow-hidden space-y-6">
            {domainGroups.map((group) => {
              const knownDomainKeys = new Set(domainGroups.map(g => g.key));
              const groupFindings = sortedFindings.filter(f => {
                const effectiveDomain = (f.domain && knownDomainKeys.has(f.domain)) ? f.domain : 'browser_defense';
                return effectiveDomain === group.key;
              });
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
                          <th className="px-6 py-4" style={{ width: '10%' }}>Priority</th>
                          <th className="px-6 py-4" style={{ width: '15%' }}>Severity</th>
                          <th className="px-6 py-4" style={{ width: '35%' }}>Security Check / Finding</th>
                          <th className="px-6 py-4" style={{ width: '25%' }}>OWASP Map</th>
                          <th className="px-6 py-4 text-right print:hidden" style={{ width: '15%' }}>Action</th>
                        </tr>
                      </thead>
                      {(() => {
                        const weights = { Critical: 6, High: 5, Medium: 4, Low: 3, Informational: 2, Passed: 1 };
                        const insertIdx = groupFindings.findIndex(f => (weights[f.severity] || 0) <= 2);
                        const finalInsertIdx = insertIdx === -1 ? groupFindings.length : insertIdx;
                        const elements = [];

                        groupFindings.forEach((finding, i) => {
                          const idx = sortedFindings.indexOf(finding);
                          elements.push(
                            <tbody key={idx} className="finding-card divide-y divide-slate-800/50 border-b border-slate-700/40 last:border-b-0">
                              <tr
                                onClick={() => setExpandedRow(expandedRow === idx ? null : idx)}
                                className={`technical-finding-row ${finding.severity === 'Passed' ? 'technical-passed-row' : ''} cursor-pointer hover:bg-slate-800/20 transition-colors ${expandedRow === idx ? 'bg-slate-800/30' : ''}`}
                              >
                                <td className="px-6 py-4 whitespace-nowrap align-top">
                                  {getPriorityBadge(calculateFindingPriority(finding))}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap align-top">
                                  {getSeverityBadge(finding.severity)}
                                </td>
                                <td className="px-6 py-4 font-bold text-slate-200 align-top">
                                  <div>{finding.name}</div>
                                </td>
                                <td className="px-6 py-4 align-top">
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

                                        <div className="flex flex-wrap gap-8 mb-4">
                                          {finding.module && (
                                            <div>
                                              <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Capability</div>
                                              <div className="text-slate-300 font-mono text-sm">{getCapabilityLabel(finding.module)}</div>
                                            </div>
                                          )}
                                          {finding.rule_id && (
                                            <div>
                                              <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Rule ID</div>
                                              <div className="text-slate-400 font-mono text-xs mt-0.5">{finding.rule_id}</div>
                                            </div>
                                          )}
                                          {finding.confidence && finding.confidence !== "N/A" && (
                                            (() => {
                                              const lowerConf = finding.confidence.toString().toLowerCase();
                                              let level = 'medium';
                                              if (lowerConf.includes('high')) level = 'high';
                                              else if (lowerConf.includes('low')) level = 'low';

                                              let colorClass = 'text-amber-300';
                                              if (level === 'high') colorClass = 'text-emerald-400';
                                              else if (level === 'low') colorClass = 'text-slate-400';

                                              return (
                                                <div>
                                                  <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Confidence Score</div>
                                                  <div className={`technical-confidence ${colorClass} font-bold text-sm`}>{finding.confidence}</div>
                                                </div>
                                              );
                                            })()
                                          )}

                                          {finding.state && (
                                            <div>
                                              <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Verification State</div>
                                              <div className={`technical-state font-bold text-sm ${finding.state.toLowerCase() === 'observed' ? 'text-blue-400' : 'text-purple-400'}`}>
                                                {finding.state.toUpperCase()}
                                              </div>
                                            </div>
                                          )}
                                        </div>

                                        {finding.evidence && finding.evidence !== "N/A" && (
                                          <div>
                                            <div className="flex items-center justify-between mb-2">
                                              <div className="text-xs font-bold text-slate-500 uppercase tracking-widest">Evidence</div>
                                              <button onClick={() => navigator.clipboard.writeText(typeof finding.evidence === 'string' ? finding.evidence : JSON.stringify(finding.evidence, null, 2))} className="text-slate-500 hover:text-indigo-400 text-xs flex items-center gap-1 transition-colors">
                                                <Copy className="w-3 h-3" /> Copy
                                              </button>
                                            </div>
                                            {typeof finding.evidence === 'object' && Object.keys(finding.evidence).length > 0 && !finding.evidence.raw && !finding.evidence.request_path ? (
                                              <div className="technical-evidence bg-slate-950 border border-slate-700/50 rounded-lg p-4 font-mono text-sm space-y-2">
                                                {Object.entries(finding.evidence).map(([key, value]) => (
                                                  <div key={key} className="text-slate-300">
                                                    <span className="text-slate-500 mr-2">{key}:</span>
                                                    {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                                                  </div>
                                                ))}
                                              </div>
                                            ) : typeof finding.evidence === 'object' && finding.evidence.request_path ? (
                                              <div className="technical-evidence bg-slate-950 border border-slate-700/50 rounded-lg p-4 font-mono text-sm">
                                                <div className="text-cyan-400 mb-2">
                                                  GET {finding.evidence.request_path} &bull; Status: {finding.evidence.status_code}
                                                </div>
                                                {finding.evidence.proof_snippet && (
                                                  <div className="text-slate-300 border-t border-slate-700/50 pt-2 mt-2">
                                                    Proof: {finding.evidence.proof_snippet}
                                                  </div>
                                                )}
                                              </div>
                                            ) : (
                                              <pre className="technical-evidence bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed shadow-inner">
                                                {typeof finding.evidence === 'object' && finding.evidence.raw ? finding.evidence.raw : (typeof finding.evidence === 'string' ? finding.evidence : JSON.stringify(finding.evidence, null, 2))}
                                              </pre>
                                            )}
                                          </div>
                                        )}

                                        <RemediationSnippetBox findingName={finding.name} ruleId={finding.rule_id} />
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

                                            {/* CVSS Metadata Block */}
                                            {finding.severity !== 'Passed' && finding.severity !== 'Informational' && (
                                              <div className="pt-3 mt-3 border-t border-slate-700/30 flex flex-col space-y-2">
                                                {finding.cvss ? (
                                                  <>
                                                    <div className="flex flex-col">
                                                      <div className="flex justify-between items-center">
                                                        <span className="text-xs font-bold text-slate-400">
                                                          {finding.cvss.startsWith('CVSS:4.0') ? 'CVSS 4.0' : 'CVSS v3.1'}
                                                        </span>
                                                      </div>
                                                      {finding.cvss.startsWith('CVSS:4.0') && (
                                                        <span className="text-xs text-slate-500 font-medium">CVSS-B</span>
                                                      )}
                                                    </div>

                                                    {(finding.cvss_score !== undefined && finding.cvss_score !== null) && (
                                                      <div className="flex flex-col text-xs text-slate-300">
                                                        <span>{finding.cvss.startsWith('CVSS:4.0') ? 'Score' : 'Base Score'}: {finding.cvss_score}</span>
                                                        {finding.cvss_severity && (
                                                          <span>CVSS Severity: {finding.cvss_severity}</span>
                                                        )}
                                                      </div>
                                                    )}

                                                    <div className="flex flex-col mt-2">
                                                      <span className="text-xs text-slate-500 mb-1">Vector:</span>
                                                      <div className="bg-slate-950 p-2 rounded border border-slate-800 min-w-0">
                                                        <span className="text-xs font-mono text-slate-300 break-words whitespace-normal inline-block w-full text-left" style={{ overflowWrap: 'anywhere' }}>
                                                          {finding.cvss}
                                                        </span>
                                                      </div>
                                                    </div>
                                                  </>
                                                ) : (
                                                  <div className="flex flex-col">
                                                    <span className="text-xs font-bold text-slate-400">CVSS</span>
                                                    <span className="text-xs text-slate-500 mt-1">Not Applicable</span>
                                                  </div>
                                                )}
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
                    });

                    return elements;
                  })()}
                    </table>
                  </div>
                  {group.key === 'browser_defense' && <CSPAnalysisPanel findings={groupFindings} />}
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
                <h2 className="font-bold text-slate-50 text-lg">Security Framework Mapping</h2>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

                {/* PCI-DSS */}
                <div className="technical-compliance-card bg-slate-900/50 border border-slate-800 rounded-xl p-5">
                  <div className="flex justify-between items-center mb-4 border-b border-slate-800 pb-3">
                    <h3 className="font-bold text-slate-200 text-sm">PCI-DSS 4.0</h3>
                    <span className={`px-2 py-1 text-[10px] font-bold uppercase tracking-wider rounded-md border ${reportData?.technical_compliance?.pci_dss_4_0?.status === 'Compliant' ? 'technical-compliance-compliant bg-emerald-950/80 text-emerald-400 border-emerald-800' : 'technical-compliance-action bg-red-500/20 text-red-400 border-red-500/20'}`}>
                      {reportData?.technical_compliance?.pci_dss_4_0?.status === 'Compliant' ? 'NO MAPPED ISSUES' : 'REVIEW RECOMMENDED'}
                    </span>
                  </div>

                  <div className="space-y-4">
                    {reportData?.technical_compliance?.pci_dss_4_0?.failed_controls?.length > 0 && (
                      <div>
                        <div className="technical-compliance-failed-heading text-xs font-bold text-red-400 mb-2 flex items-center gap-1"><XCircle className="w-3 h-3" /> Relevant Findings</div>
                        <ul className="technical-compliance-list text-xs text-slate-300 space-y-1 ml-4 list-disc marker:text-slate-600">
                          {(reportData?.technical_compliance?.pci_dss_4_0?.failed_controls || []).map((c, i) => <li key={i}>{c}</li>)}
                        </ul>
                      </div>
                    )}
                    <div>
                      <div className="technical-compliance-passed-heading text-xs font-bold text-emerald-400 mb-2 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Observed Positive Signals</div>
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
                      {reportData?.technical_compliance?.nist_sp_800_53?.status === 'Compliant' ? 'NO MAPPED ISSUES' : 'REVIEW RECOMMENDED'}
                    </span>
                  </div>

                  <div className="space-y-4">
                    {reportData?.technical_compliance?.nist_sp_800_53?.failed_controls?.length > 0 && (
                      <div>
                        <div className="technical-compliance-failed-heading text-xs font-bold text-red-400 mb-2 flex items-center gap-1"><XCircle className="w-3 h-3" /> Relevant Findings</div>
                        <ul className="technical-compliance-list text-xs text-slate-300 space-y-1 ml-4 list-disc marker:text-slate-600">
                          {(reportData?.technical_compliance?.nist_sp_800_53?.failed_controls || []).map((c, i) => <li key={i}>{c}</li>)}
                        </ul>
                      </div>
                    )}
                    <div>
                      <div className="technical-compliance-passed-heading text-xs font-bold text-emerald-400 mb-2 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Observed Positive Signals</div>
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
                      {reportData?.technical_compliance?.iso_27001?.status === 'Compliant' ? 'NO MAPPED ISSUES' : 'REVIEW RECOMMENDED'}
                    </span>
                  </div>

                  <div className="space-y-4">
                    {reportData?.technical_compliance?.iso_27001?.failed_controls?.length > 0 && (
                      <div>
                        <div className="technical-compliance-failed-heading text-xs font-bold text-red-400 mb-2 flex items-center gap-1"><XCircle className="w-3 h-3" /> Relevant Findings</div>
                        <ul className="technical-compliance-list text-xs text-slate-300 space-y-1 ml-4 list-disc marker:text-slate-600">
                          {(reportData?.technical_compliance?.iso_27001?.failed_controls || []).map((c, i) => <li key={i}>{c}</li>)}
                        </ul>
                      </div>
                    )}
                    <div>
                      <div className="technical-compliance-passed-heading text-xs font-bold text-emerald-400 mb-2 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Observed Positive Signals</div>
                      <ul className="technical-compliance-list text-xs text-slate-300 space-y-1 ml-4 list-disc marker:text-slate-600">
                        {(reportData?.technical_compliance?.iso_27001?.passed_controls || []).map((c, i) => <li key={i}>{c}</li>)}
                        {reportData?.technical_compliance?.iso_27001?.passed_controls?.length === 0 && <li className="technical-compliance-list-item-none text-slate-500">None</li>}
                      </ul>
                    </div>
                  </div>
                </div>

                <div className="mt-6 text-xs text-slate-500 leading-relaxed">
                  Framework mappings show how externally observable findings may relate to selected security controls. They are not a formal compliance assessment, audit, or certification.
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
