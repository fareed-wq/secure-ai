import { calculateFindingPriority, calculateCvePriority } from '../../utils/priority';
import React, { useState, useMemo } from 'react';
import { Terminal, Server, Cpu, Layers, Box, CheckCircle, Copy, Shield, ShieldAlert, ChevronDown, ChevronUp, XCircle, Globe, Activity, Lock, ShieldCheck, Search, Filter } from 'lucide-react';
import { RemediationSnippetBox } from './RemediationSnippetBox';
import { WhatWasTested } from './WhatWasTested';
import { getCapabilityLabel } from '../../lib/assessmentReporting';
import { CSPAnalysisPanel } from './CSPAnalysisPanel';


const TechnicalReport = ({ reportData }) => {
  const [expandedRow, setExpandedRow] = useState(null);
  const [expandedTechRow, setExpandedTechRow] = useState(null);
  const [activeView, setActiveView] = useState('vulnerabilities'); // 'vulnerabilities' | 'compliance'
  const [snippetTabs, setSnippetTabs] = useState({}); // { findingIndex: 'nginx' }
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [owaspFilter, setOwaspFilter] = useState('All');

  const findings = reportData?.findings || [];

  // Extract unique OWASP values from findings
  const owaspValues = useMemo(() => {
    const owaspSet = new Set();
    findings.forEach(f => {
      if (f.owasp && f.owasp !== 'N/A') {
        owaspSet.add(f.owasp);
      }
    });
    return Array.from(owaspSet).sort();
  }, [findings]);

  const sortedFindings = [...findings].sort((a, b) => {
    const weights = { Critical: 6, High: 5, Medium: 4, Low: 3, Informational: 2, Passed: 1 };
    const weightDiff = (weights[b.severity] || 0) - (weights[a.severity] || 0);
    if (weightDiff !== 0) return weightDiff;
    const nameA = a.name || '';
    const nameB = b.name || '';
    return nameA.localeCompare(nameB);
  });

  // Client-side filtering
  const filteredFindings = useMemo(() => {
    return sortedFindings.filter(finding => {
      // Severity filter
      if (severityFilter !== 'All' && finding.severity !== severityFilter) {
        return false;
      }

      // OWASP filter
      if (owaspFilter !== 'All' && finding.owasp !== owaspFilter) {
        return false;
      }

      // Search filter - search in name and description/impact/remediation
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const nameMatch = (finding.name || '').toLowerCase().includes(query);
        const descMatch = (finding.description || '').toLowerCase().includes(query);
        const impactMatch = (finding.impact || '').toLowerCase().includes(query);
        const remediationMatch = (finding.remediation || '').toLowerCase().includes(query);
        if (!nameMatch && !descMatch && !impactMatch && !remediationMatch) {
          return false;
        }
      }

      return true;
    });
  }, [sortedFindings, severityFilter, owaspFilter, searchQuery]);

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
          .text-slate-400, .text-slate-400 { color: #475569 !important; }
          .shadow-lg, .shadow-md, .shadow-inner { box-shadow: none !important; }
          .text-indigo-400 { color: #4338ca !important; }
          .text-emerald-400 { color: #059669 !important; }
          .text-red-500, .text-red-400 { color: #dc2626 !important; }
          .text-orange-500, .text-orange-400 { color: #ea580c !important; }
          .text-amber-500, .text-amber-400 { color: #d97706 !important; }
        }
      `}</style>

      {/* 1. Technical Metadata Table HUD */}
      <div className="technical-section report-section bg-slate-950/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-xl shadow-lg relative overflow-hidden">

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
          <div className="technical-metadata w-full min-w-0 h-full min-h-[150px] p-4 bg-slate-900/60 border border-slate-800 hover:border-slate-700/80 rounded-xl flex flex-col justify-between transition-all duration-300 hover:shadow-lg hover:">
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
          <div className="technical-metadata w-full min-w-0 h-full min-h-[150px] p-4 bg-slate-900/60 border border-slate-800 hover:border-slate-700/80 rounded-xl flex flex-col justify-between transition-all duration-300 hover:shadow-lg hover:">
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
              <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-mono font-semibold tracking-wider whitespace-nowrap shrink-0 max-w-full overflow-hidden text-ellipsis uppercase border ${reportData?.metadata?.performance_rating === 'NO HTTP RESPONSE' ? 'bg-slate-500/10 text-slate-400 border-slate-500/30' :
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
          <div className="technical-metadata w-full min-w-0 h-full min-h-[150px] p-4 bg-slate-900/60 border border-slate-800 hover:border-slate-700/80 rounded-xl flex flex-col justify-between transition-all duration-300 hover:shadow-lg hover:">
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
                {reportData?.metadata?.tls_version || 'TLS'} · <span className={`ml-1 ${reportData?.metadata?.ssl_days_left_int < 14 ? "text-rose-400 font-semibold" :
                  reportData?.metadata?.ssl_days_left_int <= 30 ? "text-amber-400 font-semibold" :
                    "text-emerald-400 font-semibold"
                  }`}>{reportData?.metadata?.ssl_days_left || 'Unknown Status'}</span>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-1.5 mt-auto pt-2 w-full">
              <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-mono font-semibold tracking-wider whitespace-nowrap shrink-0 max-w-full overflow-hidden text-ellipsis uppercase border ${reportData?.metadata?.ssl_badge === 'EXPIRED' ? 'bg-red-500/10 text-red-400 border-red-500/30' :
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
          <div className="technical-metadata w-full min-w-0 h-full min-h-[150px] p-4 bg-slate-900/60 border border-slate-800 hover:border-slate-700/80 rounded-xl flex flex-col justify-between transition-all duration-300 hover:shadow-lg hover:">
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
          <div className="report-section bg-slate-950/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-xl shadow-lg">
            <div className="flex items-center gap-3 mb-4">
              <span className="font-mono text-xs font-bold text-cyan-400 tracking-wider">&gt;_ ASSESSMENT_COVERAGE</span>
            </div>
            {cov.available ? (() => {
              const covData = [
                { label: 'Completed', count: cov.completed_modules || 0, color: 'text-emerald-500', dot: 'bg-emerald-500' },
                { label: 'Partial', count: cov.partial_modules || 0, color: 'text-amber-500', dot: 'bg-amber-500' },
                { label: 'Failed', count: cov.failed_modules || 0, color: 'text-red-500', dot: 'bg-red-500' },
                { label: 'Blocked', count: cov.blocked_modules || 0, color: 'text-slate-500', dot: 'bg-slate-500' },
                { label: 'Incomplete', count: cov.execution_incomplete_modules || 0, color: 'text-slate-400', dot: 'bg-slate-400' },
                { label: 'N/A', count: cov.not_applicable_modules || 0, color: 'text-slate-600', dot: 'bg-slate-600' }
              ];
              const activeCovData = covData.filter(d => d.count > 0);
              const totalModules = activeCovData.reduce((acc, curr) => acc + curr.count, 0) || 1;
              const DONUT_CIRCUMFERENCE = 2 * Math.PI * 52;

              return (
                <div className="flex flex-col md:flex-row items-center gap-6">
                  <div className="relative w-28 h-28 sm:w-32 sm:h-32 flex-shrink-0" role="img" aria-label={`Assessment Coverage: ${covData.map(d => `${d.label}: ${d.count}`).join(', ')}`}>
                    <svg className="w-full h-full transform -rotate-90" viewBox="0 0 128 128">
                      <circle cx="64" cy="64" r="52" stroke="currentColor" strokeWidth="14" fill="transparent" className="text-slate-800" aria-hidden="true" />
                      {activeCovData.map((seg, i) => {
                        const prevFraction = activeCovData.slice(0, i).reduce((s, p) => s + p.count, 0) / totalModules;
                        const dashLen = DONUT_CIRCUMFERENCE * (seg.count / totalModules);
                        return (
                          <circle
                            key={i}
                            cx="64"
                            cy="64"
                            r="52"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="14"
                            strokeDasharray={`${dashLen} ${DONUT_CIRCUMFERENCE - dashLen}`}
                            strokeDashoffset={DONUT_CIRCUMFERENCE * (1 - prevFraction)}
                            strokeLinecap="butt"
                            className={seg.color}
                          />
                        );
                      })}
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                      <span className="text-2xl font-black text-slate-50 font-mono">{Math.round(cov.percentage)}%</span>
                      <span className="text-[10px] text-slate-500 uppercase tracking-wider">Complete</span>
                    </div>
                  </div>

                  <div className="flex flex-col justify-center gap-2 flex-1 w-full sm:w-48 ml-0 sm:ml-8 mt-4 sm:mt-0">
                    {covData.map((seg, i) => (
                      <div key={i} className="flex items-center text-sm">
                        <span className={`w-3 h-3 rounded-full ${seg.dot} mr-3 flex-shrink-0`}></span>
                        <span className="text-slate-300 font-medium flex-1">{seg.label}</span>
                        <span className="text-slate-500 font-mono text-xs pl-4">{seg.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })() : (
              <div className="text-sm text-slate-400">Assessment Coverage: Not available</div>
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
        let bgColor = "bg-slate-900 border-slate-800";
        if (exp.level === "HIGH") { levelColor = "text-red-400"; bgColor = "bg-red-500/10 border-red-500/30"; }
        else if (exp.level === "MODERATE") { levelColor = "text-amber-400"; bgColor = "bg-amber-500/10 border-amber-500/30"; }
        else if (exp.level === "LOW") { levelColor = "text-emerald-400"; bgColor = "bg-emerald-500/10 border-emerald-500/30"; }

        return (
          <details className="group report-section bg-slate-950/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-xl shadow-lg mt-6">
            <summary className="flex items-center justify-between cursor-pointer list-none [&::-webkit-details-marker]:hidden mb-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:bg-slate-800/30">
              <span className="font-mono text-xs font-bold text-cyan-400 tracking-wider">&gt;_ EXPOSURE</span>
              <span className="group-open:rotate-180 transition-transform"><ChevronDown size={16} className="text-slate-400" /></span>
            </summary>
            <div className="mt-4">

              <div className="flex items-center gap-4 mb-6 pb-5 border-b border-slate-800/50">
                <div className={`px-5 py-2.5 rounded-xl border ${bgColor} flex flex-col items-center justify-center shadow-inner`}>
                  <span className={`text-2xl font-black font-mono ${levelColor}`}>{exp.level}</span>
                </div>
                <div>
                  <div className="text-sm font-bold text-slate-50 uppercase tracking-wide">Exposure Level</div>
                  <div className="text-[11px] text-slate-400 font-mono uppercase tracking-wider mt-0.5">Based on observed reachability</div>
                </div>
              </div>

              <div className="space-y-6">
                {exp.signals && exp.signals.length > 0 && (
                  <div>
                    <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                      <Activity className="w-4 h-4 text-slate-400" />
                      Observed Signals
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {exp.signals.map((sig, i) => (
                        <span key={i} className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm bg-slate-900 border border-slate-700/50 text-slate-200 shadow-sm hover:bg-slate-800 transition-colors">
                          <span className="w-1.5 h-1.5 rounded-full bg-indigo-500"></span>
                          {sig}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {exp.limitations && exp.limitations.length > 0 && (
                  <div className={`pt-1 ${exp.signals && exp.signals.length > 0 ? 'border-t border-slate-800/50 mt-5 pt-5' : ''}`}>
                    <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-slate-400" />
                      Limitations / Context
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {exp.limitations.map((lim, i) => (
                        <span key={i} className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs bg-slate-950 border border-slate-800 text-slate-400 shadow-sm hover:bg-slate-900 transition-colors">
                          <span className="w-1.5 h-1.5 rounded-full bg-slate-600"></span>
                          {lim}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

            </div>
          </details>
        );
      })()}



      {/* 2.6. Priority Guide */}
      <details className="group report-section bg-slate-950/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-xl shadow-lg mt-6 print:hidden">
        <summary className="flex items-center justify-between cursor-pointer list-none [&::-webkit-details-marker]:hidden mb-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:bg-slate-800/30">
          <span className="font-mono text-xs font-bold text-cyan-400 tracking-wider">&gt;_ UNDERSTANDING_PRIORITY (P1–P5)</span>
          <span className="group-open:rotate-180 transition-transform"><ChevronDown size={16} className="text-slate-400" /></span>
        </summary>
        <div className="mt-4">
          <p className="text-slate-400 text-sm mb-6">
            Priority indicates <strong className="text-slate-200">remediation urgency</strong> and is distinct from technical severity.
          </p>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Standard Findings */}
            <div className="bg-slate-900/50 border border-slate-800/50 rounded-xl p-5">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-400 uppercase tracking-wider mb-4 border-b border-slate-800/50 pb-3">
                <Shield className="w-4 h-4 text-indigo-400" />
                Standard Findings
              </div>
              <p className="text-slate-400 text-xs mb-4">Priority directly follows the finding's technical severity:</p>

              <div className="space-y-2">
                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-xs font-bold text-slate-300">High</span>
                  <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded border text-amber-400 bg-amber-950/30 border-amber-800">P2</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-xs font-bold text-slate-300">Medium</span>
                  <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded border text-yellow-400 bg-yellow-950/30 border-yellow-800">P3</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-xs font-bold text-slate-300">Low</span>
                  <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded border text-cyan-400 bg-cyan-950/30 border-cyan-800">P4</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-xs font-bold text-slate-300">Informational / Passed</span>
                  <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded border text-violet-400 bg-violet-950/30 border-violet-800">P5</span>
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-800/50 text-xs text-slate-400 leading-tight italic">
                * The scanner does not currently emit Critical-severity standard findings. If introduced, they will map to P1.
              </div>
            </div>

            {/* Known Vulnerabilities (CVEs) */}
            <div className="bg-slate-900/50 border border-slate-800/50 rounded-xl p-5">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-400 uppercase tracking-wider mb-4 border-b border-slate-800/50 pb-3">
                <Activity className="w-4 h-4 text-rose-400" />
                Known Vulnerabilities (CVEs)
              </div>
              <p className="text-slate-400 text-xs mb-4">Priority is calculated from vulnerability-intelligence signals:</p>

              <div className="space-y-2">
                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-xs font-medium text-slate-400">CVSS &ge; 9.0 <strong className="text-slate-400 mx-1">OR</strong> EPSS &ge; 10%</span>
                  <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded border text-rose-400 bg-rose-950/30 border-rose-800">P1</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-xs font-medium text-slate-400">CVSS &ge; 7.0 <strong className="text-slate-400 mx-1">OR</strong> EPSS &ge; 1%</span>
                  <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded border text-amber-400 bg-amber-950/30 border-amber-800">P2</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-xs font-medium text-slate-400">CVSS &ge; 4.0</span>
                  <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded border text-yellow-400 bg-yellow-950/30 border-yellow-800">P3</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-xs font-medium text-slate-400">CVSS &gt; 0</span>
                  <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded border text-cyan-400 bg-cyan-950/30 border-cyan-800">P4</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-xs font-medium text-slate-400">CVSS = 0 <strong className="text-slate-400 mx-1">OR</strong> (No CVSS + EPSS &lt; 1%)</span>
                  <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded border text-violet-400 bg-violet-950/30 border-violet-800">P5</span>
                </div>
              </div>
            </div>
          </div>
          <div className="mt-6 pt-4 border-t border-slate-800 text-xs text-slate-400 space-y-2">
            <p><strong>Important:</strong> Higher-priority conditions take precedence. For example, a CVE meeting a P1 condition remains P1 even if it also meets a lower-tier condition.</p>
            <p className="italic">CVSS indicates vulnerability severity; EPSS indicates exploitation likelihood. Priority uses these signals for remediation prioritization.</p>
          </div>
        </div>
      </details>

      {/* 3. Tab Switcher: Vulnerabilities vs Compliance */}
      <div className="flex bg-slate-950 border border-slate-800 p-1 rounded-xl w-full max-w-md mx-auto shadow-md print:hidden" role="tablist">
        <button
          onClick={() => setActiveView('vulnerabilities')}
          role="tab"
          aria-selected={activeView === 'vulnerabilities'}
          aria-controls="vulnerabilities-panel"
          className={`flex-1 py-2 text-sm font-bold rounded-lg transition-all ${activeView === 'vulnerabilities' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'} focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950`}
        >
          Vulnerabilities
        </button>
        <button
          onClick={() => setActiveView('compliance')}
          role="tab"
          aria-selected={activeView === 'compliance'}
          aria-controls="compliance-panel"
          className={`flex-1 py-2 text-sm font-bold rounded-lg transition-all ${activeView === 'compliance' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'} focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950`}
        >
          Framework Mapping
        </button>
        <button
          onClick={() => setActiveView('technologies')}
          role="tab"
          aria-selected={activeView === 'technologies'}
          aria-controls="technologies-panel"
          className={`flex-1 py-2 text-sm font-bold rounded-lg transition-all ${activeView === 'technologies' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'} focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950`}
        >
          Technologies
        </button>
      </div>

      {/* 4. Main Content Area */}
      <div>

        {activeView === 'technologies' && (
          <div className="w-full max-w-full overflow-hidden space-y-6">
            <div className="technical-section report-section bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
              <div className="bg-slate-900 px-6 py-4 border-b border-slate-800 flex items-center gap-3">
                <Server className="w-4 h-4 text-sky-400" />
                <h2 className="font-bold text-slate-50 text-lg">Detected Technologies</h2>
              </div>

              <div className="p-6 text-slate-300">
                {(!reportData?.technology_identities || reportData.technology_identities.length === 0) ? (
                  <div className="text-center py-8 text-slate-400">
                    <Terminal className="w-12 h-12 mx-auto mb-3 opacity-20" />
                    <p>No deterministic technology identities were observed in this scan.</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {reportData.technology_identities.map((tech, idx) => {
                      const getLayerDetails = (layer) => {
                        switch (layer) {
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
                        <div
                          key={idx}
                          className={`bg-slate-900/50 border ${expandedTechRow === idx ? 'border-indigo-500/50' : 'border-slate-800'} rounded-xl overflow-hidden transition-all hover:border-slate-700`}
                        >
                          <div
                            onClick={() => setExpandedTechRow(expandedTechRow === idx ? null : idx)}
                            className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-4 sm:px-6 cursor-pointer gap-4"
                          >
                            {/* Left: Product, Vendor, Version, Layer */}
                            <div className="flex-1 flex flex-col sm:flex-row sm:items-center gap-4 sm:gap-8">
                              <div className="min-w-[160px]">
                                <div className="font-bold text-slate-200 text-[15px]">{tech.product}</div>
                                {tech.vendor && <div className="text-[11px] text-slate-400 font-bold tracking-wider uppercase mt-1">{tech.vendor}</div>}
                              </div>

                              <div className="flex items-center gap-8">
                                <div>
                                  <div className="text-[10px] text-slate-400 uppercase tracking-widest font-bold mb-1">Version</div>
                                  {tech.version && tech.version_precision !== 'UNKNOWN' ? <div className="font-mono text-sky-300 text-sm">{tech.version}</div> : <div className="text-slate-600 font-mono text-sm">-</div>}
                                </div>

                                <div>
                                  <div className="text-[10px] text-slate-400 uppercase tracking-widest font-bold mb-1">Layer</div>
                                  <div className="text-sm text-slate-300 flex items-center whitespace-nowrap">
                                    {layerInfo.icon}
                                    <span className="capitalize">{layerInfo.label}</span>
                                  </div>
                                </div>
                              </div>
                            </div>

                            {/* Right: Badges and Expander */}
                            <div className="flex items-center gap-4 mt-2 sm:mt-0">
                              {getConfBadge(tech.confidence)}

                              {tech.cves && tech.cves.length > 0 && (
                                <span className="text-[10px] bg-rose-500/10 text-rose-400 border border-rose-500/20 px-2 py-1 rounded font-bold uppercase whitespace-nowrap" aria-label={`${tech.cves.length} CVEs detected`}>
                                  {tech.cves.length} CVEs
                                </span>
                              )}
                              <button aria-label={expandedTechRow === idx ? "Collapse technology details" : "Expand technology details"} className="text-slate-400 hover:text-slate-50 transition-colors ml-1 p-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900">
                                {expandedTechRow === idx ? <ChevronUp className="w-5 h-5" aria-hidden="true" /> : <ChevronDown className="w-5 h-5" aria-hidden="true" />}
                              </button>
                            </div>
                          </div>

                          {expandedTechRow === idx && (
                            <div className="border-t border-slate-800/50 bg-slate-950 p-4 sm:p-6 transition-all duration-300 print:hidden">
                              {/* Identity (CPE) Card */}
                              <div className="mb-6 bg-slate-900 border border-slate-800 rounded-lg p-4">
                                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-2 flex items-center gap-2">
                                  <Box className="w-3.5 h-3.5 text-slate-400" />
                                  Component Identity (CPE)
                                </div>
                                {tech.cpe ? (
                                  <code className="block bg-slate-950 border border-slate-800 text-pink-400/90 px-3 py-2 rounded text-xs font-mono break-all select-all">
                                    {tech.cpe}
                                  </code>
                                ) : (
                                  <span className="text-slate-400 text-xs italic">No structured CPE identity established.</span>
                                )}
                              </div>

                              <div className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4 flex items-center gap-2">
                                <ShieldAlert className="w-4 h-4 text-slate-400" />
                                Known Vulnerabilities
                              </div>
                              {(() => {
                                const status = reportData?.cve_enrichment_status;
                                if (status === 'QUEUED' || status === 'RUNNING') {
                                  return <div className="text-amber-400 text-sm">Vulnerability intelligence is being evaluated in the background.</div>;
                                }
                                if (status === 'FAILED') {
                                  return <div className="text-rose-400 text-sm">Vulnerability intelligence evaluation failed. Status unavailable.</div>;
                                }
                                if (!tech.cves || tech.cves.length === 0) {
                                  return <div className="text-slate-400 text-sm">No associated CVEs observed.</div>;
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
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeView === 'vulnerabilities' && (
          <div className="w-full max-w-full overflow-hidden space-y-6">
            {/* Toolbar */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
              <div className="flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between">
                <div className="flex items-center gap-2 text-sm text-slate-400">
                  <Search className="w-4 h-4 shrink-0" />
                  <span className="font-medium text-slate-300">Filter Findings</span>
                </div>
                <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center">
                  {/* Search Input */}
                  <div className="relative flex-1 sm:flex-none sm:w-64">
                    <label htmlFor="finding-search" className="sr-only">Search findings</label>
                    <input
                      id="finding-search"
                      type="text"
                      placeholder="Search by name, description, impact..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-700 text-slate-300 text-sm rounded-lg px-3 py-2 pl-9 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/50 placeholder:text-slate-600"
                    />
                    <Search className="w-4 h-4 text-slate-400 absolute left-2.5 top-2.5" aria-hidden="true" />
                  </div>
                  {/* Severity Filter */}
                  <label htmlFor="severity-filter" className="sr-only">Filter by severity</label>
                  <select
                    id="severity-filter"
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    className="bg-slate-950 border border-slate-700 text-slate-300 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/50 cursor-pointer"
                  >
                    <option value="All">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                    <option value="Informational">Informational</option>
                    <option value="Passed">Passed</option>
                  </select>
                  {/* OWASP Filter */}
                  <label htmlFor="owasp-filter" className="sr-only">Filter by OWASP category</label>
                  <select
                    id="owasp-filter"
                    value={owaspFilter}
                    onChange={(e) => setOwaspFilter(e.target.value)}
                    className="bg-slate-950 border border-slate-700 text-slate-300 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/50 cursor-pointer"
                  >
                    <option value="All">All OWASP</option>
                    {owaspValues.map(owasp => (
                      <option key={owasp} value={owasp}>{owasp}</option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="text-xs text-slate-400 mt-2">
                Showing {filteredFindings.length} of {sortedFindings.length} findings
                {searchQuery && <span className="text-indigo-400 ml-1"> (search: "{searchQuery}")</span>}
              </div>
            </div>



            {domainGroups.map((group) => {
              const knownDomainKeys = new Set(domainGroups.map(g => g.key));
              const groupDomainKey = group.key;

              // Filter findings by domain group first, then apply toolbar filters
              const groupFindings = filteredFindings.filter(f => {
                const effectiveDomain = (f.domain && knownDomainKeys.has(f.domain)) ? f.domain : 'browser_defense';
                return effectiveDomain === groupDomainKey;
              });

              if (groupFindings.length === 0) return null;

              return (
                <div key={group.key} className="technical-section report-section bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
                  <div className="bg-slate-900 px-6 py-4 border-b border-slate-800 flex items-center gap-3">
                    {group.icon}
                    <h2 className="font-bold text-slate-50 text-lg">{group.label}</h2>
                  </div>

                  <div className="w-full overflow-x-auto">
                    <table className="technical-findings-table w-full text-left border-collapse">
                      <caption className="sr-only">Finding table with priority, severity, description, OWASP mapping, and action buttons</caption>
                      <colgroup>
                        <col style={{ width: '10%' }} />
                        <col style={{ width: '15%' }} />
                        <col style={{ width: '35%' }} />
                        <col style={{ width: '25%' }} />
                        <col style={{ width: '15%' }} />
                      </colgroup>
                      <thead>
                        <tr className="bg-slate-900/50 border-b border-slate-800 text-xs font-bold text-slate-400 uppercase tracking-widest">
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
                                  <button aria-label={expandedRow === idx ? "Collapse details" : "Expand details"} className="text-slate-400 hover:text-slate-50 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900">
                                    {expandedRow === idx ? <ChevronUp className="w-5 h-5 inline" aria-hidden="true" /> : <ChevronDown className="w-5 h-5 inline" aria-hidden="true" />}
                                  </button>
                                </td>
                              </tr>

                              {/* Print-only row for full-width code snippet */}
                              {finding.remediation_snippets?.nginx && (
                                <tr className="hidden print:table-row">
                                  <td colSpan={5} className="px-6 pb-6 pt-0 w-full block">
                                    <div className="bg-slate-50 p-4 rounded border border-slate-200 w-full block">
                                      <div className="text-[10px] font-bold text-slate-400 uppercase mb-1">Remediation Snippet (Nginx/Server)</div>
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
                                            <div className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Technical Description</div>
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

                                          <div className="bg-slate-900/40 rounded-xl p-5 flex flex-wrap gap-8 border border-slate-800/60">
                                            {finding.module && (
                                              <div>
                                                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Capability</div>
                                                <div className="text-slate-300 font-mono text-sm">{getCapabilityLabel(finding.module)}</div>
                                              </div>
                                            )}
                                            {finding.rule_id && (
                                              <div>
                                                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Rule ID</div>
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
                                                    <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Confidence Score</div>
                                                    <div className={`technical-confidence ${colorClass} font-bold text-sm`}>{finding.confidence}</div>
                                                  </div>
                                                );
                                              })()
                                            )}

                                            {finding.state && (
                                              <div>
                                                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Verification State</div>
                                                <div className={`technical-state font-bold text-sm ${finding.state.toLowerCase() === 'observed' ? 'text-blue-400' : 'text-purple-400'}`}>
                                                  {finding.state.toUpperCase()}
                                                </div>
                                              </div>
                                            )}
                                          </div>

                                          {finding.evidence && finding.evidence !== "N/A" && (
                                            <div>
                                              <div className="flex items-center justify-between mb-2">
                                                <div className="text-xs font-bold text-slate-400 uppercase tracking-widest">Evidence</div>
                                                <button onClick={() => navigator.clipboard.writeText(typeof finding.evidence === 'string' ? finding.evidence : JSON.stringify(finding.evidence, null, 2))} className="text-slate-400 hover:text-indigo-400 text-xs flex items-center gap-1 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-1 focus-visible:ring-offset-slate-950" aria-label="Copy evidence to clipboard">
                                                  <Copy className="w-3 h-3" aria-hidden="true" /> Copy
                                                </button>
                                              </div>
                                              {typeof finding.evidence === 'object' && Object.keys(finding.evidence).length > 0 && !finding.evidence.raw && !finding.evidence.request_path ? (
                                                <div className="technical-evidence bg-slate-950 border border-slate-700/50 rounded-lg p-4 font-mono text-sm space-y-2">
                                                  {Object.entries(finding.evidence).map(([key, value]) => (
                                                    <div key={key} className="text-slate-300">
                                                      <span className="text-slate-400 mr-2">{key}:</span>
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
                                                <pre className="technical-evidence bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-300 overflow-x-auto overflow-y-auto max-h-96 whitespace-pre-wrap leading-relaxed shadow-inner">
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
                                                <span className="text-slate-400">Category</span>
                                                <span className="font-mono text-slate-300 uppercase">{finding.category}</span>
                                              </div>
                                              <div className="flex justify-between items-center text-xs">
                                                <span className="text-slate-400">Scanner Module</span>
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
                                                          <span className="text-xs text-slate-400 font-medium">CVSS-B</span>
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
                                                        <span className="text-xs text-slate-400 mb-1">Vector:</span>
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
                                                      <span className="text-xs text-slate-400 mt-1">Not Applicable</span>
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

                      {/* Empty State */}
                      {groupFindings.length === 0 && (
                        <div className="text-center py-12">
                          <Search className="w-12 h-12 mx-auto mb-3 text-slate-600 opacity-50" aria-hidden="true" />
                          <p className="text-slate-400 text-sm">
                            No findings match your current filters.
                          </p>
                          {searchQuery && (
                            <button
                              onClick={() => setSearchQuery('')}
                              className="mt-2 text-xs text-indigo-400 hover:text-indigo-300 underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-1 focus-visible:ring-offset-slate-950 rounded"
                            >
                              Clear search
                            </button>
                          )}
                          {(severityFilter !== 'All' || owaspFilter !== 'All') && (
                            <button
                              onClick={() => {
                                setSeverityFilter('All');
                                setOwaspFilter('All');
                              }}
                              className="mt-2 text-xs text-indigo-400 hover:text-indigo-300 underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-1 focus-visible:ring-offset-slate-950 rounded"
                            >
                              Clear filters
                            </button>
                          )}
                        </div>
                      )}
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
              <div className="technical-compliance-section bg-slate-950 border border-slate-800 rounded-xl p-6 shadow-lg">
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
                          {reportData?.technical_compliance?.pci_dss_4_0?.passed_controls?.length === 0 && <li className="technical-compliance-list-item-none text-slate-400">None</li>}
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
                          {reportData?.technical_compliance?.nist_sp_800_53?.passed_controls?.length === 0 && <li className="technical-compliance-list-item-none text-slate-400">None</li>}
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
                          {reportData?.technical_compliance?.iso_27001?.passed_controls?.length === 0 && <li className="technical-compliance-list-item-none text-slate-400">None</li>}
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div className="mt-6 text-xs text-slate-400 leading-relaxed">
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
