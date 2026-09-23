import React, { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import { ShieldCheck, ShieldAlert, Target, CheckCircle2, AlertTriangle, Info, Activity, Lock, Globe, Layout, Key, Copy, Check, Shield, Layers, Code2, Box, Mail, ChevronDown } from 'lucide-react';
import FindingCard from './FindingCard';
import ScoreDisplay from './ScoreDisplay';
import { getSimpleSummary } from '../../lib/assessmentReporting';
import { getTranslation } from '../../lib/utils/translations';
import { calculateFindingPriority, getPriorityBadgeClasses } from '../../utils/priority';

const SimpleReport = ({ reportData }) => {
  const getCategoryIcon = (category) => {
    if (category === 'Encryption') return <Lock className="w-5 h-5 text-red-400" />;
    if (category === 'Browser Protection') return <ShieldAlert className="w-5 h-5 text-red-400" />;
    if (category === 'Privacy Protection') return <Layout className="w-5 h-5 text-amber-400" />;
    return <Key className="w-5 h-5 text-slate-400" />;
  };

  const findings = reportData?.findings || [];
  const passed = findings.filter(f => f.severity === 'Passed');
  const informational = findings.filter(f => f.severity === 'Informational');
  const inconclusive = findings.filter(f => f.severity === 'Inconclusive');
  const issues = findings.filter(f => f.severity !== 'Passed' && f.severity !== 'Informational' && f.severity !== 'Inconclusive').sort((a, b) => {
    const w = { Critical: 5, High: 4, Medium: 3, Low: 2 };
    return (w[b.severity] || 0) - (w[a.severity] || 0);
  });

  const topPriorities = issues.slice(0, 3); // Max 3 items
  const highRiskCount = issues.filter(i => i.severity === 'High' || i.severity === 'Critical').length;
  const mediumRiskCount = issues.filter(i => i.severity === 'Medium').length;
  const lowRiskCount = issues.filter(i => i.severity === 'Low').length;
  const score = reportData?.score;
  const isWafBlocked = findings.length === 1 && findings[0]?.name?.includes('WAF');

  // Finding distribution derived only from real report data (no fabricated values)
  const totalFindings = findings.length;
  const findingDistribution = [
    { label: 'High', count: highRiskCount, color: 'text-red-500', dot: 'bg-red-500' },
    { label: 'Medium', count: mediumRiskCount, color: 'text-amber-500', dot: 'bg-amber-500' },
    { label: 'Low', count: lowRiskCount, color: 'text-purple-500', dot: 'bg-purple-500' },
    { label: 'Passed', count: passed.length, color: 'text-emerald-500', dot: 'bg-emerald-500' },
    { label: 'Informational', count: informational.length, color: 'text-blue-500', dot: 'bg-blue-500' },
    { label: 'Inconclusive', count: inconclusive.length, color: 'text-slate-500', dot: 'bg-slate-500' },
  ];
  const activeDistribution = findingDistribution.filter(d => d.count > 0);
  const DONUT_CIRCUMFERENCE = 2 * Math.PI * 52;

  // Risk-level status badge derived only from the real overall score
  const getRiskBadge = () => {
    if (isWafBlocked || score == null) {
      return { label: 'Scan Incomplete', dot: 'bg-slate-400', color: 'bg-slate-500/10 text-slate-400 border-slate-500/30' };
    }
    if (score >= 90) return { label: 'Low Risk', dot: 'bg-emerald-400', color: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' };
    if (score >= 80) return { label: 'Moderate Risk', dot: 'bg-teal-400', color: 'bg-teal-500/10 text-teal-400 border-teal-500/30' };
    if (score >= 70) return { label: 'Elevated Risk', dot: 'bg-amber-400', color: 'bg-amber-500/10 text-amber-400 border-amber-500/30' };
    return { label: 'High Risk', dot: 'bg-rose-400', color: 'bg-rose-500/10 text-rose-400 border-rose-500/30' };
  };
  const riskBadge = getRiskBadge();

  let healthSummary = "";
  if (reportData?.executive_summary && isWafBlocked) {
    healthSummary = reportData.executive_summary;
  } else if (score === 100) {
    healthSummary = "No scored issues were detected in this passive assessment. The publicly observable controls checked here show a strong posture.";
  } else if (score >= 90) {
    healthSummary = "Your website demonstrates a strong security posture. Addressing the few remaining recommendations below will achieve a perfect score.";
  } else if (score >= 80) {
    healthSummary = "Your website is well-secured overall. Addressing the few minor recommendations below will further harden your posture.";
  } else if (score >= 70) {
    healthSummary = "Your website has some security risks that need improvement. Addressing the recommendations below is advised.";
  } else if (score >= 60) {
    healthSummary = "Your website has moderate security risks. Addressing the top priorities below is highly recommended.";
  } else {
    healthSummary = "Your website faces critical security risks. Resolving the top priorities below is strongly recommended to protect your users.";
  }

  // Calculate domain-based health from backend findings - memoized
  const calculateDomainHealth = useMemo(() => (domain) => {
    if (score === null) return -1;
    const domainFindings = findings.filter(f => f.domain === domain);
    const domainIssues = domainFindings.filter(f => f.severity !== 'Passed' && f.severity !== 'Informational');
    if (domainFindings.length === 0) return 100;
    if (domainIssues.length === 0) return 100;
    if (domainIssues.some(f => f.severity === 'Critical' || f.severity === 'High')) return 20;
    if (domainIssues.some(f => f.severity === 'Medium')) return 50;
    return 70;
  }, [findings, score]);

  const techIdentities = reportData?.technology_identities || [];
  const uniqueProducts = Array.from(new Set(techIdentities.map(t => t.product))).filter(Boolean);

  const healthMetrics = useMemo(() => [
    { name: 'Transport & TLS', val: calculateDomainHealth('transport_tls'), icon: Lock },
    { name: 'Browser Defense', val: calculateDomainHealth('browser_defense'), icon: ShieldAlert },
    { name: 'API Surface', val: calculateDomainHealth('api_surface'), icon: Code2 },
    { name: 'Email & Domain', val: calculateDomainHealth('email_domain'), icon: Mail },
    { name: 'Network & Service Exposure', val: calculateDomainHealth('network_services'), icon: Activity }
  ], [calculateDomainHealth]);

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="simple-report space-y-8" id="report-content">

      {/* 1. Executive Summary & Score */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">

        <div className="simple-executive-summary lg:col-span-2 bg-slate-900 border border-slate-800 text-slate-50 p-6 lg:p-8 rounded-3xl shadow-md flex flex-col h-fit">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="text-2xl font-black">Executive Summary</h2>
              <div className="flex items-center gap-2 mt-1.5">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
                </span>
                <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Passive External Assessment</span>
              </div>
            </div>
            <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider border ${riskBadge.color}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${riskBadge.dot}`}></span>
              {riskBadge.label}
            </span>
          </div>

          <p className="text-xl text-slate-300 leading-relaxed mt-4">
            {healthSummary}
          </p>
          <p className="text-sm text-slate-500 mt-4 leading-relaxed">
            This assessment is a passive, external scan of publicly observable behavior. It does not replace comprehensive penetration testing or guarantee that no other vulnerabilities exist.
          </p>


          {highRiskCount > 0 && (
            <div className="rounded-xl border border-rose-500/30 border-l-4 border-l-rose-500 bg-rose-500/10 p-3.5 flex items-center gap-3 mt-6" role="alert">
              <div className="w-2 h-2 rounded-full bg-rose-400 animate-pulse flex-shrink-0" aria-hidden="true" />
              <p className="text-xs text-rose-200">
                <strong>Priority Focus:</strong> Resolve {highRiskCount} High-risk finding(s) to optimize overall security posture.
              </p>
            </div>
          )}

          {/* Finding Distribution - real report data only */}
          {totalFindings > 0 && (
            <div className="mt-6 pt-6 border-t border-slate-800">
              <h3 className="text-sm font-bold text-slate-400 uppercase tracking-widest mb-4 flex items-center gap-2">
                <Activity className="w-4 h-4" aria-hidden="true" /> Finding Distribution
              </h3>
              <div className="flex flex-col md:flex-row items-center gap-6">
                <div className="relative w-28 h-28 sm:w-32 sm:h-32 flex-shrink-0" role="img" aria-label={`Finding distribution: ${findingDistribution.map(d => `${d.label}: ${d.count}`).join(', ')}`}>
                  <svg className="w-32 h-32 transform -rotate-90" viewBox="0 0 128 128">
                    <circle cx="64" cy="64" r="52" stroke="currentColor" strokeWidth="14" fill="transparent" className="text-slate-800" aria-hidden="true" />
                    {activeDistribution.map((seg, i) => {
                      // Calculate cumulative fraction once per segment (O(n) instead of O(n²))
                      const prevFraction = activeDistribution.slice(0, i).reduce((s, p) => s + p.count, 0) / totalFindings;
                      const dashLen = DONUT_CIRCUMFERENCE * (seg.count / totalFindings);
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
                    <span className="text-2xl font-black text-slate-50">{totalFindings}</span>
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider">Findings</span>
                  </div>
                </div>
                <div className="flex flex-col justify-center gap-2 w-max ml-0 sm:ml-8 mt-4 sm:mt-0">
                    {activeDistribution.map((seg, i) => (
                      <div key={i} className="inline-flex items-center gap-2 text-sm">
                        <span className={`w-3 h-3 rounded-full ${seg.dot} flex-shrink-0`}></span>
                        <span className="text-slate-300 font-medium">{seg.label}</span>
                        <span className={`font-mono text-xs font-bold ${seg.color}`}>{seg.count}</span>
                      </div>
                    ))}
                  </div>
              </div>
            </div>
          )}

          {uniqueProducts.length > 0 && (
            <div className="mt-6 pt-6 border-t border-slate-800">
              <h3 className="text-sm font-bold text-slate-400 uppercase tracking-widest mb-3 flex items-center gap-2">
                <Layers className="w-4 h-4" /> Detected Technology Profile
              </h3>
              <div className="flex flex-wrap gap-2">
                {uniqueProducts.map((prod, i) => (
                  <span key={i} className="px-3 py-1 bg-slate-800 border border-slate-700 text-slate-300 rounded-full text-xs font-medium">
                    {prod}
                  </span>
                ))}
              </div>
            </div>
          )}

        </div>

        <ScoreDisplay
          score={score}
          isWafBlocked={isWafBlocked}
          penalties={reportData?.penalties}
          severityCounts={reportData?.severity_counts}
        />

      </div>

      {/* 3. Important Findings — High-level summary of top actionable issues */}
      {issues.length > 0 && (
        <div className="simple-important-findings bg-slate-900 border border-slate-800 rounded-3xl shadow-md overflow-hidden">
          <div className="bg-slate-950/80 border-b border-slate-800 p-6 md:p-8">
            <div className="flex items-center gap-4">
              <div className="bg-rose-500/20 p-2.5 md:p-3 rounded-xl text-rose-400 shrink-0" aria-hidden="true">
                <AlertTriangle className="w-5 h-5 md:w-6 md:h-6" strokeWidth={3} />
              </div>
              <div className="flex-1">
                <h3 className="font-black text-lg md:text-xl text-slate-50 uppercase tracking-wider">
                  Important Findings
                </h3>
                <p className="text-slate-400 mt-1 text-sm md:text-base">
                  {issues.length === 1 ? '1 actionable issue requires attention.' : `${issues.length} actionable issues identified — top ${Math.min(3, issues.length)} shown below.`}
                </p>
              </div>
            </div>
          </div>

          <div className="p-6 md:p-8 space-y-4">
            {topPriorities.map((issue, idx) => {
              const trans = getTranslation(issue);
              const priority = calculateFindingPriority(issue);
              const severityColor = issue.severity === 'High' || issue.severity === 'Critical' ? 'text-rose-400 bg-rose-500/10 border-rose-500/30' :
                issue.severity === 'Medium' ? 'text-amber-400 bg-amber-500/10 border-amber-500/30' :
                  'text-purple-400 bg-purple-500/10 border-purple-500/30';
              const severityDot = issue.severity === 'High' || issue.severity === 'Critical' ? 'bg-rose-400' :
                issue.severity === 'Medium' ? 'bg-amber-400' :
                  'bg-purple-400';

              return (
                <div key={`important-${idx}`} className="simple-important-finding bg-slate-950/50 border border-slate-800/50 rounded-2xl p-5 hover:border-slate-700/50 transition-colors">
                  <div className="flex flex-col md:flex-row md:items-start gap-4">
                    <div className="flex items-center gap-3 flex-shrink-0">
                      <div className="w-10 h-10 rounded-full bg-slate-800/80 text-slate-50 font-bold text-xl flex items-center justify-center shrink-0">{idx + 1}</div>
                      <div className="flex flex-col items-center gap-1">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider border ${severityColor}`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${severityDot}`}></span>
                          {issue.severity}
                        </span>
                        <span className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded border shrink-0 ${getPriorityBadgeClasses(priority)}`}>
                          {priority}
                        </span>
                      </div>
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-lg md:text-xl font-bold text-slate-50 tracking-tight truncate">
                        {trans.name}
                      </h4>
                      <p className="text-slate-300 mt-2 text-sm md:text-base leading-relaxed line-clamp-2">
                        {trans.problem}
                      </p>
                      {trans.action && (
                        <p className="text-emerald-400 mt-2 text-sm font-medium">
                          → {trans.action}
                        </p>
                      )}
                      <div className="flex flex-wrap items-center gap-2 mt-3">
                        {issue.owasp && (
                          <span className="text-[10px] font-mono text-slate-500 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                            {issue.owasp}
                          </span>
                        )}
                        {issue.cvss_score && (
                          <span className="text-[10px] font-mono text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/30">
                            CVSS {issue.cvss_score}
                          </span>
                        )}
                        {issue.cve_ids && issue.cve_ids.length > 0 && (
                          <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/30">
                            {issue.cve_ids.slice(0, 2).join(', ')}{issue.cve_ids.length > 2 ? ` +${issue.cve_ids.length - 2}` : ''}
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center md:justify-end flex-shrink-0">
                      <span className="text-slate-500 text-sm font-medium hidden md:block pr-2">Details below</span>
                      <span aria-hidden="true" className="text-slate-500 md:hidden p-1">
                        <ChevronDown className="w-5 h-5" />
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="bg-slate-950/80 border-t border-slate-800 p-4 md:p-6">
            <p className="text-slate-400 text-sm text-center">
              Full details for all {issues.length} issue{issues.length !== 1 ? 's' : ''} are available in the <strong className="text-slate-300">Issues That Need Attention</strong> section below.
            </p>
          </div>
        </div>
      )}

      {/* Empty state: no actionable issues */}
      {issues.length === 0 && findings.length > 0 && (
        <div className="simple-no-issues bg-emerald-950/20 border border-emerald-900/50 rounded-3xl p-6 md:p-8 text-center">
          <div className="bg-emerald-500/20 p-3 rounded-xl text-emerald-400 shrink-0 w-fit mx-auto mb-4" aria-hidden="true">
            <Check className="w-6 h-6" strokeWidth={2.5} />
          </div>
          <h3 className="font-black text-lg md:text-xl text-slate-50 uppercase tracking-wider text-emerald-400">
            No Actionable Issues
          </h3>
          <p className="text-slate-400 mt-2 max-w-xl mx-auto">
            This passive assessment did not identify any scored security issues. All checks passed or returned informational observations only.
          </p>
        </div>
      )}

      {/* 3.5 Issues That Need Attention */}
      <div className="simple-findings-section space-y-6 mt-12">
        <div className="flex flex-col">
          <h3 className="font-black text-2xl text-slate-50 uppercase tracking-wider text-slate-200">Issues That Need Attention</h3>
          <p className="text-slate-400 mt-1">A complete list of all identified security issues.</p>
        </div>

        {issues.length > 0 ? (
          <div className="grid gap-6">
            {issues.map((issue, idx) => (
              <FindingCard key={`finding-${idx}`} issue={issue} idx={idx} />
            ))}
          </div>
        ) : (
          <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl text-slate-400 text-center">
            No scored issues were detected in this passive assessment.
          </div>
        )}
      </div>

      {/* --- Relocated Details --- */}

        {/* 2. Security Health Bars */}
      <div className="simple-health-section bg-slate-900 border border-slate-800 p-8 rounded-3xl">
        <h3 className="text-xl font-bold text-slate-50 mb-6">Website Health Summary</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-12 gap-y-6">
          {healthMetrics.map((metric, i) => {
            const MetricIcon = metric.icon;
            return (
              <div key={i} className="space-y-2">
                <div className="flex justify-between items-center text-sm font-bold mb-1">
                  <span className="text-slate-300 flex items-center gap-2">
                    <MetricIcon className="w-4 h-4 text-slate-500 shrink-0" aria-hidden="true" />
                    {metric.name}
                    {metric.val !== -1 && (
                      <span className="text-[11px] font-mono text-slate-500">{metric.val}%</span>
                    )}
                  </span>
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider ${metric.val === -1 ? 'bg-slate-500/10 text-slate-400 border border-slate-500/20' : metric.val >= 90 ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : metric.val >= 50 ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                    {metric.val === -1 ? '⚪ No Data' : metric.val >= 90 ? '🟢 Optimal' : metric.val >= 50 ? '🟡 Needs Attention' : '🔴 Vulnerable'}
                  </span>
                </div>
                <div className="h-3 w-full bg-slate-800 rounded-full overflow-hidden">
                  {metric.val === -1 ? (
                    <div className="h-full rounded-full bg-slate-600/40" style={{ width: '100%', backgroundImage: 'repeating-linear-gradient(45deg, transparent, transparent 4px, rgba(148,163,184,0.1) 4px, rgba(148,163,184,0.1) 8px)' }}></div>
                  ) : (
                    <div
                      className={`h-full rounded-full ${metric.val >= 90 ? 'bg-emerald-500' : metric.val >= 50 ? 'bg-amber-500' : 'bg-red-500'}`}
                      style={{ width: `${metric.val}%` }}
                    ></div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 1.5. Target Surface Breakdown */}
      {reportData?.target_surface && (() => {
        const ts = reportData.target_surface;
        const findings = reportData?.findings || [];
        const perfRating = reportData?.metadata?.performance_rating || ts.performance || '';

        // â”€â”€ 1. WAF / SERVER â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        const serverVal = ts.waf_server || reportData?.server || 'Direct Origin';
        const serverSub = (() => {
          const status = ts.waf_status || '';
          const statusCode = status.match(/\d{3}/)?.[0] || '';
          if (reportData?.latency && statusCode === '200') return `200 OK • ${reportData.latency}`;
          if (statusCode === '200') return '200 OK • Healthy';
          if (statusCode === '403') return '403 • Access Restricted';
          if (statusCode === '503') return '503 • Service Issue';
          if (statusCode) return `${statusCode} • Detected`;
          return perfRating || 'Status Unknown';
        })();
        const wafPill = (() => {
          if (ts.waf_pill === 'REQUEST TIMEOUT' || ts.waf_pill === 'TIMEOUT') return { label: 'REQUEST TIMEOUT', color: 'bg-rose-500/10 text-rose-400 border-rose-500/30' };
          if (ts.waf_pill === 'WAF BLOCKED') return { label: 'WAF BLOCKED', color: 'bg-amber-500/10 text-amber-400 border-amber-500/30' };
          const status = ts.waf_status || '';
          const statusCode = status.match(/\d{3}/)?.[0] || '';
          const isTimeout = status.toLowerCase().includes('timeout') || perfRating?.toLowerCase() === 'request timeout';
          if (isTimeout) return { label: 'REQUEST TIMEOUT', color: 'bg-rose-500/10 text-rose-400 border-rose-500/30' };
          if (statusCode === '403' || status.toLowerCase().includes('aborted') || perfRating?.toLowerCase() === 'timeout') return { label: 'WAF BLOCKED', color: 'bg-amber-500/10 text-amber-400 border-amber-500/30' };
          const latencyMatch = status.match(/\((\d+)ms\)/);
          if (latencyMatch) {
            const ms = parseInt(latencyMatch[1], 10);
            return ms < 800
              ? { label: 'OPTIMAL LATENCY', color: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' }
              : { label: 'HIGH LATENCY', color: 'bg-amber-500/10 text-amber-400 border-amber-500/30' };
          }
          if (perfRating?.toLowerCase().includes('high')) return { label: 'HIGH LATENCY', color: 'bg-amber-500/10 text-amber-400 border-amber-500/30' };
          if (perfRating?.toLowerCase().includes('optimal') || statusCode === '200') return { label: 'OPTIMAL LATENCY', color: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' };
          return { label: 'LATENCY CHECKED', color: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30' };
        })();

        // â”€â”€ 2. FRONTEND STACK â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        const detectedTech = reportData?.technologies?.join(' • ') || reportData?.detected_framework;
        const stackVal = detectedTech || ts.frontend_stack || 'Standard Web Stack';
        const stackSub = ts.frontend_subtext || 'HTML5 / JavaScript Application';
        const stackPill = detectedTech ? 'DETECTED STACK' : (ts.frontend_pill || 'VERIFIED STACK');

        // â”€â”€ 3. API SURFACE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        const exposedApiFinding = findings.find(f => {
          const id = (f.id || '').toLowerCase();
          const name = (f.name || '').toLowerCase();
          const match = id.includes('api') || id.includes('swagger') || id.includes('graphql') || id.includes('openapi')
            || name.includes('api') || name.includes('swagger') || name.includes('graphql') || name.includes('admin portal');
          return match && f.severity !== 'Passed';
        });
        const hasExposedApi = !!exposedApiFinding;
        const getApiSurfaceData = () => {
          if (!hasExposedApi) {
            return {
              val: ts.api_surface || 'No Public Spec Exposed',
              sub: ts.api_subtext || 'GraphQL / OpenAPI Clean',
              pill: ts.api_pill || 'CLEAN SURFACE'
            };
          }
          const rawSubtext = (ts.api_subtext || '').toLowerCase();

          if (rawSubtext.includes('wp-json')) {
            return { val: 'Public API Exposed', sub: 'WordPress REST API (/wp-json/)', pill: 'EXPOSED API' };
          }
          if (rawSubtext.includes('admin') || rawSubtext.includes('wp-admin')) {
            return { val: 'Admin Surface Exposed', sub: 'Management Portal Disclosed (/wp-admin)', pill: 'ADMIN EXPOSED' };
          }
          if (rawSubtext.includes('swagger') || rawSubtext.includes('openapi')) {
            return { val: 'Public API Spec Exposed', sub: 'OpenAPI Schema Disclosed', pill: 'EXPOSED API' };
          }
          return {
            val: ts.api_surface || 'API Surface Detected',
            sub: exposedApiFinding?.name || ts.api_subtext || 'API Surface Detected',
            pill: ts.api_pill || 'API DETECTED'
          };
        };
        const { val: apiVal, sub: apiSub, pill: apiPill } = getApiSurfaceData();
        const apiColor = (apiPill === 'EXPOSED API' || apiPill === 'ADMIN EXPOSED')
          ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
          : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';

        // â”€â”€ 4. JS HEALTH â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        const mapLeaks = findings.filter(f =>
          (f.id?.includes('map_leak') || f.id?.includes('source_map') || (f.name || '').includes('Source Map'))
          && f.severity !== 'Passed'
        ).length;
        const jsVal = mapLeaks > 0 ? `${mapLeaks} .map Leak(s) Detected` : (ts.js_health || 'Clean Build');
        const jsSub = mapLeaks > 0 ? 'Source Code Exposure Risk' : (ts.js_subtext || '0 .map Leaks Detected');
        const jsPill = mapLeaks > 0 ? 'LEAKS DETECTED' : (ts.js_pill || '0 LEAKS DETECTED');
        const jsColor = mapLeaks > 0
          ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
          : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';

        // â”€â”€ Build Cards Array â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        const surfaceCards = [
          {
            title: 'WAF / SERVER',
            value: serverVal,
            subtext: serverSub,
            icon: Shield,
            iconColor: 'text-sky-400',
            pill: wafPill.label,
            pillColor: wafPill.color,
          },
          {
            title: 'FRONTEND STACK',
            value: stackVal,
            subtext: stackSub,
            icon: Layers,
            iconColor: 'text-indigo-400',
            pill: stackPill,
            pillColor: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30',
          },
          {
            title: 'API SURFACE',
            value: apiVal,
            subtext: apiSub,
            icon: Code2,
            iconColor: hasExposedApi ? 'text-amber-400' : 'text-emerald-400',
            pill: apiPill,
            pillColor: apiColor,
          },
          {
            title: 'JS HEALTH',
            value: jsVal,
            subtext: jsSub,
            icon: Box,
            iconColor: mapLeaks > 0 ? 'text-rose-400' : 'text-emerald-400',
            pill: jsPill,
            pillColor: jsColor,
          },
        ];
        return (
          <div className="simple-surface-section rounded-2xl border border-slate-800 bg-slate-950/80 p-6 backdrop-blur-md shadow-md">
            <div className="flex items-center gap-2.5 mb-6">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20" aria-hidden="true">
                <span className="relative flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
                </span>
              </div>
              <h2 className="text-lg font-semibold tracking-tight text-slate-50">Target Surface Breakdown</h2>
            </div>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {surfaceCards.map((card, idx) => {
                const Icon = card.icon;
                return (
                  <div key={idx} className="simple-surface-card w-full min-w-0 min-h-[150px] p-4 bg-slate-900/60 border border-slate-800 hover:border-slate-700/80 rounded-xl flex flex-col justify-between transition-all duration-300 hover:shadow-lg hover:">
                    <div>
                      <div className="flex items-center gap-2 text-[11px] font-bold font-mono tracking-wider text-slate-400 uppercase h-5">
                        <Icon className={`w-3.5 h-3.5 shrink-0 ${card.iconColor}`} aria-hidden="true" />
                        {card.title}
                      </div>
                      <div className="text-base sm:text-lg font-bold text-slate-50 mt-2">
                        {card.value}
                      </div>
                      <div className="text-xs text-slate-400 mt-1">
                        {card.subtext}
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5 mt-auto pt-3">
                      <span className={`inline-flex items-center px-2.5 py-1 rounded-md text-[10px] font-bold font-mono tracking-wider uppercase border ${card.pillColor}`}>
                        {card.pill}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })()}

      

        {/* 3.75 Additional Observations */}
      {informational.length > 0 && (
        <div className="simple-informational-section bg-slate-800/30 border border-slate-700/50 p-6 rounded-2xl mt-12">
          <div className="flex flex-col">
            <h3 className="font-black text-lg text-slate-200 uppercase tracking-wider">Additional Technical Observations</h3>
            <p className="text-slate-400 mt-2">
              {informational.length} additional technical {informational.length === 1 ? 'observation was' : 'observations were'} collected. These do not affect your score. View the Technical report for detailed diagnostic information.
            </p>
          </div>
        </div>
      )}

      {/* 4. Security Strengths (Passed Checks) */}
      {passed.length > 0 && (
        <div className="simple-passed-section bg-emerald-950/20 border border-emerald-900/50 p-6 md:p-8 rounded-3xl mt-12">
          <details className="group">
            <summary className="flex items-center gap-4 cursor-pointer list-none [&::-webkit-details-marker]:hidden focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:bg-slate-800/30">
              <div className="bg-emerald-500/20 p-2.5 md:p-3 rounded-xl text-emerald-400 shrink-0" aria-hidden="true">
                <Check className="w-5 h-5 md:w-6 md:h-6" strokeWidth={3} />
              </div>
              <div className="flex-1">
                <h3 className="font-black text-lg md:text-xl text-slate-50 flex items-center gap-2">
                  {passed.length} security checks passed
                </h3>
                <p className="text-emerald-400/80 text-xs md:text-sm mt-0.5 group-open:hidden">View passed checks</p>
                <p className="text-emerald-400/80 text-xs md:text-sm mt-0.5 hidden group-open:block">Hide passed checks</p>
              </div>
              <div className="text-emerald-500 bg-emerald-500/10 p-2 rounded-full group-open:rotate-180 transition-transform">
                <ChevronDown size={20} />
              </div>
            </summary>

            <div className="mt-6 pt-6 border-t border-emerald-900/30">
              <h4 className="text-emerald-400 font-bold mb-4 uppercase tracking-wider text-xs md:text-sm">Passed Security Checks</h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 md:gap-4">
                {passed.map((item, i) => (
                  <div key={i} className="simple-passed-item flex items-start gap-3 bg-slate-900/40 p-3 rounded-lg border border-emerald-900/20">
                    <Check className="w-4 h-4 md:w-5 md:h-5 text-emerald-500 shrink-0 mt-0.5" />
                    <span className="text-slate-300 text-sm font-medium leading-snug">{item.name}</span>
                  </div>
                ))}
              </div>
            </div>
          </details>
        </div>
      )}

      {/* 5. Final Recommendation */}
      <div className="text-center mt-12 py-12 border-t border-slate-800">
        <h3 className="text-2xl font-black text-slate-50 mb-4">Ready to improve your score?</h3>
        <p className="text-slate-400 text-lg max-w-2xl mx-auto">
          Interested in advanced testing? Let's chat on WhatsApp!
        </p>
      </div>

    </motion.div>
  );
};

export default SimpleReport;
