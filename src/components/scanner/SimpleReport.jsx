import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldCheck, ShieldAlert, Target, CheckCircle2, AlertTriangle, Info, Activity, Lock, Globe, Layout, Key, Copy, Check, Shield, Layers, Code2, Box, Mail, ChevronDown } from 'lucide-react';
import FindingCard from './FindingCard';
import ScoreDisplay from './ScoreDisplay';

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

  let healthSummary = "";
  if (reportData?.executive_summary && isWafBlocked) {
    healthSummary = reportData.executive_summary;
  } else if (score === 100) {
    healthSummary = "Your website meets all baseline security best practices with zero open issues or vulnerabilities detected. Outstanding security posture!";
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

  // Calculate domain-based health from backend findings
  const calculateDomainHealth = (domain) => {
    if (score === null) return -1; // Zero meaningful checks completed overall
    const domainFindings = findings.filter(f => f.domain === domain);
    const domainIssues = domainFindings.filter(f => f.severity !== 'Passed' && f.severity !== 'Informational');
    if (domainFindings.length === 0) return 100; // Meaningful checks ran but found no issues
    if (domainIssues.length === 0) return 100;
    if (domainIssues.some(f => f.severity === 'Critical' || f.severity === 'High')) return 20;
    if (domainIssues.some(f => f.severity === 'Medium')) return 50;
    return 70;
  };

  const healthMetrics = [
    { name: 'Transport & TLS', val: calculateDomainHealth('transport_tls'), icon: Lock },
    { name: 'Browser Defense', val: calculateDomainHealth('browser_defense'), icon: ShieldAlert },
    { name: 'API Surface', val: calculateDomainHealth('api_surface'), icon: Code2 },
    { name: 'Email & Domain', val: calculateDomainHealth('email_domain'), icon: Mail }
  ];

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-8" id="report-content">

      {/* 1. Executive Summary & Score */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">

        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 text-slate-50 p-6 lg:p-8 rounded-3xl shadow-xl flex flex-col h-fit">
          <div>
            <h2 className="text-2xl font-black mb-4">Executive Summary</h2>
            <p className="text-xl text-slate-300 leading-relaxed">
              {healthSummary}
            </p>
            {highRiskCount > 0 && (
              <div className="rounded-xl border border-rose-500/30 border-l-4 border-l-rose-500 bg-rose-500/10 p-3.5 flex items-center gap-3 my-4">
                <div className="w-2 h-2 rounded-full bg-rose-400 animate-pulse flex-shrink-0" />
                <p className="text-xs text-rose-200">
                  <strong>Priority Focus:</strong> Resolve {highRiskCount} High-risk finding(s) to optimize overall security posture.
                </p>
              </div>
            )}
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-6 w-full">
            <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl min-h-[140px] p-4 flex flex-col justify-between h-full">
              <div>
                <div className="text-xs font-bold text-amber-400 uppercase tracking-wider">Issues Found</div>
                <div className="text-4xl font-extrabold tracking-tight mt-2 block text-slate-50">{issues.length}</div>
              </div>
              <div className="border-t border-slate-800/80 pt-2.5 mt-3 flex flex-wrap items-center gap-2">
                <span className={`inline-flex items-center justify-center gap-1.5 rounded-full border px-3 py-1 text-xs font-mono font-medium ${highRiskCount > 0 ? 'bg-rose-500/15 text-rose-300 border-rose-500/30' : 'bg-slate-800/40 text-slate-500 border-slate-800'}`}>
                  <span className={`w-3 h-3 rounded-full border border-slate-900 flex-shrink-0 ${highRiskCount > 0 ? 'bg-red-500' : 'bg-slate-600'}`}></span>
                  High {highRiskCount}
                </span>
                <span className={`inline-flex items-center justify-center gap-1.5 rounded-full border px-3 py-1 text-xs font-mono font-medium ${mediumRiskCount > 0 ? 'bg-amber-500/15 text-amber-300 border-amber-500/30' : 'bg-slate-800/40 text-slate-500 border-slate-800'}`}>
                  <span className={`w-3 h-3 rounded-full border border-slate-900 flex-shrink-0 ${mediumRiskCount > 0 ? 'bg-amber-500' : 'bg-slate-600'}`}></span>
                  Medium {mediumRiskCount}
                </span>
                <span className={`inline-flex items-center justify-center gap-1.5 rounded-full border px-3 py-1 text-xs font-mono font-medium ${lowRiskCount > 0 ? 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30' : 'bg-slate-800/40 text-slate-500 border-slate-800'}`}>
                  <span className={`w-3 h-3 rounded-full border border-slate-900 flex-shrink-0 ${lowRiskCount > 0 ? 'bg-purple-500' : 'bg-slate-600'}`}></span>
                  Low {lowRiskCount}
                </span>
              </div>
            </div>
            <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-xl min-h-[140px] p-4 flex flex-col justify-between h-full">
              <div>
                <div className="text-xs font-bold text-emerald-500 uppercase tracking-wider">Passed Checks</div>
                <div className="text-4xl font-extrabold tracking-tight mt-2 block text-emerald-400">{passed.length}</div>
              </div>
              <div className="pt-3 mt-3 border-t border-slate-800/80 flex items-center">
                <span className="inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-mono font-medium bg-emerald-500/15 text-emerald-300 border-emerald-500/30">
                  🟢 {passed.length} Audits Clean
                </span>
              </div>
            </div>
            <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl min-h-[140px] p-4 flex flex-col justify-between h-full">
              <div>
                <div className="text-xs font-bold text-blue-500 uppercase tracking-wider">Informational</div>
                <div className="text-4xl font-extrabold tracking-tight mt-2 block text-blue-400">{informational.length}</div>
              </div>
              <div className="pt-3 mt-3 border-t border-slate-800/80 flex items-center">
                <span className="inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-mono font-medium bg-blue-500/15 text-blue-300 border-blue-500/30">
                  ⚪ {informational.length} Observations
                </span>
              </div>
            </div>
            <div className="bg-slate-500/10 border border-slate-500/20 rounded-xl min-h-[140px] p-4 flex flex-col justify-between h-full">
              <div>
                <div className="text-xs font-bold text-slate-400 uppercase tracking-wider">Inconclusive</div>
                <div className="text-4xl font-extrabold tracking-tight mt-2 block text-slate-300">{inconclusive.length}</div>
              </div>
              <div className="pt-3 mt-3 border-t border-slate-800/80 flex items-center">
                <span className="inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-mono font-medium bg-slate-800/40 text-slate-400 border-slate-700">
                  ⚠️ {inconclusive.length} Skipped Checks
                </span>
              </div>
            </div>
          </div>
        </div>

        <ScoreDisplay
          score={score}
          isWafBlocked={isWafBlocked}
          penalties={reportData?.penalties}
          severityCounts={reportData?.severity_counts}
        />
      </div>

      {/* 1.5. Target Surface Breakdown */}
      {reportData?.target_surface && (() => {
        const ts = reportData.target_surface;
        const findings = reportData?.findings || [];
        const perfRating = reportData?.metadata?.performance_rating || ts.performance || '';

        // ── 1. WAF / SERVER ──────────────────────────────────────────────
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

        // ── 2. FRONTEND STACK ────────────────────────────────────────────
        const detectedTech = reportData?.technologies?.join(' • ') || reportData?.detected_framework;
        const stackVal = detectedTech || ts.frontend_stack || 'Standard Web Stack';
        const stackSub = ts.frontend_subtext || 'HTML5 / JavaScript Application';
        const stackPill = detectedTech ? 'DETECTED STACK' : (ts.frontend_pill || 'VERIFIED STACK');

        // ── 3. API SURFACE ───────────────────────────────────────────────
        const hasExposedApi = findings.some(f => {
          const id = (f.id || '').toLowerCase();
          const name = (f.name || '').toLowerCase();
          const match = id.includes('api') || id.includes('swagger') || id.includes('graphql') || id.includes('openapi')
            || name.includes('api') || name.includes('swagger') || name.includes('graphql') || name.includes('admin portal');
          return match && f.severity !== 'Passed';
        });
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
            val: 'Public API Spec Exposed',
            sub: ts.api_subtext || 'Exposed Specification Found',
            pill: 'EXPOSED API'
          };
        };
        const { val: apiVal, sub: apiSub, pill: apiPill } = getApiSurfaceData();
        const apiColor = (apiPill === 'EXPOSED API' || apiPill === 'ADMIN EXPOSED')
          ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
          : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';

        // ── 4. JS HEALTH ─────────────────────────────────────────────────
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

        // ── Build Cards Array ────────────────────────────────────────────
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
          <div className="rounded-2xl border border-slate-800 bg-slate-950/80 p-6 backdrop-blur-md shadow-xl">
            <div className="flex items-center gap-2.5 mb-6">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
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
                  <div key={idx} className="w-full min-w-0 min-h-[150px] p-4 bg-slate-900/60 border border-slate-800 hover:border-slate-700/80 rounded-xl flex flex-col justify-between transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/5">
                    <div>
                      <div className="flex items-center gap-2 text-[11px] font-bold font-mono tracking-wider text-slate-400 uppercase h-5">
                        <Icon className={`w-3.5 h-3.5 shrink-0 ${card.iconColor}`} />
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

      {/* 2. Security Health Bars */}
      <div className="bg-slate-900 border border-slate-800 p-8 rounded-3xl">
        <h3 className="text-xl font-bold text-slate-50 mb-6">Website Health Summary</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-12 gap-y-6">
          {healthMetrics.map((metric, i) => {
            const MetricIcon = metric.icon;
            return (
              <div key={i} className="space-y-2">
                <div className="flex justify-between items-center text-sm font-bold mb-1">
                  <span className="text-slate-300 flex items-center gap-2">
                    <MetricIcon className="w-4 h-4 text-slate-500 shrink-0" />
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

      {/* 3. Action Checklist (Top Priorities) */}
      {topPriorities.length > 0 && (
        <div className="bg-amber-950/20 border border-amber-900/50 p-6 md:p-8 rounded-3xl mt-12 mb-12">
          <details className="group">
            <summary className="flex items-center gap-4 cursor-pointer list-none [&::-webkit-details-marker]:hidden">
              <div className="bg-amber-500/20 p-2.5 md:p-3 rounded-xl text-amber-400 shrink-0">
                <AlertTriangle className="w-5 h-5 md:w-6 md:h-6" strokeWidth={3} />
              </div>
              <div className="flex-1">
                <h3 className="font-black text-lg md:text-xl text-slate-50 uppercase tracking-wider text-amber-400">
                  Your Top Priorities
                </h3>
                <p className="text-amber-400/80 text-xs md:text-sm mt-0.5 group-open:hidden">
                  🔴 {topPriorities.length} priority items identified. [ View Top Priorities ▾ ]
                </p>
                <p className="text-amber-400/80 text-xs md:text-sm mt-0.5 hidden group-open:block">
                  Hide Top Priorities
                </p>
              </div>
              <div className="text-amber-500 bg-amber-500/10 p-2 rounded-full group-open:rotate-180 transition-transform">
                <ChevronDown size={20} />
              </div>
            </summary>

            <div className="mt-6 pt-6 border-t border-amber-900/30">
              <p className="text-slate-400 mb-6">Review these business risks with your IT provider or web developer.</p>
              <div className="grid gap-6">
                {topPriorities.map((issue, idx) => (
                  <FindingCard key={`priority-${idx}`} issue={issue} idx={idx} />
                ))}
              </div>
            </div>
          </details>
        </div>
      )}

      {/* 3.5 All Detected Findings */}
      {issues.length > 0 && (
        <div className="space-y-6 mt-12">
          <div className="flex flex-col">
            <h3 className="font-black text-2xl text-slate-50 uppercase tracking-wider text-slate-200">All Detected Findings</h3>
            <p className="text-slate-400 mt-1">A complete list of all identified security issues.</p>
          </div>

          <div className="grid gap-6">
            {issues.map((issue, idx) => (
              <FindingCard key={`finding-${idx}`} issue={issue} idx={idx} />
            ))}
          </div>
        </div>
      )}

      {/* 4. Security Strengths (Passed Checks) */}
      {passed.length > 0 && (
        <div className="bg-emerald-950/20 border border-emerald-900/50 p-6 md:p-8 rounded-3xl mt-12">
          <details className="group">
            <summary className="flex items-center gap-4 cursor-pointer list-none [&::-webkit-details-marker]:hidden">
              <div className="bg-emerald-500/20 p-2.5 md:p-3 rounded-xl text-emerald-400 shrink-0">
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
                  <div key={i} className="flex items-start gap-3 bg-slate-900/40 p-3 rounded-lg border border-emerald-900/20">
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
