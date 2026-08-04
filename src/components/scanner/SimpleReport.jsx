import React from 'react';
import { motion } from 'framer-motion';
import { ShieldAlert, ShieldCheck, ArrowUpRight, CheckCircle, Target } from 'lucide-react';

const getBusinessRisk = (severity) => {
  const risks = {
    'Critical': 'Immediate Business Risk: High likelihood of data breach or severe disruption.',
    'High': 'Significant Risk: Could lead to unauthorized access or reputational damage.',
    'Medium': 'Operational Risk: Potential for minor disruptions or data exposure if chained.',
    'Low': 'Minor Risk: Best practices are missing, slightly increasing attack surface.',
    'Informational': 'Observation: Architectural details that attackers might use for reconnaissance.',
    'Passed': 'Secure: Standard security controls are active and verified.'
  };
  return risks[severity] || risks['Informational'];
};

const getEffort = (severity) => {
  const effort = {
    'Critical': 'Urgent Action Required (Typically hours)',
    'High': 'High Priority (Typically days)',
    'Medium': 'Scheduled Maintenance (Typically weeks)',
    'Low': 'Backlog / Routine Update',
  };
  return effort[severity] || 'Minimal';
};

const SimpleReport = ({ reportData }) => {
  const findings = reportData?.findings || [];
  const passed = findings.filter(f => f.severity === 'Passed');
  const issues = findings.filter(f => f.severity !== 'Passed').sort((a, b) => {
    const w = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };
    return (w[b.severity] || 0) - (w[a.severity] || 0);
  });

  const criticalAndHigh = issues.filter(f => f.severity === 'Critical' || f.severity === 'High');

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-8"
      id="report-content" // For PDF generation targeting
    >
      {/* Executive Summary */}
      <div className="bg-slate-900 border border-slate-800 p-8 rounded-3xl shadow-lg">
        <h3 className="text-xl font-bold text-white mb-4">Executive Summary</h3>
        <p className="text-slate-300 leading-relaxed text-lg">
          {reportData?.executive_summary || "Our automated systems have analyzed your website's security posture. We checked for common misconfigurations, missing defenses, and known attack vectors."}
        </p>
        <div className="mt-6 flex flex-wrap gap-4">
          <div className="bg-slate-950 px-4 py-3 rounded-xl border border-slate-800 flex-1 min-w-[200px]">
            <div className="text-sm text-slate-500 mb-1">Total Issues Found</div>
            <div className="text-2xl font-bold text-white">{issues.length}</div>
          </div>
          <div className="bg-slate-950 px-4 py-3 rounded-xl border border-slate-800 flex-1 min-w-[200px]">
            <div className="text-sm text-slate-500 mb-1">Security Controls Active</div>
            <div className="text-2xl font-bold text-emerald-400">{passed.length}</div>
          </div>
          <div className="bg-slate-950 px-4 py-3 rounded-xl border border-slate-800 flex-1 min-w-[200px]">
            <div className="text-sm text-slate-500 mb-1">Immediate Priorities</div>
            <div className="text-2xl font-bold text-red-400">{criticalAndHigh.length}</div>
          </div>
        </div>
      </div>

      {/* Top Priorities */}
      {issues.length > 0 && (
        <div className="space-y-4">
          <div className="flex items-center gap-3 mb-6 border-b border-slate-800 pb-2">
            <Target className="w-6 h-6 text-amber-500" />
            <h3 className="font-semibold text-2xl text-white">Action Plan</h3>
          </div>
          
          <div className="grid gap-4">
            {issues.map((issue, idx) => (
              <div key={idx} className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex flex-col md:flex-row gap-6 items-start">
                <div className="flex-1 space-y-3">
                  <div className="flex items-center gap-3">
                    <h4 className="font-bold text-xl text-white">{issue.name}</h4>
                    <span className={`text-xs px-2 py-1 font-bold rounded-lg ${
                      ['Critical', 'High'].includes(issue.severity) ? 'bg-red-500/20 text-red-400' : 'bg-slate-800 text-slate-300'
                    }`}>
                      {issue.severity}
                    </span>
                  </div>
                  
                  <p className="text-slate-400 text-base">{issue.description}</p>
                  
                  <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 mt-4">
                    <p className="text-sm font-semibold text-slate-200 mb-1">Business Impact:</p>
                    <p className="text-sm text-slate-400">{getBusinessRisk(issue.severity)}</p>
                  </div>
                </div>

                <div className="w-full md:w-1/3 bg-indigo-500/5 border border-indigo-500/20 p-5 rounded-2xl h-full flex flex-col justify-between">
                  <div>
                    <p className="text-sm font-bold text-indigo-400 mb-2">How to Fix This</p>
                    <p className="text-sm text-indigo-200/80 mb-4">{issue.remediation || 'Consult your engineering team to review this configuration.'}</p>
                  </div>
                  <div className="mt-auto pt-4 border-t border-indigo-500/20 text-xs text-indigo-300 flex items-center justify-between">
                    <span>Estimated Effort:</span>
                    <span className="font-bold">{getEffort(issue.severity)}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Security Strengths */}
      {passed.length > 0 && (
        <div className="bg-emerald-500/5 border border-emerald-500/20 p-8 rounded-3xl mt-12">
          <div className="flex items-center gap-3 mb-6">
            <ShieldCheck className="w-8 h-8 text-emerald-500" />
            <h3 className="font-bold text-2xl text-white">Your Security Strengths</h3>
          </div>
          <p className="text-emerald-200/70 mb-6">Your website is successfully protected against several types of attacks because you have the following defenses active:</p>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {passed.map((item, i) => (
              <div key={i} className="flex items-start gap-3 bg-emerald-950/30 p-4 rounded-xl border border-emerald-900/50">
                <CheckCircle className="w-5 h-5 text-emerald-500 shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-bold text-emerald-100 mb-1">{item.name}</h4>
                  <p className="text-xs text-emerald-200/60 leading-relaxed">{item.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  );
};

export default SimpleReport;
