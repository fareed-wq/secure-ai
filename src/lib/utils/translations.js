import { TRANSLATIONS } from '../../config/translations';

export const getTranslation = (finding) => {
  const technicalName = finding.name;

  let baseTranslation = {
    name: technicalName,
    category: "Website Trust"
  };

  if (TRANSLATIONS[technicalName]) {
    baseTranslation = { ...baseTranslation, ...TRANSLATIONS[technicalName] };
  } else if (technicalName.startsWith("Unsecured Cookie")) {
    baseTranslation.category = "Session Security";
  }

  // Always use the backend's description and impact for problem and why.
  return {
    ...baseTranslation,
    problem: finding.description || "A recommended security configuration is missing or partially configured on your web server.",
    why: finding.impact && finding.impact !== "N/A" ? finding.impact : "Resolving this configuration aligns your site with industry baseline security standards."
  };
};

export const getBusinessRisk = (severity) => {
  const risks = {
    'Critical': { label: 'Critical Remediation Priority', badge: 'bg-red-700 text-white px-3.5 py-1.5 rounded-md text-base font-bold tracking-wide inline-block shadow-sm', container: 'bg-red-950/40 border border-red-500/50 rounded-xl p-4 shadow-sm', text: 'text-red-100 text-sm mt-3 font-medium block', desc: 'Critical vulnerability detected. Immediate action required.' },
    'High': { label: 'Elevated Security Hardening Priority', badge: 'bg-rose-600 text-white px-3.5 py-1.5 rounded-md text-base font-bold tracking-wide inline-block shadow-sm', container: 'bg-rose-950/40 border border-rose-500/50 rounded-xl p-4 shadow-sm', text: 'text-rose-100 text-sm mt-3 font-medium block', desc: 'Important security misconfiguration or missing defense-in-depth control.' },
    'Medium': { label: 'Moderate Hardening Priority', badge: 'bg-amber-500 text-black px-3.5 py-1.5 rounded-md text-base font-bold tracking-wide inline-block shadow-sm', container: 'bg-amber-950/40 border border-amber-500/50 rounded-xl p-4 shadow-sm', text: 'text-amber-100 text-sm mt-3 font-medium block', desc: 'Recommended security best practice that should be implemented over time.' },
    'Low': { label: 'Routine Hardening Priority', badge: 'bg-yellow-400 text-black px-3.5 py-1.5 rounded-md text-base font-bold tracking-wide inline-block shadow-sm', container: 'bg-yellow-950/30 border border-yellow-500/40 rounded-xl p-4 shadow-sm', text: 'text-yellow-100 text-sm mt-3 font-medium block', desc: 'Minor observation related to defense-in-depth configuration.' },
    'Informational': { label: 'Observation', badge: 'bg-blue-600 text-white px-3.5 py-1.5 rounded-md text-base font-bold tracking-wide inline-block shadow-sm', container: 'bg-blue-950/40 border border-blue-500/50 rounded-xl p-4 shadow-sm', text: 'text-blue-100 text-sm mt-3 font-medium block', desc: 'Technical details that are not directly exploitable.' },
  };
  return risks[severity] || risks['Informational'];
};

export const getEffort = (severity) => {
  const effort = {
    'Critical': 'Emergency (Hours)',
    'High': 'High Priority (Days)',
    'Medium': 'Scheduled (Weeks)',
    'Low': 'Routine Backlog',
  };
  return effort[severity] || 'Minimal';
};
