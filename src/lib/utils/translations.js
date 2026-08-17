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
    'Critical': { label: 'Critical Business Risk', badge: 'bg-red-700 text-white px-3.5 py-1.5 rounded-md text-base font-bold tracking-wide inline-block shadow-sm', container: 'bg-red-950/40 border border-red-500/50 rounded-xl p-4 shadow-sm', text: 'text-red-100 text-sm mt-3 font-medium block', desc: 'Immediate risk of data breach, financial loss, or severe disruption.' },
    'High': { label: 'High Business Risk', badge: 'bg-rose-500 text-white dark:bg-rose-600 dark:text-white px-3.5 py-1.5 rounded-md text-base font-bold tracking-wide inline-block shadow-sm', container: 'bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-500/50 rounded-xl p-4 shadow-sm', text: 'text-rose-700 dark:text-rose-100 text-sm mt-3 font-medium block', desc: 'Significant risk of unauthorized access or reputational damage.' },
    'Medium': { label: 'Moderate Business Risk', badge: 'bg-amber-500 text-black px-3.5 py-1.5 rounded-md text-base font-bold tracking-wide inline-block shadow-sm', container: 'bg-amber-950/40 border border-amber-500/50 rounded-xl p-4 shadow-sm', text: 'text-amber-100 text-sm mt-3 font-medium block', desc: 'Operational risk that could be exploited if combined with other flaws.' },
    'Low': { label: 'Minimal Business Risk', badge: 'bg-amber-50 text-amber-700 border border-amber-200 dark:border-transparent dark:bg-yellow-400 dark:text-black px-3.5 py-1.5 rounded-md text-base font-bold tracking-wide inline-block shadow-sm', container: 'bg-yellow-50 dark:bg-yellow-950/30 border border-yellow-200 dark:border-yellow-500/40 rounded-xl p-4 shadow-sm', text: 'text-yellow-700 dark:text-yellow-100 text-sm mt-3 font-medium block', desc: 'Minor risk, mostly missing recommended security best practices.' },
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
