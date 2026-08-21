with open('src/components/scanner/TechnicalReport.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

reps = [
    (
        '<div className="space-y-8" id="report-content">',
        '<div className="technical-report space-y-8" id="report-content">'
    ),
    (
        '<div className="report-section bg-slate-950/80',
        '<div className="technical-section report-section bg-slate-950/80'
    ),
    (
        '<div key={group.key} className="report-section bg-slate-950',
        '<div key={group.key} className="technical-section report-section bg-slate-950'
    ),
    (
        '<div className="report-section grid grid-cols-1 gap-6">',
        '<div className="technical-section report-section grid grid-cols-1 gap-6">'
    ),
    (
        '<div className="w-full min-w-0 h-full min-h-[150px] p-4 bg-slate-900/60 border',
        '<div className="technical-metadata w-full min-w-0 h-full min-h-[150px] p-4 bg-slate-900/60 border'
    ),
    (
        '<table className="w-full text-left border-collapse">',
        '<table className="technical-findings-table w-full text-left border-collapse">'
    ),
    (
        'className={`cursor-pointer hover:bg-slate-800/20 transition-colors ${expandedRow === idx ? \'bg-slate-800/30\' : \'\'}`}',
        'className={`technical-finding-row ${finding.severity === \'Passed\' ? \'technical-passed-row\' : \'\'} cursor-pointer hover:bg-slate-800/20 transition-colors ${expandedRow === idx ? \'bg-slate-800/30\' : \'\'}`}'
    ),
    (
        '<tr className="print:hidden">',
        '<tr className="technical-finding-expanded print:hidden">'
    ),
    (
        '<p className="text-slate-300 leading-relaxed text-sm">{finding.description}</p>',
        '<p className="technical-description text-slate-300 leading-relaxed text-sm">{finding.description}</p>'
    ),
    (
        '<p className="text-rose-200/80 leading-relaxed text-sm">{finding.impact}</p>',
        '<p className="technical-risk-text text-rose-200/80 leading-relaxed text-sm">{finding.impact}</p>'
    ),
    (
        '<div className={`${colorClass} font-bold mb-4`}>{finding.confidence}</div>',
        '<div className={`technical-confidence ${colorClass} font-bold mb-4`}>{finding.confidence}</div>'
    ),
    (
        '<div className="bg-slate-950 border border-slate-700/50 rounded-lg p-4 font-mono text-sm">',
        '<div className="technical-evidence bg-slate-950 border border-slate-700/50 rounded-lg p-4 font-mono text-sm">'
    ),
    (
        '<pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed shadow-inner">',
        '<pre className="technical-evidence bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed shadow-inner">'
    ),
    (
        '<div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col gap-3 h-full">',
        '<div className="technical-remediation-panel bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col gap-3 h-full">'
    ),
    (
        '<span className="bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 px-2.5 py-1 rounded-md text-xs hover:bg-indigo-500/20 cursor-pointer">{finding.owasp}</span>',
        '<span className="technical-owasp-badge bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 px-2.5 py-1 rounded-md text-xs hover:bg-indigo-500/20 cursor-pointer">{finding.owasp}</span>'
    ),
    (
        '<span className="text-slate-600 text-xs">-</span>',
        '<span className="technical-owasp-badge-none text-slate-600 text-xs">-</span>'
    ),
]

for t, r in reps:
    if t not in text:
        print(f"NOT FOUND: {t}")
    text = text.replace(t, r)

with open('src/components/scanner/TechnicalReport.jsx', 'w', encoding='utf-8', newline='\n') as f:
    f.write(text)
