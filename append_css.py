with open('src/index.css', 'a', encoding='utf-8') as f:
    f.write('''
/* ============================================
   TECHNICAL REPORT — LIGHT THEME ONLY
   ============================================ */

/* 1. MAIN TECHNICAL REPORT */
html.light-theme .technical-report {
  background-color: #f8fafc !important;
  color: #0f172a !important;
}

/* 2. MAIN FINDINGS CONTAINER & SECTIONS */
html.light-theme .technical-section {
  background-color: #ffffff !important;
  border-color: #cbd5e1 !important;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05) !important;
}
html.light-theme .technical-findings-table {
  background-color: #ffffff !important;
  border-color: #cbd5e1 !important;
}

/* 3. TABLE HEADER */
html.light-theme .technical-findings-table thead tr {
  background-color: #f1f5f9 !important;
  border-color: #cbd5e1 !important;
  color: #334155 !important;
}

/* 4. FINDING ROWS */
html.light-theme .technical-finding-row {
  background-color: #ffffff !important;
  border-color: #e2e8f0 !important;
}
html.light-theme .technical-finding-row:hover {
  background-color: #f8fafc !important;
}
html.light-theme .technical-finding-row .text-slate-200 {
  color: #0f172a !important;
}

/* 5. EXPANDED FINDING */
html.light-theme .technical-finding-expanded-inner {
  background-color: #f8fafc !important;
  border-color: #e2e8f0 !important;
}

/* 6. TECHNICAL DESCRIPTION */
html.light-theme .technical-description {
  color: #475569 !important;
}
html.light-theme .technical-finding-expanded-inner .text-slate-500 {
  color: #1e293b !important;
}

/* 7. SECURITY IMPACT / RISK */
html.light-theme .technical-risk-text {
  color: #b91c1c !important;
}

/* 8. CONFIDENCE */
html.light-theme .technical-confidence.text-emerald-400 {
  color: #059669 !important;
}
html.light-theme .technical-confidence.text-amber-300 {
  color: #b45309 !important;
}
html.light-theme .technical-confidence.text-slate-400 {
  color: #475569 !important;
}

/* 9. RAW EVIDENCE */
html.light-theme .technical-evidence {
  background-color: #ffffff !important;
  border-color: #cbd5e1 !important;
  color: #334155 !important;
}
html.light-theme .technical-evidence .text-slate-300 {
  color: #334155 !important;
}
html.light-theme .technical-evidence .text-cyan-400 {
  color: #0369a1 !important;
}

/* 10. QUICK FIX / CODE SNIPPETS */
html.light-theme .technical-code-box {
  background-color: #f1f5f9 !important;
  border-color: #cbd5e1 !important;
}
html.light-theme .technical-code-box-pre {
  background-color: #f8fafc !important;
  border-color: #cbd5e1 !important;
  color: #059669 !important;
}
html.light-theme .technical-code-box .text-slate-400 {
  color: #475569 !important;
}

/* 11. REMEDIATION PANEL */
html.light-theme .technical-remediation-panel {
  background-color: #e0e7ff !important;
  border-color: #c7d2fe !important;
}
html.light-theme .technical-remediation-panel .text-slate-300 {
  color: #334155 !important;
}
html.light-theme .technical-remediation-panel .text-slate-400 {
  color: #475569 !important;
}
html.light-theme .technical-remediation-panel .text-slate-500 {
  color: #1e293b !important;
}

/* 12. METADATA / SIDE DETAILS */
html.light-theme .technical-metadata {
  background-color: #f8fafc !important;
  border-color: #e2e8f0 !important;
}
html.light-theme .technical-metadata .text-slate-100 {
  color: #0f172a !important;
}
html.light-theme .technical-metadata .text-slate-400 {
  color: #475569 !important;
}

/* 13. PASSED ROWS */
html.light-theme .technical-passed-row {
  background-color: #f0fdf4 !important;
  border-color: #bbf7d0 !important;
}
html.light-theme .technical-passed-row:hover {
  background-color: #dcfce7 !important;
}

/* 14. OWASP BADGES */
html.light-theme .technical-owasp-badge {
  background-color: #e0e7ff !important;
  border-color: #c7d2fe !important;
  color: #4338ca !important;
}
html.light-theme .technical-owasp-badge:hover {
  background-color: #c7d2fe !important;
}
html.light-theme .technical-owasp-badge-none {
  color: #475569 !important;
}

/* 15. TYPOGRAPHY */
html.light-theme .technical-report h3 {
  color: #0f172a !important;
}
html.light-theme .technical-report .text-slate-50 {
  color: #0f172a !important;
}
''')
