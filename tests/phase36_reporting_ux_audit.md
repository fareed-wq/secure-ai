# Phase 36 Reporting & UX Audit

## 1. Existing Implementation Baseline

### 1.1 Simple Report Mode
**Status: Partially Implemented**
- **What is correct**: `SimpleReport.jsx` successfully renders a high-level summary, executive health summary, Target Surface breakdown, and top priorities (max 5 issues). It accurately separates issues from "Passed" checks.
- **What is missing/inconsistent**: It uses `finding.remediation`, but the wording in some checks might be overly technical for non-technical users. It does not show Informational findings (this is correct/intended).
- **Needs Improvement**: "Informational" findings are excluded from the list, which aligns with Simple mode, but we need to ensure the language remains plain.

### 1.2 Technical Report Mode
**Status: Implemented but needs refinement**
- **What is correct**: `TechnicalReport.jsx` renders a comprehensive table grouped by domains. Expandable rows show technical descriptions, evidence, CVSS, OWASP, and remediation.
- **What is missing/inconsistent**: 
  - CVSS rendering implies it's a contextually calculated score for this exact vulnerability, but `base.py` uses a default severity-to-vector mapping. It should clearly distinguish this as a "Default mapping".
  - OWASP mapping is rendered just as the string (e.g. `A05: Security Misconfiguration`). This is acceptable but could be slightly clearer.
  - Secret masking happens in `base.py` before rendering, which is correct and safe.

### 1.3 Score & Grade Presentation
**Status: Partially Implemented / Correct**
- **What is correct**: `scoring.py` accurately calculates the 0-100 score. It uses an `identity` deduplication mechanism to ensure that multiple findings of the same root cause (e.g., multiple missing headers) do not unfairly penalize the score repeatedly.
- **What is missing/inconsistent**: The `severity_counts` in the UI does NOT deduplicate (it counts all raw findings). This means the UI might say "2 High Priority Issues" but the score only deducted points for 1. The score logic is correct, but we must verify that Informational findings don't subtract points (they don't, penalty is 0).

### 1.4 PDF / Report Export
**Status: Partially Implemented / Architecturally Flawed**
- **What is correct**: `usePdfGenerator.js` exists and uses `html2canvas` + `jspdf` to export the current React DOM to a PDF.
- **What is missing/inconsistent**:
  - `usePdfGenerator.js` generates the PDF based on the dark-mode DOM which does not trigger `@media print` cleanly and uses `html2canvas` which can cut text across page breaks.
  - The backend has `/api/export/pdf` which *re-runs* the scan (`data = scan_url(req.url)`) violating the "Do NOT refetch the target" rule. However, the frontend doesn't even use this endpoint, it generates it purely client-side.
  - The dedicated print container `<div className="hidden print:block ...">` in `Scanner.jsx` is completely ignored by `html2canvas` because it is `display: none` in the normal DOM.

### 1.5 Security & Privacy
**Status: Correct**
- `base.py` masks secrets (Stripe, AWS, OpenAI, GitHub, tokens) *before* appending to the finding structure. This ensures neither the UI nor the PDF export can leak secrets.

## 2. Action Plan (Minimal Corrections)

1. **CVSS Presentation**: Update `TechnicalReport.jsx` to explicitly label CVSS as `CVSS v3.1 (Severity Default)` rather than just `CVSS v3.1 Score`.
2. **PDF Generation**: Modify `usePdfGenerator.js` to natively use the browser's `window.print()` functionality, which automatically supports `@media print`, pagination, text selection, and the dedicated clean print container in `Scanner.jsx` without large overhead. Alternatively, if we must return a PDF file, fix `html2canvas` to temporarily expose the print container and hide the dark UI during capture. Using `window.print()` is the cleanest and most reliable "minimal" improvement.
3. **Backend Export Route**: Remove or patch the `/api/export/pdf` route in `api/index.py` so it does not trigger a re-scan. It should either accept the JSON payload directly or be removed if purely relying on frontend export.
4. **Remediation Strings**: Review `REMEDIATION_SNIPPETS` in `dictionaries.py` to ensure they are plain language where possible.
5. **Score Verification**: Ensure `SimpleReport` and `TechnicalReport` always operate off the same `reportData` object seamlessly. (They currently do).

---
*End of Audit.*
