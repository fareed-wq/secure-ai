# SCAN RESULT HANDLING AUDIT

## Executive Summary
This audit validates the user's observation that failed or timed-out scans are improperly rendered as "clean" reports with zero findings. The root cause is that the backend orchestrator explicitly traps top-level connection failures and intercepts them with a hardcoded, mock "WAF-blocked" payload. This mock payload is designed to prevent UI crashes but contains fabricated "Passed" and "Standard" metadata, which the frontend blindly renders, causing the user to perceive the failure as a successful but empty scan.

No actual detection logic or real findings are lost during a successful scan. This is purely an error-handling and API contract discrepancy.

---

## A. Root Cause
When the scanner fails to establish an initial connection (e.g., due to an aggressive WAF, network block, or DNS failure), the `check_liveness()` or `initial_resp` block catches the exception. Instead of propagating an error status to the frontend (e.g., `status: "failed"`), the backend calls `get_waf_fallback_payload(url)`. 

This fallback function generates a hardcoded "mock" report designed to simulate a successful API response. The mock report intentionally populates fields like `score: 45` and `target_surface` with fabricated default values (e.g., `frontend_stack: "Standard Web Stack"`, `js_health: "Clean Build"`). The frontend receives this 200 OK mock response, observes exactly one Informational finding ("Target Origin Protected by Enterprise WAF"), and renders the UI. Because there are no High/Med/Low vulnerabilities, the UI calculates "Issues Found: 0".

## B. Exact Affected Files/Functions
1. `api/scanner/orchestrator.py`
   - `scan_url()`: The initial `except` block catches `requests.exceptions.RequestException` and `socket.timeout` and explicitly returns `get_waf_fallback_payload(url)`.
   - `scan_url()`: The `check_liveness(hostname)` block generates a similar hardcoded `score: 100` mock report.
2. `api/scanner/fallback.py`
   - `get_waf_fallback_payload()`: Hardcodes the fallback payload, including the fabricated `target_surface` values and `severity_counts`.
3. `src/components/scanner/SimpleReport.jsx`
   - `isWafBlocked` heuristic: Checks if `findings.length === 1 && findings[0]?.name?.includes('WAF')`.
   - `issues.length` and `passed.length`: Calculated purely by filtering the `findings` array (which only contains the single Informational mock finding).
4. `src/components/scanner/ScoreDisplay.jsx`
   - Reads `isWafBlocked` and overrides the numeric score to display `"N/A"`.

## C. Exact API Response/State Involved
When a timeout occurs, the frontend receives:
```json
{
  "status": "waf_protected",
  "score": 45,
  "findings": [
    {
      "name": "Target Origin Protected by Enterprise WAF",
      "severity": "Informational"
    }
  ],
  "target_surface": {
    "frontend_stack": "Standard Web Stack",
    "js_health": "Clean Build"
  }
}
```

## D. Why the UI is Showing Contradictory Information
- **Issues Found: 0 / Passed Checks: 0:** The frontend calculates these metrics directly from the `findings` array. The array contains exactly 1 finding (Informational), so `issues = 0` (no High/Med/Low) and `passed = 0` (no Passed severity).
- **Score: N/A:** `ScoreDisplay.jsx` explicitly checks the `isWafBlocked` heuristic. If true, it discards the `score: 45` and renders the string `"N/A"`.
- **"Clean Build" / "Standard Web Stack":** These strings are hardcoded into the fallback payload in `fallback.py` and passed down to `SimpleReport.jsx`.

## E. Are Real Findings Being Lost?
**No.** Real findings are not being lost. This behavior only triggers when the initial HTTP connection completely fails or times out. In these scenarios, the scanner never executed the modules, so there are zero real findings to lose. (During a successful scan, the fallback payload is never used, and no findings are lost).

## F. Smallest Safe Remediation
1. **Define Explicit Error States:** Modify `api/scanner/orchestrator.py` to return an explicit overarching status flag (e.g., `status: "failed"` or `status: "timeout"`) rather than attempting to masquerade as a successful scan via `get_waf_fallback_payload()`.
2. **Remove Fabricated Fallbacks:** Do not populate `target_surface` with fabricated "Clean Build" metrics if the scan timed out. Return `null` or explicit `"N/A"` strings for these fields.
3. **Update UI Rendering:** In `ScannerInterface.jsx` and `SimpleReport.jsx`, explicitly check for `status === "failed" || status === "timeout"`. If detected, render a dedicated "Scan Incomplete / Failed to Connect" error view instead of passing the empty payload into the standard report components. 

## G. Files That Would Need Modification
- `api/scanner/orchestrator.py`
- `api/scanner/fallback.py`
- `src/components/scanner/ScannerInterface.jsx`
- `src/components/scanner/SimpleReport.jsx`

## H. Regression Risks
- Modifying `ScannerInterface.jsx` to intercept error states could break the graceful degradation if the React conditional rendering throws an error.
- Stripping out `get_waf_fallback_payload()` might cause legacy components (if any rely strictly on the presence of `target_surface` keys) to crash via `Cannot read properties of undefined`. Safe optional chaining (`?.`) must be verified on the frontend.
