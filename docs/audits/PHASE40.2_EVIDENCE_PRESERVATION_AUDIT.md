# PHASE 40.2 EVIDENCE PRESERVATION AUDIT

## Executive Summary
This audit evaluated the Phase 40.1 backend deduplication fix for potential data loss. The audit confirmed that while Phase 40.1 successfully eliminated duplicate finding cards in the UI without affecting the scoring engine, it **did silently discard useful Raw Evidence** (subsequent NS and MX hostnames). 

A remediation is necessary to restore the lost evidence while preserving the clean, single-card UI introduced in Phase 40.1.

---

## 1. Current Deduplication Logic Analysis
**Target File:** `api/scanner/modules/infrastructure.py`

The current logic utilizes a `set()` (e.g., `identified_ns_providers`) scoped to the DNS query response. The module iterates through the returned DNS `Answer` records. When a record matches a known provider regex, the logic checks if the provider is already in the `set`. 
- **If missing:** The provider is added to the set, and a finding is generated containing that specific record as evidence.
- **If present:** The record is entirely skipped.

## 2. DNS Infrastructure Provider Identified
- **What happens when multiple NS records belong to the same provider?** Only the *first* NS record processed is evaluated. Subsequent NS records are discarded because the provider was added to the `identified_ns_providers` set on the first pass.
- **Is every unique NS record preserved anywhere?** **No.**
- **Or is only the first/one provider record retained?** Only the first record matching that provider is retained.
- **Exact Raw Evidence reaching the frontend:** `Provider: Cloudflare (NS: ns1.cloudflare.com)`

## 3. Mail Infrastructure Identified
- **What happens when multiple MX records belong to the same provider?** Identical to DNS. The first matched MX record triggers a finding, and subsequent MX records mapped to the same provider are skipped.
- **Is every unique MX record preserved?** **No.**
- **Or is only one record retained?** Only the first record.
- **Exact Raw Evidence reaching the frontend:** `Provider: Google (MX: aspmx.l.google.com)`

## 4. Pre-Phase-40 vs Current Behavior
- **PRE-PHASE-40:** The module iterated over every NS/MX record, matched the provider, broke out of the provider-matching loop, but did *not* track previously identified providers. **Result:** All unique NS/MX records were preserved, but they were split across multiple duplicate finding cards.
- **CURRENT (PHASE 40.1):** The module tracks previously identified providers via a `set()` and skips subsequent records. **Result:** Visual duplicate finding cards are fixed, but secondary NS/MX records are permanently lost.

## 5. Did Phase 40.1 Remove Useful Evidence?
**Yes.** Resolving the duplicate-card bug inadvertently caused the loss of legitimate infrastructural enumeration data. Presenting all nameservers/mailservers provides necessary intelligence for an auditor (e.g., detecting misconfigured secondary servers), and discarding them degrades the scanner's reporting quality.

## 6. Scoring Engine Impact
**The scoring engine is completely unaffected.**
In `api/scanner/scoring.py`, the numeric penalty calculation deduplicates findings based on a `scored_identities` set mapped to the finding `name` (and custom grouping categories like `TLS_Configuration_Issue`). 
- Because DNS and Mail Infrastructure findings are "Informational", they carry a numeric penalty of `0`.
- Even if they possessed a severity penalty, the scoring engine naturally collapses them by name. Thus, generating 1 finding card vs 4 finding cards produces the exact same numeric score.

## 7. Frontend Rendering Capability
**TechnicalReport / SimpleReport can cleanly render the proposed solution.**
In `TechnicalReport.jsx` (lines 322-324), string-based Raw Evidence is rendered using:
```jsx
<pre className="... whitespace-pre-wrap ...">
```
Because of `whitespace-pre-wrap`, any `\n` characters injected into the backend finding's evidence string will perfectly format as a clean, multi-line list without requiring any frontend code changes.

---

## 8. Recommended Architecture & Remediation
**Is remediation necessary?** Yes, to fully satisfy both the UX goal (no duplicate cards) and the Intelligence goal (zero evidence loss).

**Smallest Safe Remediation Approach (Backend-Only):**
Instead of evaluating and emitting findings in a single pass, the `infrastructure.py` module should:
1. Initialize a tracking dictionary: `ns_by_provider = defaultdict(list)`
2. Iterate over all `Answer` records, matching them to a provider, and appending the raw record to the provider's list (e.g., `ns_by_provider["Cloudflare"].append("ns2.cloudflare.com")`).
3. Iterate over the populated dictionary. For each unique provider, format a single, multi-line string:
   ```text
   Provider: Cloudflare
   - ns1.cloudflare.com
   - ns2.cloudflare.com
   ```
4. Emit exactly ONE logical finding per provider, passing the multi-line string into the `evidence` field.

This securely resolves the data loss, preserves the single-card UX fix, requires zero frontend changes, and maintains the scanner's passive constraints.
