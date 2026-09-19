# Scanner Engine

## Safety Model
- **Passive/non-intrusive**: Read-only observation posture.
- **No destructive testing**: Never alters application state.
- **No brute force**: Never attempts credential guessing.
- **No fuzzing**: Never injects malformed payloads.
- **No broad crawling**: Constraints navigation strictly to targeted endpoints.

## Scoring
- **Frozen severity deductions**: Penalties are fixed.
- **Score cap/minimum**: Strictly bounded limits.
- **Grade thresholds**: Standardized letter tiers.
- **Confidence does not affect scanner score**: Scores rely solely on severity.

## Verification
- **OBSERVED**: Verified with concrete evidence.
- **INFERRED**: Highly probable but lacking direct proof.
- **NOT_VERIFIED**: Hypothetical exposure.

## Vulnerability Intelligence
- **Vulnerability states**:
  - NOT_EVALUATED
  - NO_MATCH
  - MATCHED
  - UNAVAILABLE
- **Reasons**: Provides rationale for non-evaluation.
- **CVE matching behavior**: Strict NVD adherence.
- **Authoritative NVD applicability**: The sole source of truth for matches.
- **CVSS/CWE provenance**: CVSS assessments may originate from NVD, CNA, and ADP.
- **EPSS score/percentile semantics**: EPSS provides both score and percentile, but Priority uses EPSS score only.
- **Background enrichment behavior**: Lookups execute asynchronously.

## Priority
### Finding Priority
- **Critical** ? P1
- **High** ? P2
- **Medium** ? P3
- **Low** ? P4
- **Informational/Passed** ? P5
- **invalid/missing** ? UNSCORED

### CVE Priority
- **MATCHED** ? evaluate
- **NO_MATCH** ? N/A
- **NOT_EVALUATED/UNAVAILABLE** ? UNSCORED
- Calculates max CVSS across assessments
- **CVSS Thresholds**:
  - >= 9 ? P1
  - >= 7 ? P2
  - >= 4 ? P3
  - > 0 ? P4
  - == 0 ? P5
- **EPSS score only**:
  - >= 0.10 ? P1
  - >= 0.01 ? P2
  - < 0.01 ? P5
- Highest resulting tier wins. These are URLScannerOnline deterministic policy thresholds.
- No Priority persistence.
- Priority is derived metadata. It does not change scanner score, grade, severity, identity, or persisted Phase5 data. Phase7 may compare Priority changes as derived trend metadata.

## Compare / Vulnerability Evolution
- **Intelligence acquired/recovered/lost**: Lifecycle state transitions.
- **CVE added/removed**: Identifies delta changes.
- **CVE no longer matched**: Distinguishes missing matches.
- **Priority shift**: Reflects dynamic threat evolution.
- **Technology lifecycle does not imply vulnerability remediation**: Technology/version changes provide context; CVE evolution is determined only by the explicit vulnerability-state/CVE comparison rules.
- **Missing intelligence is never "safe"**: Explicit lack of safety inference.
