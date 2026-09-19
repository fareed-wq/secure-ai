# Project Architecture

URLScannerOnline (Secure-AI) utilizes a decoupled architecture combining a modern React frontend with a high-performance Python serverless backend engine.

## Scanner Pipeline
1. **Target**: Validates and canonicalizes the input.
2. **Orchestrator / Thread Pool**: Spawns concurrent execution environments.
3. **Modules**: Executes modular checks.
4. **make_finding**: Normalizes module outputs.
5. **Dedupe**: Eliminates overlapping findings.
6. **Metadata**: Extracts base technological indicators.
7. **Scoring**: Computes final grades.
8. **Final Output**: Emits the finalized report structure.

## Finding Contracts
All findings strictly adhere to the following contracts:
- **Structured evidence**: Standardized request/response snippets.
- **Verification state**: Whether a finding is observed, inferred, or not verified.
- **Confidence**: Assessed reliability of the finding.
- **Severity**: Base severity level.
- **
ule_id**: Deterministic vulnerability class identifier.
- **instance_key**: Deterministic instance location identifier.
- **Vulnerability state**: Tracks intelligence lifecycle.
- **CVE/CVSS/CWE/EPSS enrichment**: Curated threat intelligence (CVSS assessments may originate from NVD, CNA, and ADP).
- **Derived Priority**: Contextual dynamic sorting value.

## Technology Identity + CPE
- **Deterministic normalization**: Tech stacks map cleanly to normalized forms.
- **Curated exact CPE mappings**: Strictly defined in authoritative dictionaries.
- **No fuzzy guessing**: CPEs are never hallucinated.
- **Exact/parsing observation requirements**: Valid mappings require definitive technical observation.

## Background Enrichment
- **Core scan remains independent/fast**: Returns execution directly to the user.
- **QStash worker**: Orchestrates asynchronous fetch tasks.
- **NOT_REQUESTED ? QUEUED**: State securely tracks the lifecycle.
- **Worker lease/retry behavior**: Guards against concurrent races.
- **Approximately 45s worker budget**: Strict upper bound per worker invocation.
- **55s lease**: Prevents overlapping claims.
- **Terminal retry behavior**: Limits retry storms.
- **NVD/EPSS enrichment outside the critical scan path**: Decoupled network calls.

## Cache
- **CPE-keyed cache**: Stores intelligence natively by CPE string.
- **Cache versioning**: Validates schema compatibility.
- **expires_at > current UTC time**: Queries strictly enforce freshness.
- **Expired entries are ignored**: Automatically triggers a refresh.
- **Incomplete enrichment must not poison complete cache**: Terminal EPSS failures prevent caching.

## Compare
- **Stable identity (rule_id, instance_key-or-None)**: Powers absolute diffing.
- **Legacy identity**: Handles legacy scans lacking precise keys.
- **Mixed compatibility bridge**: Seamlessly compares modern scans to legacy scans.
- **Exact-severity-first duplicate handling**: Ensures safest deduplication.
- **Vulnerability evolution states**: Tracks exact intelligence transitions.
- **cve_removed is not remediation**: Explicitly designates missing matches rather than verified fixes.
- **Technology lifecycle**: Technology/version changes provide context; CVE evolution is determined only by the explicit vulnerability-state/CVE comparison rules.

## Reporting
- **Simple Reporting**: Provides an executive, high-level summary of the target's security posture.
- **Technical Reporting**: Delivers comprehensive evidence, verification states, and CVE/EPSS intelligence for security professionals.
