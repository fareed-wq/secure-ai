# Phase 32 Coverage Audit Report

## 1. Executive Summary
The Phase 32 code-level audit reviewed all 31 existing scanner modules to determine the true implementation status of requirements requested in Phases 26–31. The scanner successfully implemented the vast majority of the requested features, but a few redundancies and genuine gaps were discovered and immediately rectified according to the Minimal-Change Principle.

## 2. Redundancy & Overlap Consolidation
- **JavaScript Module Consolidation**: Discovered two nearly identical modules, `JSBundleSecretsModule` and `JavaScriptSecurityModule`, running the exact same network probes and DOM parsing logic for JS files. 
  - **Resolution**: Merged public/private key categorizations into `JavaScriptSecurityModule` and successfully deleted `JSBundleSecretsModule`, reducing unnecessary duplicate network traffic.
- **Sensitive Paths**: Discovered `SensitivePathsModule` redundantly probing `/swagger.json` (already handled comprehensively by `OpenApiModule`).
  - **Resolution**: Deleted `SensitivePathsModule` to streamline operations and eliminate duplicate API calls.

## 3. Requirement Gap Analysis & Fixes
The following requested features were found missing and successfully implemented:
- **OpenAPI / Swagger-UI**: The `OpenApiModule` probed for `.json` and `api-docs` but missed the `/swagger-ui.html` path. This was successfully added.
- **Sensitive Env Files**: The `ExposedFilesModule` probed `.git` and `phpinfo.php` but missed `/.env` files. The `.env` probe was successfully added.
- **CORS Vulnerability Distinction**: The `CORSModule` previously only verified passive wildcard presence. It was successfully updated to inject a single `Origin` header (without active exploitation) to properly evaluate both dynamic arbitrary reflection and the presence of `Access-Control-Allow-Credentials`.
- **CVSS Generation**: While the `cvss` attribute existed in the finding dictionary, it was universally hardcoded to `None`. A centralized mapping mechanism was successfully injected into `base.make_finding()` to automatically generate static Base Vectors based on finding severity across all modules.

## 4. Intentionally Excluded Requirements
Following strict passive, stateless rules, the following requested features were confirmed missing and **intentionally excluded** from implementation:
- **Favicon MMH3 Fingerprinting**: Requires the external non-standard dependency `mmh3`.
- **Alternative Management Ports (8080, 8443, 9000)**: Probing alternative ports significantly increases latency against WAFs and disrupts the strict 25-second global budget constraints.
- **Unauthenticated API Data Extraction (e.g. `/api/me`)**: Validating whether PII is exposed requires stateful parsing and heuristic modeling which falls outside strict passive bounds.
- **PDF Generator Detection**: Highly specialized edge case with minimal widespread impact.
- **Host Header Routing Checks**: Requires DNS resolution tracking and active manipulation which violates strict passive constraints.

## 5. Test Verification
All legacy tests along with the newly generated `tests/test_phase32_coverage_audit.py` execute successfully, validating that the new CVSS generations, CORS origin checks, and Swagger/Env probes are correctly incorporated into the module architecture.
