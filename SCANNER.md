# Scanner Engine & Modes

The URLScannerOnline / Secure-AI scanner is built on a concurrent, modular execution engine. The engine enforces a **passive-first, low-impact** philosophy.

## Basic Scan
- **Passive Assessment:** Operates exclusively as a passive scanner.
- **Scope:** 9 passive modules (as verified in the registry) (e.g., header analysis, basic metadata discovery).
- **Behavior:** Acts like a standard, well-behaved web client. Analyzes publicly broadcasted data without intrusive probing.

## Advanced Scan
- **Authorized Bounded Active/Low-Impact:** Includes all 9 Basic checks plus an additional 20 active/low-impact modules.
- **Scope:** 20 additional active/low-impact modules (verified in registry). May perform bounded additional HTTP, DNS, and limited TCP checks.
- **Requirements:** Requires explicit authorization acknowledgement from the user.
- **Behavior:** Remains low-impact and non-exploitative. It does **not** perform penetration testing.

## Shared Safety Rules
- **Public Targets Only:** The scanner actively rejects requests to loopback addresses, RFC1918 private IPs, link-local addresses, and cloud metadata endpoints.
- **SSRF Protections:** Strong Server-Side Request Forgery protections are enforced in both Basic and Advanced modes.
- **Bounded Requests & Timeouts:** All modules are constrained by a global 45-second execution budget (SCAN_BUDGET_SECONDS).
- **No Active Exploitation:** The scanner will never inject SQLi, XSS, or OS Command payloads.
- **No Destructive Actions:** No brute forcing, password spraying, authentication bypass attempts, or DoS/stress testing.

## Scanner Modules
Modules are executed concurrently to respect serverless platform execution limits.

*(discovery.py, infrastructure.py)*
- **Discovery & Reconnaissance:** Validates the presence of
obots.txt, sitemap.xml, and security.txt. Analyzes Server and X-Powered-By headers.
- **Exposed Files:** Checks common paths (e.g., .git/, .env) for accidental information disclosure.

*(http_security.py, headers.py)*
- **HTTP & Header Security:** Enforces the presence of HSTS, CSP, X-Content-Type-Options, and X-Frame-Options.
- **CORS Misconfiguration:** Analyzes Access-Control-Allow-Origin behavior for insecure configurations.
- **Authentication & Session Security:** Analyzes Set-Cookie directives for Secure, HttpOnly, and SameSite flags.

*(	ls.py, dns.py,
etwork_checks.py)*
- **TLS & Encryption:** Evaluates SSL/TLS certificate validity and checks for deprecated/weak ciphers.
- **DNS & Infrastructure:** Checks DNS CAA, validates SPF/DMARC TXT records, and passively resolves common subdomains.

*(pi_web_security.py, content.py, javascript_security.py)*
- **APIs & Web Security:** Probes common GraphQL endpoints for exposed introspection and checks for mixed content.

## Finding Semantics
Findings are assigned the following severities:
- **Actionable:** Critical, High, Medium, Low
- **Non-actionable:** Informational, Inconclusive
- **Successful:** Passed

*Note: Aliases Info -> Informational and Skipped -> Inconclusive apply. Informational and Inconclusive findings are not counted as "Issues Found".*

## Failure Handling
- **Graceful Degradation:** Network errors or module timeouts do not automatically become vulnerability findings.
- **Inconclusive Semantics:** Uncertain results, timeouts, or unreachable targets fail safely and are reported as Inconclusive. A network/infrastructure failure must not automatically become an Informational finding.
- **Global Timeouts:** If a module exceeds its time budget, the scan continues with partial results rather than failing the entire request.

## Limitations
- **No Authentication:** The scanner cannot traverse authenticated routes or login portals.
- **Timeouts:** Long-running modules may be truncated to respect the overall execution budget.
