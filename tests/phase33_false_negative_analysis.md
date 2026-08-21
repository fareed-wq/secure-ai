# Phase 33 - False Negative Analysis

This report documents areas where the passive architecture constraints (budget and non-destructiveness) intentionally or unavoidably create false negatives (FNs).

## 1. Deep / Authenticated API Surface
**Limitation:** The scanner operates entirely without credentials.
**False Negative Impact:** Any vulnerability (IDOR, BOLA, injection, misconfiguration) that exists behind an authentication wall will be missed, unless the endpoints are accidentally exposed or leaked via public JavaScript/OpenAPI schemas. 

## 2. Active Injection Flaws
**Limitation:** The scanner strictly follows a non-destructive, passive design paradigm. It does not send payloads for SQLi, XSS, SSRF, or Command Injection.
**False Negative Impact:** The scanner will NOT identify classical OWASP Top 10 injection vulnerabilities, as confirming them requires actively sending malicious payloads which violates the read-only constraint.

## 3. Subdomain Bruteforcing Depth
**Limitation:** The scanner is constrained to a 25-second execution budget.
**False Negative Impact:** `SubdomainProbingModule` relies on a fixed, lightweight list of common subdomains (e.g., `api`, `dev`, `staging`). It does not perform exhaustive dictionary attacks or permutation bruteforcing. Obscure or randomly named subdomains will not be discovered.

## 4. Crawling / Spidering Depth
**Limitation:** The scanner does not implement a full web crawler.
**False Negative Impact:** Modules like `JavaScriptSecurityModule` or `MixedContentModule` only analyze the HTML body of the root target URL and files referenced directly from it. If sensitive JS bundles or insecure resources are only loaded on deep, unlinked pages (e.g., `/app/dashboard/deep_route`), the scanner will miss them.

## 5. CAPTCHA / Anti-Bot Mitigation
**Limitation:** The scanner does not use headless browsers or solve CAPTCHAs.
**False Negative Impact:** If a target employs strict bot mitigation (Cloudflare IUAM, reCAPTCHA) on the root path, the scanner may be blocked before it can parse the DOM, resulting in missed HTML/JS vulnerabilities on what is otherwise a public site.

## 6. Timeouts & Budget Caps
**Limitation:** The 25-second global budget and per-module `timeout` (usually 8s) combined with request timeouts of `(1.5, 2.5)`.
**False Negative Impact:** Slow servers or tarpits will cause modules to timeout and abort. While the scanner gracefully reports the timeout as an Informational finding, it inevitably results in false negatives for any checks that module was supposed to perform.

## Conclusion
False negatives in Secure-AI are almost entirely a byproduct of its architectural constraints: it must be fast (25s) and safe (passive). Users must be aware that a "Compliant" score indicates the absence of *passive* misconfigurations, not the absence of all vulnerabilities.
