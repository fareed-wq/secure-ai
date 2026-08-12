# Scanner Engine & Modules

The Secure-AI scanner is built on a concurrent, modular execution engine. All checks operate **passively** over HTTP/HTTPS/DNS and do not perform active vulnerability exploitation.

## Discovery & Reconnaissance
*(`discovery.py`, `infrastructure.py`)*
- **Exposed Files & Directories:** Checks common paths (e.g., `.git/`, `.env`, `phpinfo.php`) for 200 OK responses to detect severe information disclosure.
- **Metadata Files:** Validates the presence and format of `robots.txt`, `sitemap.xml`, and `security.txt`.
- **Tech Fingerprint:** Analyzes `Server` and `X-Powered-By` headers to detect exposed technology stacks and version numbers, mapped to OWASP A05 (Security Misconfiguration).

## HTTP & Header Security
*(`http_security.py`, `headers.py`)*
- **Core Security Headers:** Enforces the presence of `Strict-Transport-Security` (HSTS), `X-Content-Type-Options`, and `X-Frame-Options` to prevent MIME-sniffing and Clickjacking.
- **Advanced Security Headers:** Checks for `Content-Security-Policy` (CSP) and modern isolation headers (`Cross-Origin-Embedder-Policy`, `Cross-Origin-Opener-Policy`).
- **CORS Misconfiguration:** Actively tests the `Access-Control-Allow-Origin` behavior by sending a dummy `Origin` header to detect wildcard (`*`) or dynamically reflected origin vulnerabilities.
- **HTTPS Redirection:** Verifies that HTTP requests successfully upgrade to HTTPS.

## Authentication & Session Security
*(`auth_session_security.py`, `http_security.py`)*
- **Advanced Cookies:** Analyzes all `Set-Cookie` directives to ensure the `Secure`, `HttpOnly`, and `SameSite` flags are explicitly defined. Missing flags map to OWASP A05 and result in Medium severity findings.

## TLS & Encryption
*(`tls.py`, `network_checks.py`)*
- **Enhanced TLS:** Evaluates the SSL/TLS certificate validity, expiration date, and protocol version.
- **Cipher Strength:** Connects over sockets to evaluate if deprecated/weak ciphers (e.g., RC4, DES, 3DES, NULL ciphers) are supported by the host.

## DNS & Infrastructure
*(`dns.py`, `network_checks.py`)*
- **DNS CAA:** Checks for Certification Authority Authorization records.
- **Email Security:** Validates the presence of SPF and DMARC TXT records on the domain to prevent email spoofing (OWASP A05).
- **Subdomain Enumeration:** Passively resolves common subdomains (e.g., `dev`, `staging`, `api`) to map the external attack surface. Checks for potential dangling DNS records indicating Subdomain Takeover risks.

## APIs & Web Security
*(`api_web_security.py`, `content.py`, `javascript_security.py`)*
- **GraphQL Introspection:** Probes common GraphQL endpoints to detect if the introspection query is left enabled in production, leading to full API schema disclosure.
- **Mixed Content:** Scans the homepage DOM for `http://` assets loaded over HTTPS.

## Limitations
- **No Authentication:** The scanner cannot traverse authenticated routes or login portals.
- **Timeouts:** Long-running modules (like deep subdomain discovery) may be truncated to respect serverless platform execution limits.
