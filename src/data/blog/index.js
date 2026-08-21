export const articles = [
    {
        "id": "1",
        "title": "Website Security Checklist: 20 Things Every Website Owner Should Check",
        "slug": "website-security-checklist",
        "category": "Website Security",
        "primaryKeyword": "website security checklist",
        "excerpt": "A practical 20-point checklist for identifying common website security weaknesses, configuration issues, and exposure risks.",
        "content": "Securing a website in today's threat landscape requires a proactive approach. This practical <strong>website security checklist</strong> covers 20 essential steps every website owner should take to identify potential weaknesses.",
        "sections": [
            {
                "id": "enforce-https",
                "number": "01",
                "title": "Enforce HTTPS Everywhere",
                "content": "Ensure your website uses TLS encryption for all connections. Never transmit data over plain HTTP. Obtain a valid SSL/TLS certificate and force all traffic to use HTTPS. You can quickly verify your HTTPS setup using a <a href=\"/scan\">passive vulnerability scanner</a>.",
                "listTitle": "What to check",
                "list": [
                    "HTTPS is enabled on all pages",
                    "HTTP automatically redirects to HTTPS",
                    "TLS certificate is valid and not expired"
                ]
            },
            {
                "id": "configure-tls",
                "number": "02",
                "title": "Configure Strong TLS Settings",
                "content": "For modern public-facing websites, disable obsolete protocols such as TLS 1.0 and TLS 1.1 and generally prefer TLS 1.2 or TLS 1.3, subject to your compatibility requirements.",
                "listTitle": "What to check",
                "list": [
                    "TLS 1.2 and TLS 1.3 are enabled",
                    "TLS 1.0 and TLS 1.1 are disabled",
                    "Strong cipher suites are prioritized"
                ]
            },
            {
                "id": "security-headers",
                "number": "03",
                "title": "Implement Essential Security Headers",
                "content": "Deploy <a href=\"/blog/http-security-headers-guide\">security headers</a> such as X-Content-Type-Options, X-Frame-Options, and Referrer-Policy to instruct browsers to enforce basic security mechanisms automatically.",
                "listTitle": "What to check",
                "list": [
                    "X-Content-Type-Options is set to nosniff",
                    "X-Frame-Options is set to DENY or SAMEORIGIN",
                    "Referrer-Policy is configured correctly"
                ]
            },
            {
                "id": "setup-csp",
                "number": "04",
                "title": "Set up Content Security Policy (CSP)",
                "content": "A well-designed <a href=\"/blog/content-security-policy-guide\">Content Security Policy</a> can significantly reduce the impact of many XSS and content-injection scenarios, but it should complement secure application coding rather than replace it.",
                "listTitle": "What to check",
                "list": [
                    "CSP header is present",
                    "unsafe-inline is avoided if possible",
                    "Default-src is properly restricted"
                ]
            },
            {
                "id": "enable-hsts",
                "number": "05",
                "title": "Enable HTTP Strict Transport Security (HSTS)",
                "content": "HSTS guarantees that browsers will only connect to your site over HTTPS, preventing downgrade attacks. Ensure the max-age directive is sufficiently long.",
                "listTitle": "What to check",
                "list": [
                    "Strict-Transport-Security header is active",
                    "max-age is properly configured",
                    "includeSubDomains is used when applicable"
                ]
            },
            {
                "id": "secure-cookies",
                "number": "06",
                "title": "Secure Session Cookies",
                "content": "All session cookies must be flagged with Secure, HttpOnly, and an appropriate SameSite attribute to protect against interception and CSRF.",
                "listTitle": "What to check",
                "list": [
                    "Secure flag is true",
                    "HttpOnly flag is true",
                    "SameSite attribute is Strict or Lax"
                ]
            },
            {
                "id": "strengthen-auth",
                "number": "07",
                "title": "Strengthen Authentication",
                "content": "Enforce strong password policies, require multi-factor authentication (MFA) for administrative accounts, and securely hash passwords.",
                "listTitle": "What to check",
                "list": [
                    "MFA is required for admins",
                    "Passwords are hashed (e.g. bcrypt/Argon2)",
                    "Password complexity is enforced"
                ]
            },
            {
                "id": "access-control",
                "number": "08",
                "title": "Implement Strict Access Control",
                "content": "Enforce the principle of least privilege. Ensure that users can only access the data and features explicitly permitted by their role.",
                "listTitle": "What to check",
                "list": [
                    "Role-based access is active",
                    "Default deny is implemented",
                    "Object-level authorization is checked"
                ]
            },
            {
                "id": "sensitive-files",
                "number": "09",
                "title": "Prevent Exposed Sensitive Files",
                "content": "Verify that configuration files, version control directories (like .git), and backups are not publicly accessible on your web server.",
                "listTitle": "What to check",
                "list": [
                    ".git directory is blocked",
                    ".env files return 403 or 404",
                    "Backup files (.bak, .sql) are secured"
                ]
            },
            {
                "id": "info-disclosure",
                "number": "10",
                "title": "Prevent Information Disclosure",
                "content": "Turn off detailed error messages and stack traces in production. Remove verbose server headers that reveal your technology stack.",
                "listTitle": "What to check",
                "list": [
                    "Server header is hidden or generic",
                    "X-Powered-By is removed",
                    "Stack traces are disabled in production"
                ]
            },
            {
                "id": "audit-js",
                "number": "11",
                "title": "Audit JavaScript and Source Maps",
                "content": "Review client-side bundles. Ensure you are not accidentally exposing sensitive API keys, secrets, or privileged endpoints.",
                "listTitle": "What to check",
                "list": [
                    "Source maps are not publicly deployed",
                    "API keys in frontend are safe to expose",
                    "Internal endpoints are removed"
                ]
            },
            {
                "id": "secure-apis",
                "number": "12",
                "title": "Secure API Endpoints",
                "content": "Protect all API routes with robust authentication and authorization. Do not rely on frontend obscurity.",
                "listTitle": "What to check",
                "list": [
                    "All API endpoints require auth",
                    "Rate limiting is active",
                    "Input validation is performed"
                ]
            },
            {
                "id": "restrict-cors",
                "number": "13",
                "title": "Restrict CORS",
                "content": "Do not use a wildcard (*) for Access-Control-Allow-Origin on sensitive endpoints. Only allow trusted domains.",
                "listTitle": "What to check",
                "list": [
                    "Wildcard CORS is avoided",
                    "Trusted origins are explicitly defined",
                    "Credentials are not allowed with wildcard"
                ]
            },
            {
                "id": "dns-settings",
                "number": "14",
                "title": "Secure DNS and Domain Settings",
                "content": "Implement SPF, DKIM, and DMARC to prevent email spoofing. Monitor for dangling DNS records.",
                "listTitle": "What to check",
                "list": [
                    "SPF records are valid",
                    "DMARC policy is established",
                    "No dangling subdomains exist"
                ]
            },
            {
                "id": "backups",
                "number": "15",
                "title": "Maintain Regular Backups",
                "content": "Automate backups of your database and application files. Store them securely offsite and test the restoration process periodically.",
                "listTitle": "What to check",
                "list": [
                    "Automated backups run successfully",
                    "Restoration is tested",
                    "Backups are stored offsite"
                ]
            },
            {
                "id": "update-deps",
                "number": "16",
                "title": "Update Dependencies Regularly",
                "content": "Use dependency scanning tools to identify and update vulnerable libraries, frameworks, and CMS plugins.",
                "listTitle": "What to check",
                "list": [
                    "Automated dependency scans are active",
                    "Known CVEs are patched",
                    "Obsolete packages are replaced"
                ]
            },
            {
                "id": "security-logging",
                "number": "17",
                "title": "Implement Security Logging",
                "content": "Log security-relevant events like logins, password changes, access control failures, and administrative actions.",
                "listTitle": "What to check",
                "list": [
                    "Auth failures are logged",
                    "Admin actions are tracked",
                    "Logs are stored securely"
                ]
            },
            {
                "id": "active-monitoring",
                "number": "18",
                "title": "Set Up Active Monitoring",
                "content": "Monitor your website for uptime, unauthorized changes, and suspicious traffic patterns.",
                "listTitle": "What to check",
                "list": [
                    "Uptime alerts are active",
                    "Traffic anomalies trigger alerts",
                    "Log analysis is performed"
                ]
            },
            {
                "id": "vuln-scans",
                "number": "19",
                "title": "Run Regular Security Scans",
                "content": "Using tools like URLScannerOnline can help you identify missing headers, exposed files, and misconfigurations.",
                "listTitle": "What to check",
                "list": [
                    "Automated scans are scheduled",
                    "Findings are prioritized",
                    "Remediations are tracked"
                ]
            },
            {
                "id": "incident-response",
                "number": "20",
                "title": "Plan for Incident Response",
                "content": "Have a documented plan for what to do if a breach occurs. Know who to contact and how to communicate.",
                "listTitle": "What to check",
                "list": [
                    "IR plan is documented",
                    "Roles are defined",
                    "Communication templates exist"
                ]
            }
        ]
    },
    {
        "id": "2",
        "title": "How to Check if a Website Is Secure: A Practical Guide",
        "slug": "how-to-check-if-a-website-is-secure",
        "category": "Website Security",
        "primaryKeyword": "how to check if a website is secure",
        "excerpt": "Learn the practical steps to evaluate a website's security posture, from basic visual checks to advanced vulnerability scanning.",
        "content": "Understanding <strong>how to check if a website is secure</strong> is essential for site owners and visitors alike. This practical guide covers everything from basic browser indicators to targeted security testing.",
        "sections": [
            {
                "id": "basic-checks",
                "title": "Basic Checks (Visual and Browser)",
                "content": "The easiest way to perform an initial check is by looking at the browser's address bar. Ensure the URL begins with HTTPS. However, remember that encryption alone does not guarantee the site itself is safe from vulnerabilities or malicious intent."
            },
            {
                "id": "passive-analysis",
                "title": "Passive Security Analysis",
                "content": "Passive security analysis involves evaluating a website without sending malicious payloads or intrusive requests. This approach analyzes the primary target responses, observing headers, cookies, configuration files, and exposed client-side code. Tools like URLScannerOnline's passive mode perform read-only checks to identify issues like missing security headers (e.g., CSP, HSTS), weak TLS configurations, and unintended information disclosure."
            },
            {
                "id": "active-testing",
                "title": "Active Security Testing",
                "content": "Active testing goes deeper by sending additional requests to application endpoints to map the attack surface. This includes directory probing, endpoint discovery, and API introspection. Because it generates more traffic, it carries a slightly higher footprint than passive analysis."
            },
            {
                "id": "vuln-scanning",
                "title": "Vulnerability Scanning",
                "content": "Automated vulnerability scanners systematically test a web application for known flaws like SQL Injection (SQLi) and Cross-Site Scripting (XSS). Scanning is a crucial component of continuous security."
            },
            {
                "id": "pentesting",
                "title": "Penetration Testing",
                "content": "While automated tools cover immense ground quickly, manual penetration testing involves human experts simulating real-world attacks. Pentesters chain vulnerabilities together to breach systems and exfiltrate data."
            }
        ]
    },
    {
        "id": "3",
        "title": "How to Detect OWASP Top 10 Vulnerabilities Using Passive Scanning",
        "slug": "owasp-top-10-explained",
        "category": "OWASP Security",
        "primaryKeyword": "OWASP Top 10",
        "excerpt": "A detailed breakdown of the current OWASP Top 10 web application security risks and how to protect your applications against them.",
        "content": "The <strong>OWASP Top 10</strong> is the universally recognized awareness document for web application security. It represents a broad consensus about the most critical security risks to web applications.",
        "sections": [
            {
                "id": "a01",
                "title": "A01: Broken Access Control",
                "content": "This occurs when users can act outside their intended permissions. It is currently the most serious web application risk.",
                "list": [
                    "Why it matters: Attackers can bypass access checks to modify data.",
                    "Example: Changing a URL parameter to view someone else's profile.",
                    "Prevention: Enforce access controls strictly on the server side."
                ]
            },
            {
                "id": "a02",
                "title": "A02: Cryptographic Failures",
                "content": "Previously known as Sensitive Data Exposure, this focuses on failures related to cryptography.",
                "list": [
                    "Why it matters: Passwords and personal data can be stolen.",
                    "Example: Transmitting credentials over unencrypted HTTP.",
                    "Prevention: Enforce strong HTTPS/TLS, use modern hashing."
                ]
            },
            {
                "id": "a03",
                "title": "A03: Injection",
                "content": "Injection flaws occur when untrusted data is sent to an interpreter as part of a command.",
                "list": [
                    "Why it matters: Attackers can execute arbitrary commands.",
                    "Example: Entering SQL statements into a login form.",
                    "Prevention: Use safe APIs and parameterized queries."
                ]
            },
            {
                "id": "a04",
                "title": "A04: Insecure Design",
                "content": "A new category focusing on risks related to design flaws.",
                "list": [
                    "Why it matters: A perfectly implemented system can still be vulnerable if the design is flawed.",
                    "Example: Weak password reset tokens.",
                    "Prevention: Perform threat modeling."
                ]
            },
            {
                "id": "a05",
                "title": "A05: Security Misconfiguration",
                "content": "This includes insecure default settings, incomplete configurations, open cloud storage, and misconfigured HTTP headers.",
                "list": [
                    "Why it matters: Misconfigurations provide easy avenues to exploit a system.",
                    "Example: Leaving default administrative credentials active.",
                    "Prevention: Automate hardening processes and audit configurations."
                ]
            }
        ]
    },
    {
        "id": "4",
        "title": "HTTP Security Headers: Complete Guide for Website Owners",
        "slug": "http-security-headers-guide",
        "category": "Security Headers",
        "primaryKeyword": "security headers",
        "excerpt": "A comprehensive guide to HTTP security headers, their purpose, and how to configure them to protect your web application.",
        "content": "<strong>HTTP security headers</strong> are instructions sent by your web server to the user's browser. They provide an essential layer of defense by dictating how the browser should behave when interacting with your site.",
        "sections": [
            {
                "id": "csp",
                "title": "Content-Security-Policy (CSP)",
                "content": "Defends against Cross-Site Scripting (XSS) and data injection attacks by strictly defining which domains are allowed to load scripts. Avoid using 'unsafe-inline'."
            },
            {
                "id": "hsts",
                "title": "Strict-Transport-Security (HSTS)",
                "content": "Enforces secure connections by telling the browser to never load the site over plain HTTP. Start with a short max-age to test."
            },
            {
                "id": "xcto",
                "title": "X-Content-Type-Options",
                "content": "Prevents MIME-sniffing. Forces the browser to honor the declared Content-Type. Set strictly to nosniff."
            },
            {
                "id": "xfo",
                "title": "X-Frame-Options",
                "content": "Prevents Clickjacking attacks by stopping malicious websites from embedding your site. Use DENY or SAMEORIGIN."
            },
            {
                "id": "rp",
                "title": "Referrer-Policy",
                "content": "Controls how much origin information is sent when users click links. strict-origin-when-cross-origin is the recommended modern default."
            },
            {
                "id": "pp",
                "title": "Permissions-Policy",
                "content": "Controls browser features and APIs. Allows you to disable APIs like the camera or microphone, reducing the attack surface."
            }
        ],
        "faqs": [
            {
                "question": "What are the most critical HTTP security headers?",
                "answer": "The most critical headers are Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Content-Type-Options, X-Frame-Options, and Referrer-Policy."
            },
            {
                "question": "Can I check my website security headers for free?",
                "answer": "Yes, you can use online passive vulnerability scanners to check your security headers without performing any active exploitation."
            },
            {
                "question": "Does missing X-Frame-Options mean I am vulnerable to Clickjacking?",
                "answer": "Yes, if X-Frame-Options or a CSP frame-ancestors directive is missing, malicious sites can embed your site in an iframe to trick users into clicking buttons."
            }
        ]
    },
    {
        "id": "5",
        "title": "Content Security Policy (CSP): What It Is and How to Configure It",
        "slug": "content-security-policy-guide",
        "category": "Security Headers",
        "primaryKeyword": "Content Security Policy",
        "excerpt": "Learn how to build and deploy a robust Content Security Policy to protect your users from Cross-Site Scripting (XSS) attacks.",
        "content": "A <strong>Content Security Policy (CSP)</strong> is an HTTP response header that can significantly reduce the risk of Cross-Site Scripting (XSS) and data injection attacks.",
        "sections": [
            {
                "id": "how-it-works",
                "title": "How CSP Works",
                "content": "Without a CSP, browsers assume that all scripts delivered by a server are trusted. With a CSP, the browser checks every script, stylesheet, and image against a strict whitelist."
            },
            {
                "id": "directives",
                "title": "Key CSP Directives",
                "content": "Key directives you should understand:",
                "list": [
                    "default-src: The fallback policy for most directives.",
                    "script-src: Defines valid sources for JavaScript.",
                    "style-src: Defines valid sources for stylesheets.",
                    "connect-src: Restricts the URLs to which the browser can send data.",
                    "frame-ancestors: Specifies valid parents that may embed a page."
                ]
            },
            {
                "id": "report-only",
                "title": "Report-Only Mode",
                "content": "Use the Content-Security-Policy-Report-Only header to monitor what resources would be blocked without actually blocking them."
            },
            {
                "id": "mistakes",
                "title": "Common CSP Mistakes",
                "content": "The most critical mistake is relying on overly permissive whitelists or using 'unsafe-inline'. While it makes development easier, allowing inline scripts effectively neuters the XSS protection."
            }
        ]
    },
    {
        "id": "6",
        "title": "HSTS Explained: How HTTP Strict Transport Security Protects Websites",
        "slug": "hsts-explained",
        "category": "SSL / TLS Security",
        "primaryKeyword": "HSTS",
        "excerpt": "Understand HTTP Strict Transport Security (HSTS), how it prevents downgrade attacks, and best practices for deployment.",
        "content": "<strong>HTTP Strict Transport Security (HSTS)</strong> is an essential security mechanism that protects websites against protocol downgrade attacks.",
        "sections": [
            {
                "id": "http-vs-https",
                "title": "HTTP vs HTTPS",
                "content": "While modern websites typically redirect HTTP traffic to HTTPS, the initial HTTP request is unencrypted. An attacker could intercept that initial request."
            },
            {
                "id": "how-hsts-solves",
                "title": "How HSTS Solves the Problem",
                "content": "HSTS mitigates this by instructing the browser to remember that the site is HTTPS-only. The browser will automatically upgrade all HTTP requests to HTTPS."
            },
            {
                "id": "directives",
                "title": "HSTS Directives",
                "content": "Key configuration directives:",
                "list": [
                    "max-age: The time, in seconds, that the browser should remember the policy.",
                    "includeSubDomains: Applies the rule to all subdomains.",
                    "preload: Indicates consent to be hardcoded into the browser's HSTS preload list."
                ]
            },
            {
                "id": "deployment",
                "title": "Deployment Considerations",
                "content": "Rolling out HSTS should be done cautiously. Start with a very short max-age to ensure it doesn't break your site. Gradually increase the max-age as you gain confidence."
            }
        ]
    },
    {
        "id": "7",
        "title": "TLS 1.2 vs TLS 1.3: Security, Performance and Compatibility",
        "slug": "tls-1-2-vs-tls-1-3",
        "category": "SSL / TLS Security",
        "primaryKeyword": "TLS 1.2 vs TLS 1.3",
        "excerpt": "A technical comparison of TLS 1.2 and TLS 1.3, highlighting the security enhancements and performance benefits of modern encryption.",
        "content": "Transport Layer Security (TLS) is the protocol responsible for providing secure, encrypted communications. Understanding <strong>TLS 1.2 vs TLS 1.3</strong> is critical.",
        "sections": [
            {
                "id": "security-improvements",
                "title": "Security Improvements",
                "content": "TLS 1.3 brings a massive overhaul to the protocol's security by eliminating obsolete and insecure cryptographic features. TLS 1.3 strictly limits cipher suites to a handful of highly secure algorithms."
            },
            {
                "id": "performance",
                "title": "Handshake and Performance",
                "content": "TLS 1.2 requires two round-trips (2-RTT) to establish a connection. TLS 1.3 optimizes the handshake to require only one round-trip (1-RTT), drastically improving page load times."
            },
            {
                "id": "compatibility",
                "title": "Compatibility",
                "content": "For modern public-facing websites, disable obsolete protocols such as TLS 1.0 and TLS 1.1 and generally prefer TLS 1.2 or TLS 1.3, subject to your compatibility requirements."
            },
            {
                "id": "cipher-suites",
                "title": "Cipher Suite Considerations",
                "content": "Even if TLS 1.2 is enabled for compatibility, ensure that the server prefers strong, modern ciphers and refuses to negotiate weak CBC-mode ciphers whenever possible."
            }
        ]
    },
    {
        "id": "8",
        "title": "API Security Checklist: 15 Things Developers Should Check",
        "slug": "api-security-checklist",
        "category": "API Security",
        "primaryKeyword": "API security checklist",
        "excerpt": "A comprehensive API security checklist to help developers secure endpoints, manage authentication, and prevent data breaches.",
        "content": "APIs are the backbone of modern web applications, making them prime targets. This <strong>API security checklist</strong> provides steps to secure their architecture.",
        "sections": [
            {
                "id": "auth",
                "number": "01",
                "title": "Enforce Robust Authentication",
                "content": "Do not rely on simple API keys for sensitive user data. Use modern authentication mechanisms like OAuth 2.0."
            },
            {
                "id": "authz",
                "number": "02",
                "title": "Implement Strict Authorization",
                "content": "Authentication proves who the user is; authorization proves what they can do. Enforce role-based access control."
            },
            {
                "id": "bola",
                "number": "03",
                "title": "Check Object-Level Access Control",
                "content": "Ensure that a user requesting data for a specific object ID actually has permission to view that exact object."
            },
            {
                "id": "validation",
                "number": "04",
                "title": "Validate All Input",
                "content": "Never trust client input. Implement strict type checking and length restrictions."
            },
            {
                "id": "rate-limit",
                "number": "05",
                "title": "Apply Rate Limiting",
                "content": "Protect endpoints from brute-force attacks by enforcing strict rate limits per IP."
            },
            {
                "id": "cors",
                "number": "06",
                "title": "Secure CORS Policies",
                "content": "Restrict Cross-Origin Resource Sharing. Avoid using wildcards (*) for authenticated APIs."
            },
            {
                "id": "tls",
                "number": "07",
                "title": "Force TLS Everywhere",
                "content": "Require HTTPS for all API traffic to ensure data is encrypted in transit."
            },
            {
                "id": "secrets",
                "number": "08",
                "title": "Manage Secrets Securely",
                "content": "Never hardcode API keys in the source code. Use secure environment variables."
            },
            {
                "id": "errors",
                "number": "09",
                "title": "Standardize Error Handling",
                "content": "Suppress stack traces and verbose debug information that could leak internal details."
            },
            {
                "id": "docs",
                "number": "10",
                "title": "Protect API Documentation",
                "content": "Do not expose Swagger or OpenAPI endpoints to the public internet unless intended."
            },
            {
                "id": "audit-endpoints",
                "number": "11",
                "title": "Audit Sensitive Endpoints",
                "content": "Review administrative routes and password reset flows for potential bypasses."
            },
            {
                "id": "logging",
                "number": "12",
                "title": "Implement Audit Logging",
                "content": "Log authentication events. Ensure logs do not contain plaintext passwords."
            },
            {
                "id": "versioning",
                "number": "13",
                "title": "Use API Versioning",
                "content": "Enforce explicit API versioning to safely deprecate insecure endpoints."
            },
            {
                "id": "deps",
                "number": "14",
                "title": "Monitor Dependencies",
                "content": "Continuously scan dependencies for known CVEs and update them."
            },
            {
                "id": "monitor",
                "number": "15",
                "title": "Automate Security Monitoring",
                "content": "Integrate continuous monitoring to alert teams to unusual access patterns."
            }
        ]
    },
    {
        "id": "9",
        "title": "Common API Security Vulnerabilities and How to Prevent Them",
        "slug": "common-api-security-vulnerabilities",
        "category": "API Security",
        "primaryKeyword": "API security vulnerabilities",
        "excerpt": "Explore the most common API security vulnerabilities, including Broken Object Level Authorization, and learn how to prevent them.",
        "content": "As applications become increasingly distributed, <strong>API security vulnerabilities</strong> have become the primary attack vector. This guide explores the most frequent problems.",
        "sections": [
            {
                "id": "bola",
                "title": "Broken Object Level Authorization (BOLA)",
                "content": "BOLA occurs when an API endpoint uses an ID provided by the client to access a resource without verifying authorization. Always enforce authorization checks at the object level."
            },
            {
                "id": "auth",
                "title": "Broken Authentication",
                "content": "Flaws in authentication allow attackers to compromise passwords or tokens. Implement standard flows like OAuth 2.0 and validate JWT signatures explicitly."
            },
            {
                "id": "exposure",
                "title": "Excessive Data Exposure",
                "content": "APIs often return full data objects, relying on the frontend UI to filter out sensitive fields. Never rely on the client to filter data."
            },
            {
                "id": "limits",
                "title": "Lack of Resources & Rate Limiting",
                "content": "APIs that do not restrict request frequency are susceptible to DoS. Implement strict rate limiting policies and pagination."
            }
        ]
    },
    {
        "id": "10",
        "title": "DAST vs SAST: What's the Difference?",
        "slug": "dast-vs-sast",
        "category": "Security Testing",
        "primaryKeyword": "DAST vs SAST",
        "excerpt": "A detailed comparison of Dynamic Application Security Testing (DAST) and Static Application Security Testing (SAST).",
        "content": "Integrating automated security tooling is critical. Understanding <strong>DAST vs SAST</strong> is vital for building a comprehensive security program.",
        "sections": [
            {
                "id": "sast",
                "title": "What is SAST?",
                "content": "Static Application Security Testing analyzes the source code without executing the program.",
                "list": [
                    "Strengths: Identifies exact lines of code where vulnerabilities exist.",
                    "Limitations: High false positives, cannot detect runtime issues."
                ]
            },
            {
                "id": "dast",
                "title": "What is DAST?",
                "content": "Dynamic Application Security Testing evaluates the application from the outside in while it is running.",
                "list": [
                    "Strengths: Accurate regarding exploitability. Detects real-world misconfigurations.",
                    "Limitations: Cannot pinpoint exact source code lines."
                ]
            },
            {
                "id": "complementary",
                "title": "Complementary Approaches",
                "content": "SAST and DAST are highly complementary. SAST catches coding errors early, while DAST validates the security posture of the deployed application."
            }
        ]
    },
    {
        "id": "11",
        "title": "Vulnerability Scanning vs Penetration Testing: What's the Difference?",
        "slug": "vulnerability-scanning-vs-penetration-testing",
        "category": "Security Testing",
        "primaryKeyword": "vulnerability scanning vs penetration testing",
        "excerpt": "Learn the vital differences between automated vulnerability scanning and manual penetration testing.",
        "content": "While both are essential components, <strong>vulnerability scanning and penetration testing</strong> serve vastly different purposes.",
        "sections": [
            {
                "id": "scanning",
                "title": "Vulnerability Scanning",
                "content": "An automated security assessment that systematically inspects applications for known security flaws.",
                "list": [
                    "Nature: Automated, repeatable, and scalable.",
                    "Limitations: Cannot understand complex business logic flaws."
                ]
            },
            {
                "id": "pentesting",
                "title": "Penetration Testing",
                "content": "A highly manual exercise conducted by human security experts attempting to exploit vulnerabilities.",
                "list": [
                    "Nature: Manual, complex, and time-intensive.",
                    "Limitations: A point-in-time snapshot and more expensive."
                ]
            },
            {
                "id": "difference",
                "title": "The Essential Difference",
                "content": "Automated scanning ensures baseline hygiene is maintained continuously. Penetration testing should be performed annually to dive deep into business logic."
            }
        ]
    },
    {
        "id": "12",
        "title": "Passive vs Active Security Testing: What's the Difference?",
        "slug": "passive-vs-active-security-testing",
        "category": "Security Testing",
        "primaryKeyword": "passive vs active security testing",
        "excerpt": "Understand the differences between passive and active security testing.",
        "content": "When assessing the security posture of a live web application, understanding <strong>passive vs active security testing</strong> is critical.",
        "sections": [
            {
                "id": "passive",
                "title": "Passive Security Testing",
                "content": "Analyzes the primary target responses with minimal target interaction.",
                "list": [
                    "Behavior: Observes responses without endpoint fuzzing.",
                    "What it finds: Missing headers, insecure cookies.",
                    "When to use: Continuous monitoring of sensitive environments."
                ]
            },
            {
                "id": "active",
                "title": "Active Security Testing",
                "content": "Interacts forcefully with the target to discover vulnerabilities.",
                "list": [
                    "Behavior: Sends unexpected payloads and fuzzes inputs.",
                    "What it finds: SQL injection, path traversal.",
                    "When to use: Periodic deep assessments."
                ]
            },
            {
                "id": "approach",
                "title": "A Blended Approach",
                "content": "Combining both approaches provides the best coverage. Passive scans can run continuously, while active testing occurs during dedicated windows."
            }
        ]
    },

    {
        "id": "fix-hsts-header",
        "title": "How to Fix Missing Strict-Transport-Security Header",
        "slug": "fix-missing-strict-transport-security-header",
        "category": "Remediation",
        "primaryKeyword": "strict-transport-security header",
        "excerpt": "Learn why the HTTP Strict Transport Security (HSTS) header is critical for securing your traffic and how to implement it safely on modern web servers.",
        "content": "The <strong>Strict-Transport-Security (HSTS)</strong> header is an essential security control that instructs web browsers to only connect to your site via secure HTTPS connections. Without this header, your visitors are vulnerable to protocol downgrade attacks and cookie hijacking. In this guide, we explain how to safely implement HSTS to secure your application.<br><br>Before enforcing strict policies, you can use our <a href=\"/scan\">passive vulnerability scanner</a> to verify your baseline TLS configuration.",
        "sections": [
            {
                "id": "what-is-hsts",
                "number": "01",
                "title": "What is Strict-Transport-Security?",
                "content": "HSTS is a response header sent by the server. When a browser receives this header, it remembers that this domain should never be loaded over unencrypted HTTP. If a user types `http://yourdomain.com`, the browser will automatically upgrade the request to `https://` internally before sending it over the network.",
                "listTitle": "Key benefits",
                "list": [
                    "Prevents SSL stripping attacks",
                    "Forces secure connections natively in the browser",
                    "Improves page load times by skipping HTTP-to-HTTPS redirects"
                ]
            },
            {
                "id": "hsts-directives",
                "number": "02",
                "title": "Understanding HSTS Directives",
                "content": "An HSTS header contains several important directives that dictate its behavior. The most critical is `max-age`, which specifies how long (in seconds) the browser should remember to enforce HTTPS.",
                "listTitle": "Common directives",
                "list": [
                    "max-age: Duration in seconds (e.g., 31536000 for 1 year)",
                    "includeSubDomains: Applies the rule to all subdomains",
                    "preload: Authorizes browser vendors to hardcode your domain into their global HSTS preload list"
                ]
            },
            {
                "id": "how-to-fix",
                "number": "03",
                "title": "How to Implement HSTS",
                "content": "You can add the HSTS header at your web server, load balancer, or CDN level. Below are basic examples for common web servers. <strong>Warning:</strong> Start with a short max-age (like 5 minutes) to test your configuration before committing to a 1-year duration. Be extremely cautious with includeSubDomains and preload as they can make subdomains inaccessible if they lack valid TLS certificates.",
                "listTitle": "Configuration examples",
                "list": [
                    "Nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
                    "Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
                    "Express (Node.js): Use the Helmet.js middleware"
                ]
            }
        ]
    },
    {
        "id": "fix-csp-header",
        "title": "How to Fix Missing Content-Security-Policy Header",
        "slug": "fix-missing-content-security-policy-header",
        "category": "Remediation",
        "primaryKeyword": "content-security-policy header",
        "excerpt": "Content-Security-Policy (CSP) is your primary defense against Cross-Site Scripting (XSS). Learn how to incrementally deploy a CSP to protect your users.",
        "content": "A missing <strong>Content-Security-Policy (CSP)</strong> header removes a critical layer of defense-in-depth against Cross-Site Scripting (XSS) and data injection attacks. CSP provides a rigorous allowlist of trusted content sources, preventing the browser from executing malicious inline scripts or loading untrusted assets.<br><br>To see if your current framework exposes any headers by default, consider running a quick check using our <a href=\"/scan\">passive vulnerability scanner</a>.",
        "sections": [
            {
                "id": "why-csp-matters",
                "number": "01",
                "title": "Why You Need a CSP",
                "content": "Modern web applications load resources from dozens of external domains (analytics, fonts, CDNs). If an attacker manages to inject a malicious script tag into your page, the browser will execute it by default. CSP acts as a strict set of rules, telling the browser exactly which domains are allowed to provide scripts, styles, and images.",
                "listTitle": "Attacks mitigated by CSP",
                "list": [
                    "Cross-Site Scripting (XSS)",
                    "Clickjacking (via frame-ancestors)",
                    "Data exfiltration (by restricting form-action and connect-src)"
                ]
            },
            {
                "id": "csp-report-only",
                "number": "02",
                "title": "Start with Report-Only Mode",
                "content": "Implementing a strict CSP on an existing application can break functionality if legitimate assets are blocked. Use the `Content-Security-Policy-Report-Only` header first. This instructs the browser to report violations to an endpoint you control without actually blocking the resources.",
                "listTitle": "Rollout strategy",
                "list": [
                    "1. Deploy Content-Security-Policy-Report-Only",
                    "2. Analyze violation reports to identify legitimate resources",
                    "3. Adjust your allowlist accordingly",
                    "4. Enforce the policy using the standard Content-Security-Policy header"
                ]
            },
            {
                "id": "basic-csp-example",
                "number": "03",
                "title": "Basic CSP Configuration",
                "content": "A strong baseline CSP restricts all resources to the same origin by default, and then explicitly opens up permissions as needed. Ensure you read up on <a href=\"/blog/http-security-headers-guide\">general HTTP security headers</a> for broader context.",
                "listTitle": "Example Policy",
                "list": [
                    "default-src 'self';",
                    "script-src 'self' https://trusted-cdn.com;",
                    "object-src 'none';"
                ]
            }
        ]
    },
    {
        "id": "fix-x-frame-options",
        "title": "How to Fix Missing X-Frame-Options Header",
        "slug": "fix-missing-x-frame-options-header",
        "category": "Remediation",
        "primaryKeyword": "x-frame-options header",
        "excerpt": "Clickjacking is a stealthy UI-redress attack. Find out how the X-Frame-Options header stops attackers from framing your website.",
        "content": "If your website is missing the <strong>X-Frame-Options</strong> header, it can be embedded inside an invisible iframe on a malicious third-party site. This technique, known as Clickjacking, tricks users into clicking sensitive buttons (like \"Transfer Funds\" or \"Delete Account\") while they think they are interacting with the attacker's harmless page.",
        "sections": [
            {
                "id": "understanding-clickjacking",
                "number": "01",
                "title": "Understanding Clickjacking",
                "content": "In a clickjacking attack, a malicious actor overlays your legitimate site inside a transparent iframe, placing it directly underneath a deceptive button. When the user attempts to click the visible button, the click is intercepted by your invisible site.",
                "listTitle": "Risks of framing",
                "list": [
                    "Unauthorized account modifications",
                    "Unintended social media sharing",
                    "Hidden financial transactions"
                ]
            },
            {
                "id": "xfo-directives",
                "number": "02",
                "title": "Choosing the Right Directive",
                "content": "The X-Frame-Options header supports simple directives to control framing behavior. It is widely supported across legacy and modern browsers. To verify if your site currently permits framing, you can run an assessment with our <a href=\"/scan\">passive vulnerability scanner</a>.",
                "listTitle": "Available Options",
                "list": [
                    "DENY: No one can embed your page, not even yourself.",
                    "SAMEORIGIN: Only pages on your exact domain can embed your page.",
                    "ALLOW-FROM: Deprecated and unsupported in modern browsers."
                ]
            },
            {
                "id": "csp-frame-ancestors",
                "number": "03",
                "title": "Modern Alternative: CSP frame-ancestors",
                "content": "While X-Frame-Options is highly recommended for legacy support, modern browsers prefer the `frame-ancestors` directive within the Content-Security-Policy header, which allows for more complex framing rules.",
                "listTitle": "Implementation Examples",
                "list": [
                    "Nginx: add_header X-Frame-Options \"SAMEORIGIN\" always;",
                    "Apache: Header always append X-Frame-Options SAMEORIGIN",
                    "CSP: Content-Security-Policy: frame-ancestors 'self'"
                ]
            }
        ]
    },
    {
        "id": "fix-insecure-cookies",
        "title": "How to Fix Insecure Cookie Flags: Secure, HttpOnly, SameSite",
        "slug": "fix-insecure-cookie-flags",
        "category": "Remediation",
        "primaryKeyword": "insecure cookie flags",
        "excerpt": "Session hijacking is a severe threat. Learn how to implement the Secure, HttpOnly, and SameSite flags to harden your session cookies.",
        "content": "Cookies often contain sensitive session identifiers. If these cookies lack the proper security flags, they can be stolen via Cross-Site Scripting (XSS), intercepted over unencrypted networks, or abused in Cross-Site Request Forgery (CSRF) attacks.",
        "sections": [
            {
                "id": "httponly-flag",
                "number": "01",
                "title": "The HttpOnly Flag",
                "content": "When a cookie is set with the `HttpOnly` flag, the browser prevents client-side JavaScript from accessing it via `document.cookie`. This is a critical defense-in-depth measure against XSS attacks, ensuring that even if an attacker executes code in the user's browser, they cannot steal the session token.",
                "listTitle": "Usage rule",
                "list": [
                    "Always apply to session IDs and authentication tokens",
                    "Do not apply to cookies that client-side scripts legitimately need to read (e.g., UI state)"
                ]
            },
            {
                "id": "secure-flag",
                "number": "02",
                "title": "The Secure Flag",
                "content": "The `Secure` flag ensures the cookie is only transmitted over encrypted HTTPS connections. Without this flag, a network-level attacker could intercept the cookie if the user inadvertently browses over plain HTTP. You can easily check if your cookies are exposed using our <a href=\"/scan\">passive scanner</a>.",
                "listTitle": "Network constraints",
                "list": [
                    "Requires a valid TLS/SSL certificate",
                    "Prevents accidental leakage over port 80",
                    "Modern browsers increasingly enforce this securely by default"
                ]
            },
            {
                "id": "samesite-flag",
                "number": "03",
                "title": "The SameSite Flag",
                "content": "The `SameSite` attribute prevents the browser from sending the cookie along with cross-site requests, mitigating Cross-Site Request Forgery (CSRF) attacks.",
                "listTitle": "SameSite Modes",
                "list": [
                    "Strict: Cookie is never sent on cross-site requests.",
                    "Lax: Cookie is sent on top-level navigations (e.g., following a link).",
                    "None: Cookie is sent everywhere (Requires the Secure flag)."
                ]
            }
        ]
    },
    {
        "id": "fix-cors-misconfiguration",
        "title": "How to Check CORS Misconfiguration Safely",
        "slug": "fix-cors-misconfiguration",
        "category": "Remediation",
        "primaryKeyword": "cors misconfiguration",
        "excerpt": "Cross-Origin Resource Sharing (CORS) is often misunderstood. Learn how a permissive CORS policy can leak private data and how to correctly restrict it.",
        "content": "Cross-Origin Resource Sharing (CORS) is a mechanism that allows a web application running at one origin to access restricted resources from a different origin. While necessary for modern API integrations, a poorly configured CORS policy can completely undermine the Same-Origin Policy (SOP), leading to severe data leakage.",
        "sections": [
            {
                "id": "dangers-of-wildcard",
                "number": "01",
                "title": "The Danger of the Wildcard (*)",
                "content": "Developers often use `Access-Control-Allow-Origin: *` to bypass frustrating browser errors during development. However, leaving this in production allows any malicious website on the internet to make unauthenticated API requests to your server and read the responses.",
                "listTitle": "Risks of permissive CORS",
                "list": [
                    "Data exfiltration of sensitive API responses",
                    "Bypass of intranet/internal network protections",
                    "Exposure of authenticated user details"
                ]
            },
            {
                "id": "cors-with-credentials",
                "number": "02",
                "title": "Credentials and CORS",
                "content": "The real danger arises when a permissive origin policy is combined with `Access-Control-Allow-Credentials: true`. Fortunately, modern browsers prohibit using a wildcard `*` alongside credentials. To bypass this, some backends dynamically reflect whatever origin requested the resource, which is equally dangerous.",
                "listTitle": "Best practices",
                "list": [
                    "Never dynamically reflect the `Origin` header without strict validation",
                    "Maintain an explicit, hardcoded allowlist of trusted domains",
                    "Separate public, credential-less APIs from private authenticated APIs"
                ]
            },
            {
                "id": "validating-cors",
                "number": "03",
                "title": "Validating Your CORS Policy",
                "content": "You should regularly audit your API headers. While a <a href=\"/scan\">passive vulnerability scanner</a> can identify missing security headers on your frontend, deeper CORS testing requires inspecting the specific OPTIONS preflight responses of your API endpoints.",
                "listTitle": "How to test",
                "list": [
                    "Send a curl request with `Origin: https://evil.com` and inspect the response",
                    "Verify that credentials are only permitted for highly trusted subdomains"
                ]
            }
        ]
    },
    {
        "id": "passive-vs-active-scanning",
        "title": "Passive Vulnerability Scanner vs Active Penetration Testing",
        "slug": "passive-vulnerability-scanner-vs-active-penetration-testing",
        "category": "Concepts",
        "primaryKeyword": "passive vulnerability scanner",
        "excerpt": "Understand the fundamental differences between passive scanning and active penetration testing to choose the right tool for your security workflow.",
        "content": "When building a secure application, teams must choose the right security assessment tools. The two most common approaches are passive scanning and active penetration testing. Understanding the distinction is vital for maintaining uptime while uncovering risks.",
        "sections": [
            {
                "id": "passive-scanning",
                "number": "01",
                "title": "What is a Passive Vulnerability Scanner?",
                "content": "A <strong>passive vulnerability scanner</strong> interacts with a target exactly like a standard web browser or search engine crawler. It evaluates the publicly accessible surface of the website without attempting to bypass authentication, inject malicious payloads, or modify state.",
                "listTitle": "Key characteristics of passive scanning",
                "list": [
                    "Non-destructive and completely safe for production environments",
                    "Analyzes HTTP headers, TLS configurations, and public DNS records",
                    "Identifies misconfigurations rather than deep logic flaws",
                    "Is generally less intrusive than active testing, as it evaluates public configuration data"
                ]
            },
            {
                "id": "active-testing",
                "number": "02",
                "title": "What is Active Penetration Testing?",
                "content": "Active testing involves purposefully sending malicious payloads (like SQL injection strings or XSS vectors) to a web application to see if it behaves insecurely. This type of testing can alter database records, crash servers, or trigger massive error logs.",
                "listTitle": "Key characteristics of active testing",
                "list": [
                    "Simulates real-world cyberattacks",
                    "Detects complex vulnerabilities like IDOR and Command Injection",
                    "Requires written authorization and defined rules of engagement",
                    "Should ideally be performed in staging or highly isolated environments"
                ]
            },
            {
                "id": "how-they-work-together",
                "number": "03",
                "title": "How They Complement Each Other",
                "content": "Passive scanning and active testing are not mutually exclusive; they form a layered defense strategy. You can use our <a href=\"/scan\">passive scanner</a> daily to catch immediate misconfigurations, while scheduling deep active penetration tests annually or before major architectural releases.",
                "listTitle": "A balanced workflow",
                "list": [
                    "Use passive scanners in CI/CD pipelines for fast, risk-free checks",
                    "Use active testing to validate the integrity of business logic",
                    "Combine both to achieve comprehensive security visibility"
                ]
            }
        ]
    }

];
