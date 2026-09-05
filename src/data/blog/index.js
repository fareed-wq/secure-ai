export const articles = [
    {
        "id": "1",
        "title": "Website Security Checklist: 20 Things Every Website Owner Should Check",
        "slug": "website-security-checklist",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "Website Security",
        "primaryKeyword": "website security checklist",
        "secondaryKeywords": [
            "website security best practices",
            "website security audit checklist",
            "website security checklist for businesses"
        ],
        "seoTitle": "Website Security Checklist | URLScanOnline",
        "metaDescription": "A practical 20-point website security checklist covering common misconfigurations, security headers, HTTPS, and access control for modern websites.",
        "excerpt": "A practical 20-point checklist for identifying common website security weaknesses, configuration issues, and exposure risks.",
        "content": "Securing a website in today's threat landscape requires a proactive, layered approach. This practical <strong>website security checklist</strong> covers essential steps every website owner, developer, and IT professional should take to identify potential weaknesses and harden their infrastructure.",
        "sections": [
            {
                "id": "https-tls",
                "title": "1. Enforce Strong HTTPS/TLS",
                "content": "Ensure your website uses TLS encryption for all connections. Never transmit data over plain HTTP. Automatically redirect HTTP traffic to HTTPS. Disable obsolete protocols like TLS 1.0 and TLS 1.1, and check your server prefers strong, modern cipher suites."
            },
            {
                "id": "security-headers",
                "title": "2. Deploy HTTP Security Headers",
                "content": "Configure your web server to return strong security headers. This includes Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), X-Content-Type-Options, X-Frame-Options, and Referrer-Policy. These headers instruct the browser to enforce critical security behaviors."
            },
            {
                "id": "access-control",
                "title": "3. Harden Access Controls and Authentication",
                "content": "Enforce strong password policies and mandate Multi-Factor Authentication (MFA) for privileged and user accounts. Apply the principle of least privilege. Protect session cookies using the <code>Secure</code>, <code>HttpOnly</code>, and <code>SameSite</code> flags."
            },
            {
                "id": "software-updates",
                "title": "4. Maintain Software and Dependencies",
                "content": "Keep your CMS, plugins, web server software, and all third-party libraries strictly up to date. Subscribe to security advisories for the software stack you use, and establish a process for applying critical patches immediately."
            },
            {
                "id": "exposure-reduction",
                "title": "5. Reduce Information Exposure",
                "content": "Ensure development files, backup archives, <code>.git</code> repositories, and <code>.env</code> configuration files are never accessible via the public web root. Configure custom error pages to prevent verbose stack traces from leaking backend infrastructure details to attackers."
            },
            {
                "id": "cta",
                "title": "Start Your Security Audit",
                "content": "URLScanOnline can help automate the first step of this checklist. Our passive vulnerability scanner can instantly identify missing security headers, weak TLS configurations, and exposed information files on your public-facing assets."
            }
        ],
        "faqs": [
            {
                "question": "Where should I start with website security?",
                "answer": "Start with the basics: check strong HTTPS is enforced everywhere, apply all available software updates, and secure administrative accounts with MFA."
            },
            {
                "question": "How often should I review my website security?",
                "answer": "Security is a continuous process. You should review your posture monthly, apply patches as soon as they are released, and run automated vulnerability scans regularly."
            }
        ]
    },
    {
        "id": "2",
        "title": "How to Check if a Website Is Secure: A Practical Guide",
        "slug": "how-to-check-if-a-website-is-secure",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "Website Security",
        "primaryKeyword": "how to check if a website is secure",
        "secondaryKeywords": [
            "check website security",
            "website security check",
            "how to know if a website is secure"
        ],
        "seoTitle": "How to Check if a Website is Secure | URLScanOnline",
        "metaDescription": "Learn how to check if a website is secure using browser indicators, passive analysis, and automated vulnerability scanning techniques.",
        "excerpt": "Learn the practical steps to evaluate a website's security posture, from basic visual checks to advanced vulnerability scanning.",
        "content": "Whether you are a consumer evaluating an online store or a developer reviewing a new application, knowing <strong>how to check if a website is secure</strong> is a vital skill. This guide outlines how to evaluate a website's security posture using browser indicators and passive analysis.",
        "sections": [
            {
                "id": "browser-indicators",
                "title": "Check Browser Security Indicators",
                "content": "The most basic check is the connection security. Look at your browser's address bar: the URL should begin with <code>https://</code>, accompanied by a padlock icon. Clicking the padlock reveals the certificate details. Ensure the certificate is valid, issued by a trusted Certificate Authority (CA), and matches the domain name you intend to visit."
            },
            {
                "id": "verify-domain",
                "title": "Verify the Domain Name Carefully",
                "content": "Phishing sites frequently use deceptive domain names (e.g., <code>examp1e.com</code> instead of <code>example.com</code>) and secure them with free SSL certificates. The presence of HTTPS only means your connection to that server is encrypted; it does not guarantee the server itself is run by a legitimate or trustworthy organization."
            },
            {
                "id": "evaluate-trust",
                "title": "Evaluate Trust and Privacy Signals",
                "content": "Look for a clear Privacy Policy, Terms of Service, and legitimate contact information. A site asking for sensitive information without these trust signals should be treated with suspicion. Be wary of aggressive pop-ups or requests for excessive permissions (like location or camera access) immediately upon loading."
            },
            {
                "id": "passive-analysis",
                "title": "Perform Passive Technical Analysis",
                "content": "For a deeper evaluation, you can analyze the site's HTTP response headers and configuration. Tools can observe whether the site enforces policies like CSP or HSTS. These are observable configuration signals, though not absolute proof that the application is fully secure."
            },
            {
                "id": "cta",
                "title": "Run a Technical Security Check",
                "content": "If you want to evaluate the technical security configuration of a website, URLScanOnline can help. Our passive scanner safely analyzes a site's headers, TLS configuration, and observable security posture without sending intrusive payloads."
            }
        ],
        "faqs": [
            {
                "question": "Does a padlock mean a website is 100% safe?",
                "answer": "No. The padlock only means the connection between your browser and the server is encrypted. A malicious phishing site can easily obtain a padlock."
            },
            {
                "question": "What is passive security analysis?",
                "answer": "Passive analysis involves checking a website's security configuration (like HTTP headers and certificates) by making normal requests, without attempting to hack or exploit it."
            }
        ]
    },
    {
        "id": "3",
        "title": "How to Detect OWASP Top 10 Vulnerabilities Using Passive Scanning",
        "slug": "owasp-top-10-explained",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "OWASP Security",
        "primaryKeyword": "OWASP Top 10 explained",
        "secondaryKeywords": [
            "OWASP Top 10",
            "web application security risks",
            "OWASP vulnerabilities"
        ],
        "seoTitle": "OWASP Top 10 Explained | URLScanOnline",
        "metaDescription": "An overview of the OWASP Top 10 web application security risks, explaining broken access control, cryptographic failures, injection flaws, and more.",
        "excerpt": "A detailed breakdown of the current OWASP Top 10 web application security risks and how to protect your applications against them.",
        "content": "The OWASP Top 10 is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications. This educational overview explains the core categories of the <strong>OWASP Top 10 explained</strong>.",
        "sections": [
            {
                "id": "observation-vs-testing",
                "title": "Observation vs. Deep Testing",
                "content": "This overview describes the OWASP Top 10:2025 edition. It is important to distinguish between configuration observations and deep application testing. Passive scanning tools can observe missing headers, outdated libraries, and weak TLS configurations. However, discovering complex flaws like Broken Access Control or business logic errors requires deeper, often manual, penetration testing. No single automated tool guarantees the discovery of all OWASP Top 10 vulnerabilities."
            },
            {
                "id": "a01-broken-access-control",
                "title": "A01:2025 \u2014 Broken Access Control",
                "content": "Broken Access Control occurs when users can act outside of their intended permissions, leading to unauthorized information disclosure or data modification. In OWASP 2025, Server-Side Request Forgery (SSRF) is now incorporated into this category."
            },
            {
                "id": "a02-security-misconfiguration",
                "title": "A02:2025 \u2014 Security Misconfiguration",
                "content": "This covers insecure default settings, incomplete configurations, misconfigured HTTP headers, and verbose error messages. It requires a repeatable hardening process to secure the application stack."
            },
            {
                "id": "a03-software-supply-chain",
                "title": "A03:2025 \u2014 Software Supply Chain Failures",
                "content": "A new focus on the risks of relying on third-party libraries, frameworks, and tools that may contain vulnerabilities or malicious code inserted during the development lifecycle."
            },
            {
                "id": "a04-cryptographic-failures",
                "title": "A04:2025 \u2014 Cryptographic Failures",
                "content": "Failures related to cryptography, leading to the exposure of sensitive data like passwords or health records, such as transmitting data in cleartext or using weak cryptographic algorithms."
            },
            {
                "id": "a05-injection",
                "title": "A05:2025 \u2014 Injection",
                "content": "Injection flaws, such as SQL injection or Command Injection, occur when untrusted data is sent to an interpreter as part of a command or query. Cross-Site Scripting (XSS) is considered a form of injection."
            },
            {
                "id": "a06-insecure-design",
                "title": "A06:2025 \u2014 Insecure Design",
                "content": "Highlights risks related to design and architectural flaws, emphasizing the need for threat modeling, secure design patterns, and reference architectures."
            },
            {
                "id": "a07-authentication-failures",
                "title": "A07:2025 \u2014 Authentication Failures",
                "content": "Failures allowing attackers to compromise passwords, keys, or session tokens, permitting them to temporarily or permanently assume the identities of other users."
            },
            {
                "id": "a08-integrity-failures",
                "title": "A08:2025 \u2014 Software or Data Integrity Failures",
                "content": "Focuses on making assumptions about software updates, critical data, and CI/CD pipelines without verifying integrity, such as relying upon plugins from untrusted sources."
            },
            {
                "id": "a09-logging-failures",
                "title": "A09:2025 \u2014 Security Logging and Alerting Failures",
                "content": "Without proper logging and alerting, breaches cannot be detected. Failures include not logging auditable events or storing logs locally where an attacker can delete them."
            },
            {
                "id": "a10-exceptional-conditions",
                "title": "A10:2025 \u2014 Mishandling of Exceptional Conditions",
                "content": "A new category addressing how applications handle errors and exceptional states, which can leak sensitive information or lead to unexpected behavior if not managed securely."
            },
            {
                "id": "cta",
                "title": "Start Assessing Your Posture",
                "content": "URLScanOnline provides passive and low-impact external security checks that can help identify externally observable configuration issues, such as missing security headers and exposed information, which often align with the Security Misconfiguration category."
            }
        ],
        "faqs": [
            {
                "question": "Can automated tools detect all OWASP Top 10 vulnerabilities?",
                "answer": "No. While automated scanners excel at finding misconfigurations and known vulnerable components, they struggle with complex business logic flaws and authorization issues, which require manual penetration testing."
            },
            {
                "question": "How often is the OWASP Top 10 updated?",
                "answer": "The OWASP Top 10 is typically updated every few years based on comprehensive data collected from security practitioners and organizations worldwide."
            }
        ]
    },
    {
        "id": "4",
        "title": "HTTP Security Headers: Complete Guide for Website Owners",
        "slug": "http-security-headers-guide",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "Security Headers",
        "primaryKeyword": "HTTP security headers",
        "secondaryKeywords": [
            "website security headers",
            "security headers",
            "HTTP security headers guide"
        ],
        "seoTitle": "HTTP Security Headers Guide | URLScanOnline",
        "metaDescription": "A practical guide to HTTP security headers, detailing how to configure CSP, HSTS, X-Frame-Options, and Referrer-Policy to protect your web application.",
        "excerpt": "A comprehensive guide to HTTP security headers, their purpose, and how to configure them to protect your web application.",
        "content": "HTTP security headers are a fundamental component of web application security. By configuring your web server to return specific headers, you instruct the visitor's browser to enforce various security mechanisms. This <strong>practical guide to HTTP security headers</strong> outlines the most important headers you should implement.",
        "sections": [
            {
                "id": "defense-in-depth",
                "title": "A Layer of Defense-in-Depth",
                "content": "It is critical to understand that security headers do not make an application secure by themselves. They are a defense-in-depth measure. They provide a safety net by instructing the browser to behave securely, mitigating the impact of vulnerabilities like Cross-Site Scripting (XSS) or Clickjacking. However, they do not replace secure coding practices, input validation, or proper server-side authentication."
            },
            {
                "id": "csp",
                "title": "Content-Security-Policy (CSP)",
                "content": "The Content-Security-Policy header restricts the sources from which the browser is allowed to load resources, such as scripts, stylesheets, and images. It is one of the most effective tools for mitigating XSS attacks. By explicitly defining an allowlist of trusted domains, you prevent the execution of malicious injected scripts."
            },
            {
                "id": "hsts",
                "title": "Strict-Transport-Security (HSTS)",
                "content": "The Strict-Transport-Security header forces the browser to communicate with the server exclusively over HTTPS. This prevents protocol downgrade attacks and ensures that even if a user types 'http://' into their address bar, the browser will automatically upgrade the connection to secure HTTPS before sending any data."
            },
            {
                "id": "xfo",
                "title": "X-Frame-Options",
                "content": "The X-Frame-Options header protects against Clickjacking (UI redress attacks) by controlling whether a browser is allowed to render a page in a <code><frame></code>, <code><iframe></code>, or <code><object></code>. Common values are <code>DENY</code> (no framing allowed) or <code>SAMEORIGIN</code> (framing only allowed by pages on the same site). Note that the modern <code>frame-ancestors</code> directive in CSP largely supersedes this header, but X-Frame-Options remains relevant for older browser compatibility."
            },
            {
                "id": "xcto",
                "title": "X-Content-Type-Options",
                "content": "The X-Content-Type-Options header, when set to <code>nosniff</code>, tells compatible browsers not to MIME-sniff certain resources. This is particularly relevant to blocking script or style execution when their declared MIME types are incorrect."
            },
            {
                "id": "referrer-policy",
                "title": "Referrer-Policy",
                "content": "The Referrer-Policy header controls how much referrer information (the URL of the previous page) the browser includes when navigating to a new page. Setting this to <code>strict-origin-when-cross-origin</code> (the modern default in many browsers) or <code>no-referrer</code> ensures that sensitive data in URLs is not leaked to third-party sites."
            },
            {
                "id": "permissions-policy",
                "title": "Permissions-Policy",
                "content": "Formerly known as Feature-Policy, the Permissions-Policy header allows site administrators to explicitly enable or disable access to specific browser features and APIs, such as the camera, microphone, geolocation, and WebUSB. Restricting access to unused features reduces the potential attack surface if the site is compromised."
            },
            {
                "id": "cta",
                "title": "Verify Your Headers",
                "content": "URLScanOnline can help identify externally observable configuration issues such as missing security headers, TLS configuration concerns, and other website security signals. Running a scan can provide a quick overview of which headers your site currently implements."
            }
        ],
        "faqs": [
            {
                "question": "What security headers should a website have?",
                "answer": "A strong baseline configuration should include Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy."
            },
            {
                "question": "Will adding security headers break my website?",
                "answer": "Headers like X-Content-Type-Options or basic HSTS usually cause no issues, but a strict Content-Security-Policy can block legitimate scripts if not configured carefully. It is recommended to test CSP using Report-Only mode first."
            },
            {
                "question": "Are security headers a replacement for penetration testing?",
                "answer": "No. Security headers are a valuable layer of defense, but they do not fix underlying application flaws. Thorough security testing remains essential."
            }
        ]
    },
    {
        "id": "5",
        "title": "Content Security Policy (CSP): What It Is and How to Configure It",
        "slug": "content-security-policy-guide",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "Security Headers",
        "primaryKeyword": "Content Security Policy",
        "secondaryKeywords": [
            "CSP header",
            "Content Security Policy header",
            "CSP security"
        ],
        "seoTitle": "What is Content Security Policy (CSP)? | URLScanOnline",
        "metaDescription": "Discover what a Content Security Policy (CSP) is and how it helps defend against Cross-Site Scripting (XSS) and data injection attacks.",
        "excerpt": "Learn how to build and deploy a robust Content Security Policy to protect your users from Cross-Site Scripting (XSS) attacks.",
        "content": "A <strong>Content Security Policy (CSP)</strong> is a powerful HTTP header that adds a robust layer of defense-in-depth against some of the most pervasive web vulnerabilities, particularly Cross-Site Scripting (XSS). This informational guide explains what CSP is, how it works, and its core directives.",
        "sections": [
            {
                "id": "what-is-csp",
                "title": "What Problem Does CSP Address?",
                "content": "Modern web browsers generally trust the code delivered by a web server. If an attacker successfully injects malicious JavaScript into a page (an XSS attack), the browser will execute it, assuming it is legitimate part of the site. A Content Security Policy addresses this by allowing site administrators to declare an explicit allowlist of trusted sources. The browser uses this policy to reject and block the execution of any scripts, styles, or resources that do not originate from an approved source."
            },
            {
                "id": "core-directives",
                "title": "Core CSP Directives",
                "content": "A CSP is built using various directives that control different types of resources. The most fundamental is <code>default-src</code>, which acts as a fallback for other resource types. Other critical directives include:<br><br><br><br>- <code>script-src</code>: Restricts where JavaScript can be loaded from.<br>- <code>style-src</code>: Controls the sources of CSS stylesheets.<br>- <code>img-src</code>: Limits where images can be loaded from.<br>- <code>connect-src</code>: Restricts the URLs to which the browser can send data (e.g., via fetch, XHR, or WebSockets).<br>- <code>object-src</code>: Controls plugins like Flash or Java (usually set to 'none' today).<br>- <code>frame-ancestors</code>: Determines which external sites are permitted to embed your site in an iframe, effectively replacing the older X-Frame-Options header."
            },
            {
                "id": "unsafe-inline-eval",
                "title": "The Risks of unsafe-inline and unsafe-eval",
                "content": "By default, a strict CSP blocks inline scripts (<code><script>...</script></code>) and inline styles, as these are common vectors for XSS. To allow them, developers sometimes use the <code>'unsafe-inline'</code> keyword in their <code>script-src</code> directive. However, this largely defeats the XSS protection of CSP. Similarly, <code>'unsafe-eval'</code> allows the use of functions like <code>eval()</code>, which can be dangerous. A robust CSP aims to eliminate the need for these keywords entirely."
            },
            {
                "id": "nonces-hashes",
                "title": "Nonces and Hashes",
                "content": "When inline scripts are unavoidable, modern CSP implementations use nonces (cryptographically strong, single-use random values) or hashes (like SHA-256) instead of <code>'unsafe-inline'</code>. A script will only execute if its tag contains a <code>nonce</code> attribute matching the value in the CSP header, or if the script's contents match the hash specified in the policy. This allows developers to securely authorize specific inline scripts while blocking injected ones."
            },
            {
                "id": "report-only",
                "title": "Report-Only Mode and Gradual Rollout",
                "content": "Implementing a strict CSP on an existing, complex website can inadvertently break legitimate functionality by blocking necessary resources. To mitigate this, developers use the <code>Content-Security-Policy-Report-Only</code> header. In this mode, the browser does not block anything; it only reports policy violations to a designated endpoint (using the <code>report-uri</code> or <code>report-to</code> directive). This allows administrators to observe what would be blocked and refine the policy before enforcing it."
            },
            {
                "id": "cta",
                "title": "Check Your Current CSP",
                "content": "URLScanOnline can help identify externally observable configuration issues such as missing security headers, including CSP. A quick scan can reveal if your site currently broadcasts a Content Security Policy and whether it relies on insecure directives like unsafe-inline."
            }
        ],
        "faqs": [
            {
                "question": "What does CSP block?",
                "answer": "CSP blocks the execution or loading of any resources (scripts, styles, images, fonts, connections) that violate the allowlist defined in the policy. It is particularly effective at blocking unauthorized inline scripts and unauthorized external domains."
            },
            {
                "question": "Does CSP replace input validation?",
                "answer": "No. CSP is a defense-in-depth mechanism. It acts as a safety net in case an injection vulnerability exists, but it does not replace the need for robust input validation, output encoding, and secure coding practices."
            },
            {
                "question": "How do I implement a CSP?",
                "answer": "Implementing CSP requires returning the HTTP header from your web server. For a detailed troubleshooting and implementation guide, see our article on how to fix a missing Content Security Policy header."
            }
        ]
    },
    {
        "id": "6",
        "title": "HSTS Explained: How HTTP Strict Transport Security Protects Websites",
        "slug": "hsts-explained",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "SSL / TLS Security",
        "primaryKeyword": "HSTS header",
        "secondaryKeywords": [
            "HTTP Strict Transport Security",
            "HSTS security",
            "Strict-Transport-Security"
        ],
        "seoTitle": "HSTS Header Explained: How It Works | URLScanOnline",
        "metaDescription": "Learn how the HTTP Strict Transport Security (HSTS) header works and how it protects websites against protocol downgrade attacks.",
        "excerpt": "Understand HTTP Strict Transport Security (HSTS), how it prevents downgrade attacks, and best practices for deployment.",
        "content": "The HTTP Strict Transport Security (HSTS) header is a critical web security policy mechanism. This guide explains how the <strong>HSTS header</strong> works, why it is essential for modern websites, and the implications of its various directives.",
        "sections": [
            {
                "id": "how-hsts-works",
                "title": "How HSTS Works",
                "content": "When a web server returns the <code>Strict-Transport-Security</code> HTTP header, it instructs the browser that it must only communicate with the site using a secure HTTPS connection. Once the browser receives this policy, it will automatically upgrade any future HTTP requests to HTTPS before they ever leave the device. This prevents attackers from intercepting initial plaintext HTTP requests and executing SSL stripping or protocol downgrade attacks."
            },
            {
                "id": "the-header",
                "title": "The Strict-Transport-Security Header and max-age",
                "content": "The core of the HSTS policy is the <code>max-age</code> directive, specified in seconds. For example, <code>max-age=31536000</code> tells the browser to enforce the HTTPS-only policy for exactly one year. Every time the user visits the site, the browser resets this timer. If the max-age expires without the user revisiting the site, the policy is removed. A long max-age is recommended to check robust protection."
            },
            {
                "id": "include-subdomains",
                "title": "The includeSubDomains Directive",
                "content": "By default, HSTS only applies to the exact hostname that issued the header. Adding the <code>includeSubDomains</code> directive extends the policy to subdomains. Without it, the parent policy does not cover them, and they may require their own HSTS policies to reduce exposure."
            },
            {
                "id": "preloading",
                "title": "HSTS Preloading and First-Visit Limitation",
                "content": "HSTS has a 'Trust on First Use' (TOFU) limitation: a user must visit the site over a secure connection at least once to receive the header. An attacker could intercept the very first visit. HSTS Preloading solves this. By submitting your domain to the official HSTS preload list (maintained by Google and hardcoded into major browsers), your site is guaranteed to only ever be accessed via HTTPS, even on the very first visit."
            },
            {
                "id": "risks",
                "title": "Risks of Enabling HSTS Incorrectly",
                "content": "HSTS is a powerful commitment. If you enable HSTS with a long max-age and subsequently lose the ability to serve HTTPS (e.g., an expired certificate or a misconfigured server), your website will become completely inaccessible to returning visitors. The browser will block the connection, and users cannot click through the warning. Similarly, adding <code>includeSubDomains</code> or <code>preload</code> without ensuring every single subdomain supports HTTPS can cause massive outages. Always roll out HSTS gradually using short max-age values before committing to long-term enforcement."
            },
            {
                "id": "remediation-link",
                "title": "Implementation",
                "content": "Implementing HSTS requires modifying your web server configuration (like Nginx, Apache, or IIS) to return the appropriate HTTP header. For detailed, step-by-step instructions on implementing this safely, refer to our dedicated guide on <a href=\"/blog/fix-missing-strict-transport-security-header\">how to fix a missing HSTS header</a>."
            },
            {
                "id": "cta",
                "title": "Verify Your Header Configuration",
                "content": "URLScanOnline can help identify externally observable configuration issues such as missing security headers, TLS configuration concerns, and other website security signals. A quick scan can verify if your HSTS header is correctly formatted and active."
            }
        ],
        "faqs": [
            {
                "question": "Is HSTS required?",
                "answer": "While not strictly required for a website to function, HSTS is strongly recommended for any site handling sensitive data, authentication, or e-commerce, as it provides a critical layer of defense against man-in-the-middle attacks."
            },
            {
                "question": "What happens if my SSL certificate expires while HSTS is active?",
                "answer": "If your certificate expires, browsers enforcing HSTS will block access entirely. Users will see a strict security error and will not be given the option to bypass the warning and proceed to the site."
            },
            {
                "question": "How do I remove my site from the HSTS preload list?",
                "answer": "You can request removal through the official HSTS preload website, but the process can take months to propagate to all users as browser updates are rolled out. This is why careful planning is essential before preloading."
            }
        ]
    },
    {
        "id": "7",
        "title": "TLS 1.2 vs TLS 1.3: Security, Performance and Compatibility",
        "slug": "tls-1-2-vs-tls-1-3",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "SSL / TLS Security",
        "primaryKeyword": "TLS 1.2 vs TLS 1.3",
        "secondaryKeywords": [
            "TLS 1.3 security",
            "TLS versions",
            "TLS 1.2 security"
        ],
        "seoTitle": "TLS 1.2 vs TLS 1.3: Security and Performance | URLScanOnline",
        "metaDescription": "Compare TLS 1.2 and TLS 1.3 to understand the security enhancements, faster handshakes, and overall performance benefits of modern encryption protocols.",
        "excerpt": "A technical comparison of TLS 1.2 and TLS 1.3, highlighting the security enhancements and performance benefits of modern encryption.",
        "content": "Transport Layer Security (TLS) is the cornerstone protocol responsible for providing secure, encrypted communications over the internet. Understanding the differences between <strong>TLS 1.2 vs TLS 1.3</strong> is critical for security professionals, developers, and website owners who want to optimize both data protection and performance.",
        "sections": [
            {
                "id": "handshake-changes",
                "title": "Handshake and Performance Improvements",
                "content": "One of the most significant upgrades in TLS 1.3 is the streamlined handshake process. TLS 1.2 typically requires two round-trips (2-RTT). TLS 1.3 optimizes this to just one round-trip (1-RTT). For returning visitors with resumed connections, TLS 1.3 supports a 0-RTT mode, improving page load times. However, this introduces a risk of replay attacks, and applications must be designed to avoid replay-sensitive operations with early data."
            },
            {
                "id": "legacy-algorithms",
                "title": "Removal of Legacy Algorithms",
                "content": "TLS 1.3 brings a massive overhaul to the protocol's security by eliminating obsolete and insecure cryptographic features. While TLS 1.2 supported older, vulnerable algorithms for backward compatibility, TLS 1.3 completely removes support for RC4, DES, 3DES, SHA-1, MD5, and various weak CBC-mode ciphers. This aggressive pruning reduces the attack surface and mitigates risks associated with downgrade attacks."
            },
            {
                "id": "cipher-negotiation",
                "title": "Simplified Cipher Negotiation",
                "content": "In TLS 1.2, cipher suites were complex combinations of key exchange, authentication, encryption, and hashing algorithms, leading to confusing configurations and potential misconfigurations. TLS 1.3 strictly limits cipher suites to a handful of highly secure Authenticated Encryption with Associated Data (AEAD) algorithms, separating the key exchange mechanism from the cipher suite itself."
            },
            {
                "id": "forward-secrecy",
                "title": "Forward Secrecy Improvements",
                "content": "TLS 1.2 allowed for static RSA key exchanges, meaning if an attacker recorded encrypted traffic and later compromised the server's private key, they could decrypt all past communications. TLS 1.3 removes static RSA key exchange. Normal certificate-based TLS 1.3 handshakes use ephemeral key exchange, providing forward secrecy."
            },
            {
                "id": "compatibility",
                "title": "Compatibility and Migration Considerations",
                "content": "Despite its age, TLS 1.2 remains widely supported and is still considered secure when configured correctly (i.e., using strong cipher suites and disabling weak algorithms). For modern public-facing websites, the best practice is to disable obsolete protocols (TLS 1.0 and 1.1) and enable both TLS 1.2 (for broad compatibility) and TLS 1.3 (for optimal security and performance for modern clients). Keep in mind that enabling TLS 1.3 may require updates to your web server (e.g., Nginx, Apache), load balancer, or CDN configuration."
            },
            {
                "id": "cta",
                "title": "Verify Your Configuration",
                "content": "URLScanOnline can help identify externally observable configuration issues such as weak TLS configurations, missing security headers, and other website security signals. Running a quick scan can confirm if your server is correctly negotiating modern TLS protocols."
            }
        ],
        "faqs": [
            {
                "question": "Is TLS 1.2 still secure?",
                "answer": "Yes, TLS 1.2 is still considered secure provided that weak cipher suites and obsolete algorithms (like RC4 and 3DES) are disabled, and strong AEAD ciphers are prioritized."
            },
            {
                "question": "Does enabling TLS 1.3 break older browsers?",
                "answer": "Enabling TLS 1.3 alongside TLS 1.2 ensures backward compatibility. Older browsers will negotiate down to TLS 1.2, while modern browsers will benefit from TLS 1.3."
            },
            {
                "question": "How does TLS 1.3 improve website speed?",
                "answer": "TLS 1.3 reduces the handshake process from two round-trips to one round-trip (and potentially zero round-trips for returning connections), which significantly reduces connection latency."
            }
        ]
    },
    {
        "id": "8",
        "title": "API Security Checklist: 15 Things Developers Should Check",
        "slug": "api-security-checklist",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "API Security",
        "primaryKeyword": "API security checklist",
        "secondaryKeywords": [
            "API security best practices",
            "secure API checklist",
            "API security testing checklist"
        ],
        "seoTitle": "API Security Checklist | URLScanOnline",
        "metaDescription": "A comprehensive 15-point API security checklist covering authentication, authorization, rate limiting, and data exposure prevention.",
        "excerpt": "A comprehensive API security checklist to help developers secure endpoints, manage authentication, and prevent data breaches.",
        "content": "APIs are the primary way modern applications communicate, making them a high-value target for threat actors. This practical <strong>API security checklist</strong> provides essential guidelines to secure your endpoints, protect sensitive data, and maintain robust access controls.",
        "sections": [
            {
                "id": "authentication-authorization",
                "title": "1. Authentication and Authorization",
                "content": "Explicitly classify public vs protected endpoints. Require strong authentication on endpoints that need identity, and enforce authorization independently. While OAuth 2.0 is a robust authorization framework, OpenID Connect can provide authentication on top of it. JSON Web Tokens (JWT) provide a token format, not an authentication protocol itself. Authorization must validate whether the caller is permitted to access the requested object or action."
            },
            {
                "id": "rate-limiting",
                "title": "2. Rate Limiting and Resource Allocation",
                "content": "Implement risk-appropriate rate limiting to prevent brute-force attacks, credential stuffing, and Denial of Service (DoS). Configure API gateways to limit the number of requests per user, IP address, and API token within specific time windows. Set maximum payload sizes to prevent memory exhaustion attacks."
            },
            {
                "id": "input-validation",
                "title": "3. Input Validation and Data Exposure",
                "content": "Never trust client input. Validate, sanitize, and strictly type-check all incoming data against a defined schema before processing it. On the response side, avoid returning generic data objects. Create specific Data Transfer Objects (DTOs) that only expose the exact fields the client needs, preventing Excessive Data Exposure."
            },
            {
                "id": "security-headers",
                "title": "4. API Headers and CORS",
                "content": "Configure appropriate HTTP security headers on API responses. Ensure Cross-Origin Resource Sharing (CORS) is strictly configured. Modern browsers reject credentialed requests if the allowed origin is a wildcard <code>*</code>. A dangerous pattern is reflecting an untrusted Origin while allowing credentials. Restrict origins to explicitly trusted domains."
            },
            {
                "id": "logging-monitoring",
                "title": "5. Logging, Monitoring, and Secrets",
                "content": "Log all authentication attempts, access denials, and high-value transactions. Do not log sensitive data (like passwords, PII, or API keys). Ensure secrets and keys are never hardcoded in the application source code; use a dedicated secret manager."
            },
            {
                "id": "cta",
                "title": "Verify Your API Configuration",
                "content": "URLScanOnline can help identify externally observable configuration issues on your API infrastructure, such as overly permissive CORS policies, missing TLS configurations, and exposed documentation endpoints."
            }
        ],
        "faqs": [
            {
                "question": "What is the most common API vulnerability?",
                "answer": "Broken Object Level Authorization (BOLA) is a major API authorization risk and has historically ranked highly in OWASP API Security guidance."
            },
            {
                "question": "Can I use basic authentication for my API?",
                "answer": "Basic authentication is generally discouraged for modern APIs because it requires sending credentials with every request. Token-based authentication (like OAuth 2.0) is strongly preferred."
            }
        ]
    },
    {
        "id": "9",
        "title": "Common API Security Vulnerabilities and How to Prevent Them",
        "slug": "common-api-security-vulnerabilities",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "API Security",
        "primaryKeyword": "API security vulnerabilities",
        "secondaryKeywords": [
            "common API vulnerabilities",
            "OWASP API security",
            "API security risks"
        ],
        "seoTitle": "Common API Security Vulnerabilities | URLScanOnline",
        "metaDescription": "Explore the most frequent API security vulnerabilities, including Broken Object Level Authorization (BOLA), and discover how to prevent them.",
        "excerpt": "Explore the most common API security vulnerabilities, including Broken Object Level Authorization, and learn how to prevent them.",
        "content": "APIs are the backbone of modern web and mobile applications, making them a high-value target for attackers. This educational overview explores the most <strong>common API security vulnerabilities</strong> and how development teams can prevent them.",
        "sections": [
            {
                "id": "bola",
                "title": "Broken Object Level Authorization (BOLA)",
                "content": "BOLA (formerly known as IDOR) occurs when an API endpoint does not validate whether the currently authenticated user actually has permission to access the specific object they are requesting. For example, if a user changes the ID in an API request from <code>/api/receipts/100</code> to <code>/api/receipts/101</code>, and the API returns the data without verifying ownership, the API is vulnerable to BOLA. Preventing BOLA requires strict authorization checks on every single object access."
            },
            {
                "id": "authentication-failures",
                "title": "Broken User Authentication",
                "content": "APIs often implement complex authentication mechanisms that can be flawed. Broken authentication allows attackers to compromise passwords, keys, or session tokens. Common issues include lacking brute-force protections on login endpoints, exposing sensitive tokens in URLs, or failing to validate the signature and expiration of JSON Web Tokens (JWTs)."
            },
            {
                "id": "excessive-data-exposure",
                "title": "Excessive Data Exposure",
                "content": "Developers sometimes design APIs to return generic, massive data objects and rely on the client-side application (like a mobile app or SPA) to filter what the user sees. Attackers intercepting the API response can see all the hidden data, which may include sensitive PII or administrative flags. APIs should only return the exact data required by the client."
            },
            {
                "id": "rate-limiting",
                "title": "Lack of Resources and Rate Limiting",
                "content": "APIs that do not restrict the size or number of requests from a single client are vulnerable to Denial of Service (DoS) and brute-force attacks. Attackers can flood the API with requests, exhausting server resources (CPU, memory, database connections). Implementing strict rate limiting, payload size limits, and pagination is essential."
            },
            {
                "id": "security-misconfiguration",
                "title": "Security Misconfiguration and CORS",
                "content": "Security misconfiguration is a broad category that includes insecure default settings, incomplete configurations, open cloud storage, misconfigured HTTP headers, and excessively permissive Cross-Origin Resource Sharing (CORS) policies. A misconfigured CORS policy (e.g., <code>Access-Control-Allow-Origin: *</code> with credentials) can allow malicious websites to make authenticated requests to the API on behalf of the user."
            },
            {
                "id": "observation-limits",
                "title": "Observation vs. Deep Testing",
                "content": "It is important to understand that passive observation cannot prove authorization flaws like BOLA. While a passive scanner can identify misconfigured CORS headers or exposed API documentation, detecting logic flaws, missing authorization checks, and excessive data exposure requires deep, authenticated testing and careful manual analysis."
            },
            {
                "id": "cta",
                "title": "Check Your API Infrastructure",
                "content": "URLScanOnline can help identify externally observable configuration issues such as permissive CORS headers, missing security headers, and TLS configuration concerns on your API endpoints."
            }
        ],
        "faqs": [
            {
                "question": "What is the difference between authentication and authorization in APIs?",
                "answer": "Authentication verifies who the user is (e.g., verifying a password and issuing a token). Authorization verifies what the authenticated user is allowed to do (e.g., checking if they have permission to view a specific record)."
            },
            {
                "question": "Can a WAF protect my API from BOLA?",
                "answer": "A Web Application Firewall (WAF) generally cannot protect against BOLA because the requests often look entirely legitimate. BOLA is a business logic flaw that must be fixed in the application code through proper access controls."
            }
        ]
    },
    {
        "id": "10",
        "title": "DAST vs SAST: What's the Difference?",
        "slug": "dast-vs-sast",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "Security Testing",
        "primaryKeyword": "DAST vs SAST",
        "secondaryKeywords": [
            "SAST vs DAST",
            "static vs dynamic security testing",
            "application security testing"
        ],
        "seoTitle": "DAST vs SAST: Security Testing Differences | URLScanOnline",
        "metaDescription": "Understand the differences between Dynamic Application Security Testing (DAST) and Static Application Security Testing (SAST) methodologies.",
        "excerpt": "A detailed comparison of Dynamic Application Security Testing (DAST) and Static Application Security Testing (SAST).",
        "content": "Application security testing is crucial for identifying vulnerabilities before they reach production. Two of the most common methodologies are Dynamic Application Security Testing (DAST) and Static Application Security Testing (SAST). Understanding <strong>DAST vs SAST</strong> helps teams build a comprehensive security strategy.",
        "sections": [
            {
                "id": "what-is-sast",
                "title": "What is SAST?",
                "content": "SAST is a \"white-box\" testing method that analyzes the application's source code, bytecode, or binaries without executing the program. It looks for coding errors, such as insecure use of cryptography, hardcoded secrets, and SQL injection flaws, by tracing the data flow through the code. SAST is typically integrated early in the Software Development Life Cycle (SDLC) and provides exact line numbers for vulnerabilities, making remediation easier for developers."
            },
            {
                "id": "what-is-dast",
                "title": "What is DAST?",
                "content": "DAST is a \"black-box\" testing method that analyzes the application while it is running. The scanner interacts with the application from the outside, sending various payloads and malformed requests to identify vulnerabilities like Cross-Site Scripting (XSS), authentication bypasses, and server misconfigurations. DAST does not require access to the source code and evaluates the application in its deployed environment, catching issues that only manifest at runtime."
            },
            {
                "id": "comparison",
                "title": "Methodology Comparison",
                "content": "Both SAST and DAST can produce false positives and false negatives. Results depend heavily on the specific tool, coverage, configuration, and the application being tested. SAST examines code without requiring application execution. DAST observes a running application and may provide runtime evidence. Neither methodology universally outperforms the other."
            },
            {
                "id": "which-to-choose",
                "title": "Which Should You Choose?",
                "content": "A mature application security program uses both. SAST is used during the coding phase to catch bugs early (shifting left), while DAST is used during staging and production to verify the deployed application's resilience against real-world attacks."
            },
            {
                "id": "cta",
                "title": "Evaluate Your Runtime Posture",
                "content": "URLScanOnline provides passive scanning capabilities that observe your deployed application from the outside, identifying externally observable configuration issues such as missing security headers and TLS configuration concerns."
            }
        ],
        "faqs": [
            {
                "question": "Can DAST find vulnerabilities in my source code?",
                "answer": "DAST interacts with the running application and does not analyze source code. It identifies vulnerabilities based on the application's responses to test payloads."
            },
            {
                "question": "Which is faster, SAST or DAST?",
                "answer": "SAST is generally faster because it operates on source code without requiring a deployed environment. DAST can take longer as it must crawl the application and simulate interactions."
            }
        ]
    },
    {
        "id": "11",
        "title": "Vulnerability Scanning vs Penetration Testing: What's the Difference?",
        "slug": "vulnerability-scanning-vs-penetration-testing",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "Security Testing",
        "primaryKeyword": "vulnerability scanning vs penetration testing",
        "secondaryKeywords": [
            "vulnerability scanner vs penetration test",
            "vulnerability assessment vs penetration testing"
        ],
        "seoTitle": "Vulnerability Scanning vs Penetration Testing | URLScanOnline",
        "metaDescription": "Learn the differences between automated vulnerability scanning and manual penetration testing for discovering and exploiting security flaws.",
        "excerpt": "Learn the vital differences between automated vulnerability scanning and manual penetration testing.",
        "content": "Organizations often use the terms vulnerability scanning and penetration testing interchangeably, but they serve fundamentally different purposes. Understanding <strong>vulnerability scanning vs penetration testing</strong> is essential for allocating security resources effectively.",
        "sections": [
            {
                "id": "vulnerability-scanning",
                "title": "What is Vulnerability Scanning?",
                "content": "Vulnerability scanning is an automated process that identifies known security weaknesses in systems, networks, and applications. Scanners look for outdated software versions, missing patches, default passwords, and common misconfigurations. Scanning is typically fast, repeatable, and scalable, making it ideal for continuous monitoring and baseline security checks."
            },
            {
                "id": "penetration-testing",
                "title": "What is Penetration Testing?",
                "content": "Penetration testing is a manual, human-led assessment where skilled security professionals attempt to exploit vulnerabilities to achieve a specific goal, such as accessing sensitive data or compromising a system. Pen testers use automated tools as a starting point, but they rely on creative thinking to chain vulnerabilities together, bypass security controls, and discover complex business logic flaws that automated tools miss."
            },
            {
                "id": "comparison",
                "title": "Key Differences",
                "content": "Vulnerability scanning answers the question: \"What known vulnerabilities exist on my systems?\" It is automated, broad, and continuous. Penetration testing answers the question: \"Can a determined attacker breach my defenses and steal my data?\" It is manual, deep, and periodic."
            },
            {
                "id": "when-to-use",
                "title": "When to Use Each",
                "content": "Vulnerability scanning should be performed continuously (e.g., weekly or monthly) to catch newly discovered CVEs and configuration drift. Penetration testing should be performed annually or after significant architectural changes to validate the effectiveness of the organization's defense-in-depth strategy."
            },
            {
                "id": "cta",
                "title": "Start with Automated Scanning",
                "content": "Before engaging a manual penetration testing team, check your baseline security is solid. URLScanOnline can help identify externally observable configuration issues such as missing security headers, weak TLS configurations, and exposed information."
            }
        ],
        "faqs": [
            {
                "question": "Does a vulnerability scan replace a penetration test?",
                "answer": "No. A vulnerability scan is a necessary baseline check, but it does not replace the deep analysis and exploitation provided by a manual penetration test."
            },
            {
                "question": "How often should I run a vulnerability scan?",
                "answer": "Given the rapid pace at which new vulnerabilities are discovered, automated scanning should be run continuously or at least on a weekly basis."
            }
        ]
    },
    {
        "id": "12",
        "title": "Passive vs Active Security Testing: What's the Difference?",
        "slug": "passive-vs-active-security-testing",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "Security Testing",
        "primaryKeyword": "passive vs active security testing",
        "secondaryKeywords": [
            "passive security testing",
            "active security testing",
            "passive vs active scanning"
        ],
        "seoTitle": "Passive vs Active Security Testing | URLScanOnline",
        "metaDescription": "Compare passive vs active security testing approaches to understand their differences in target interaction, footprint, and discovery methods.",
        "excerpt": "Understand the differences between passive and active security testing.",
        "content": "When evaluating an application's security posture, the methodology used heavily influences the risk and depth of the assessment. Understanding <strong>passive vs active security testing</strong> helps organizations choose the appropriate level of interaction with their target systems.",
        "sections": [
            {
                "id": "passive-testing",
                "title": "Passive Security Testing",
                "content": "Passive security testing involves analyzing an application without sending malicious payloads or intrusive requests that could alter the state of the target. A passive scanner makes normal HTTP requests, much like a regular user's browser, and analyzes the responses. It observes headers, cookies, configuration files, and exposed client-side code. This approach minimizes operational risk, as it avoids creating test data or triggering application errors."
            },
            {
                "id": "active-testing",
                "title": "Active Security Testing",
                "content": "Active security testing actively interacts with the application, sending crafted payloads, malformed data, and injection strings to observe how the application reacts. This is necessary to find vulnerabilities like SQL Injection, Cross-Site Scripting (XSS), and Command Injection. However, active testing carries risks: it can generate junk data in databases, trigger unexpected emails, or even cause denial-of-service conditions if the application is fragile."
            },
            {
                "id": "comparison",
                "title": "Interaction and Footprint",
                "content": "Passive testing has a minimal footprint. It only identifies configuration issues and exposed information (e.g., missing CSP headers, insecure cookie flags, exposed <code>.git</code> directories). Active testing has a large footprint and can discover complex execution flaws, but it requires careful scoping and is often restricted to staging environments."
            },
            {
                "id": "use-cases",
                "title": "Use Cases",
                "content": "Passive testing is ideal for continuous monitoring of production environments, providing a daily baseline of security hygiene. Active testing is typically integrated into the CI/CD pipeline against ephemeral testing environments, or performed periodically during scheduled maintenance windows."
            },
            {
                "id": "cta",
                "title": "Run a Passive Scan",
                "content": "URLScanOnline provides passive and low-impact external security checks. It analyzes your website's observable configuration without sending malicious payloads, making it safe to run against any production environment to identify missing security headers and TLS configuration concerns."
            }
        ],
        "faqs": [
            {
                "question": "Is passive testing safe for production?",
                "answer": "Yes. Passive testing only makes standard HTTP requests and does not inject malicious payloads, making it minimizes operational risk."
            },
            {
                "question": "Can passive testing find SQL injection?",
                "answer": "Generally, no. Finding SQL injection requires actively sending test payloads to input fields to observe if the database executes them. Passive testing focuses on configuration analysis."
            }
        ]
    },
    {
        "id": "fix-hsts-header",
        "title": "How to Fix Missing Strict-Transport-Security Header",
        "slug": "fix-missing-strict-transport-security-header",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "Remediation",
        "primaryKeyword": "how to fix missing HSTS header",
        "secondaryKeywords": [
            "missing Strict-Transport-Security header",
            "fix HSTS header",
            "enable HSTS"
        ],
        "seoTitle": "How to Fix a Missing HSTS Header | URLScanOnline",
        "metaDescription": "Step-by-step remediation guide on how to fix a missing Strict-Transport-Security (HSTS) header on common web servers like Nginx and Apache.",
        "excerpt": "Learn why the HTTP Strict Transport Security (HSTS) header is critical for securing your traffic and how to implement it safely on modern web servers.",
        "content": "A missing Strict-Transport-Security header leaves your users vulnerable to man-in-the-middle protocol downgrade attacks. This troubleshooting guide explains exactly <strong>how to fix a missing HSTS header</strong> and safely enforce HTTPS on your web server.",
        "sections": [
            {
                "id": "why-it-matters",
                "title": "Why a Missing HSTS Header Matters",
                "content": "Without HSTS, the site lacks a browser-enforced HTTPS-only protection that can reduce exposure to downgrade or SSL-stripping scenarios. If a user connects via HTTP initially, an attacker could intercept the request before the server redirects to HTTPS."
            },
            {
                "id": "implementation",
                "title": "How to Add the HSTS Header",
                "content": "To implement HSTS, you must configure your web server to return the <code>Strict-Transport-Security</code> HTTP header on all HTTPS responses. (Note: Browsers ignore the HSTS header if it is served over plain HTTP).<br><br><strong>For Nginx:</strong><br><br>Add the following directive to your server block:<br><code>add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;</code><br><br><strong>For Apache:</strong><br><br>Add this to your VirtualHost configuration:<br><code>Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"</code>"
            },
            {
                "id": "safe-rollout",
                "title": "Safe Rollout Strategy",
                "content": "Do not start with a <code>max-age</code> of one year (<code>31536000</code>). If you make a mistake or lose your SSL certificate, your site will become completely inaccessible to returning users. Start with a short duration, such as 5 minutes (<code>max-age=300</code>). Verify everything works correctly, then increase it to a week, a month, and finally a year."
            },
            {
                "id": "verification",
                "title": "Verification and Common Mistakes",
                "content": "A common mistake is applying HSTS to the root domain but forgetting the <code>includeSubDomains</code> directive. This means the parent policy does not cover subdomains; they may require their own HSTS policies to reduce exposure. After implementing, verify the header on the HTTPS response."
            },
            {
                "id": "cta",
                "title": "Verify Your HSTS Implementation",
                "content": "URLScanOnline can quickly confirm if your HSTS header is correctly applied and visible to the public. Run a scan to check for a missing Strict-Transport-Security header or syntax errors in your configuration."
            }
        ],
        "faqs": [
            {
                "question": "What is the recommended max-age for HSTS?",
                "answer": "The recommended final max-age is 31536000 seconds (1 year) or 63072000 (2 years). However, always start with a very short max-age during initial testing."
            },
            {
                "question": "Should I add the preload directive?",
                "answer": "Only add the <code>preload</code> directive if you intend to submit your domain to the official browser HSTS preload list, and only if you are absolutely certain every single subdomain you own supports HTTPS."
            }
        ]
    },
    {
        "id": "fix-csp-header",
        "title": "How to Fix Missing Content-Security-Policy Header",
        "slug": "fix-missing-content-security-policy-header",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "Remediation",
        "primaryKeyword": "how to fix missing Content Security Policy header",
        "secondaryKeywords": [
            "missing CSP header",
            "fix Content Security Policy",
            "Content-Security-Policy header missing"
        ],
        "seoTitle": "Fix Missing Content Security Policy (CSP) Header | URLScanOnline",
        "metaDescription": "Troubleshooting guide to fixing a missing Content-Security-Policy (CSP) header, including how to safely build and enforce policies.",
        "excerpt": "Content-Security-Policy (CSP) is your primary defense against Cross-Site Scripting (XSS). Learn how to incrementally deploy a CSP to protect your users.",
        "content": "A missing Content-Security-Policy (CSP) header removes a critical layer of defense-in-depth against Cross-Site Scripting (XSS). This remediation guide covers <strong>how to fix a missing Content Security Policy header</strong> through a safe, incremental rollout.",
        "sections": [
            {
                "id": "why-it-matters",
                "title": "Why a Missing CSP Matters",
                "content": "Without a CSP, browsers inherently trust all scripts and resources loaded by a web page. If an attacker injects malicious JavaScript (XSS), the browser executes it. Implementing a CSP provides an allowlist, instructing the browser to block unauthorized scripts, mitigating the impact of injection vulnerabilities."
            },
            {
                "id": "implementation",
                "title": "Building a Basic Policy",
                "content": "A good starting point for a CSP is a restrictive default policy that allows resources only from your own origin. <br><br><strong>Example Policy:</strong><br><br><code>Content-Security-Policy: default-src 'self'; img-src 'self' https://trusted-cdn.com; script-src 'self'</code><br><br>This policy ensures that scripts, styles, and other resources only load if they originate from your own domain, with an exception allowing images from a trusted CDN."
            },
            {
                "id": "safe-rollout",
                "title": "Safe Rollout using Report-Only",
                "content": "Deploying a strict CSP directly to a production site will likely break legitimate functionality by blocking required third-party scripts or inline styles. You should always begin using the <code>Content-Security-Policy-Report-Only</code> header. This instructs the browser to evaluate the policy and report violations to a specified URL, without actually blocking the resources. Analyze the violation reports to fine-tune your policy before enforcing it."
            },
            {
                "id": "verification",
                "title": "Verification and Common Mistakes",
                "content": "A common mistake is relying heavily on <code>'unsafe-inline'</code> or <code>'unsafe-eval'</code> in the <code>script-src</code> directive, which essentially nullifies the XSS protection CSP provides. Work with your development team to move inline scripts to external files or implement nonces/hashes. Once enforced, verify the header is correctly parsed by the browser using developer tools."
            },
            {
                "id": "cta",
                "title": "Check Your CSP Header",
                "content": "URLScanOnline can help identify if your site is currently broadcasting a Content Security Policy and flag if it relies on overly permissive directives like unsafe-inline."
            }
        ],
        "faqs": [
            {
                "question": "Can I use CSP to stop all XSS?",
                "answer": "No. CSP is a powerful mitigation tool (defense-in-depth), but it cannot stop all forms of XSS, especially if the policy is misconfigured. You must still practice secure coding and input validation."
            },
            {
                "question": "What happens if my CSP blocks a necessary script?",
                "answer": "If you enforce a CSP and it blocks a script, the script will not execute, and errors will appear in the browser console. This is why testing with Report-Only mode first is crucial."
            }
        ]
    },
    {
        "id": "fix-x-frame-options",
        "title": "How to Fix Missing X-Frame-Options Header",
        "slug": "fix-missing-x-frame-options-header",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "Remediation",
        "primaryKeyword": "how to fix missing X-Frame-Options",
        "secondaryKeywords": [
            "missing X-Frame-Options header",
            "X-Frame-Options security",
            "clickjacking protection"
        ],
        "seoTitle": "How to Fix Missing X-Frame-Options Header | URLScanOnline",
        "metaDescription": "Learn how to remediate a missing X-Frame-Options header to protect your website from clickjacking and UI-redress attacks.",
        "excerpt": "Clickjacking is a stealthy UI-redress attack. Find out how the X-Frame-Options header stops attackers from framing your website.",
        "content": "Clickjacking is a stealthy UI-redress attack where an attacker tricks a user into clicking something different from what they perceive. This guide explains <strong>how to fix missing X-Frame-Options</strong> to protect your application from being maliciously framed.",
        "sections": [
            {
                "id": "why-it-matters",
                "title": "The Threat of Clickjacking",
                "content": "If your website lacks framing protection, an attacker can embed your site within an invisible <code><iframe></code> on their own malicious website. They can then overlay deceptive buttons on top of your site's UI. When the victim attempts to click the visible button, they are actually clicking the invisible interface of your framed application, potentially executing unauthorized actions (like transferring funds or deleting an account)."
            },
            {
                "id": "implementation",
                "title": "How to Implement X-Frame-Options",
                "content": "The <code>X-Frame-Options</code> HTTP response header tells the browser whether it is allowed to render a page in a <code><frame></code>, <code><iframe></code>, <code><embed></code> or <code><object></code>. <br><br><strong>Common Values:</strong><br><br>- <code>DENY</code>: The page cannot be displayed in a frame, regardless of the site attempting to do so.<br>- <code>SAMEORIGIN</code>: The page can only be displayed in a frame on the same origin as the page itself.<br><br><strong>Nginx Example:</strong><br><code>add_header X-Frame-Options \"SAMEORIGIN\" always;</code><br><br><strong>Apache Example:</strong><br><code>Header always set X-Frame-Options \"SAMEORIGIN\"</code>"
            },
            {
                "id": "csp-alternative",
                "title": "Modern Alternative: CSP frame-ancestors",
                "content": "While <code>X-Frame-Options</code> is widely supported, the modern approach is to use the <code>frame-ancestors</code> directive within the <code>Content-Security-Policy</code> header. For example, <code>Content-Security-Policy: frame-ancestors 'self'</code> provides the equivalent of <code>SAMEORIGIN</code>. If both are present, modern browsers will prioritize the CSP directive. However, setting both provides the best backward compatibility for older browsers."
            },
            {
                "id": "cta",
                "title": "Verify Framing Protections",
                "content": "URLScanOnline can passively check your HTTP responses to ensure that either an X-Frame-Options header or a CSP frame-ancestors directive is correctly configured to protect your site."
            }
        ],
        "faqs": [
            {
                "question": "Which is better: DENY or SAMEORIGIN?",
                "answer": "If your application never needs to be embedded in an iframe anywhere, use <code>DENY</code> for maximum security. If you need to embed pages within your own application across the same domain, use <code>SAMEORIGIN</code>."
            }
        ]
    },
    {
        "id": "fix-insecure-cookies",
        "title": "How to Fix Insecure Cookie Flags: Secure, HttpOnly, SameSite",
        "slug": "fix-insecure-cookie-flags",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "Remediation",
        "primaryKeyword": "how to fix insecure cookie flags",
        "secondaryKeywords": [
            "Secure HttpOnly SameSite cookies",
            "cookie security flags",
            "insecure cookies"
        ],
        "seoTitle": "How to Fix Insecure Cookie Flags | URLScanOnline",
        "metaDescription": "Remediation instructions for securing session cookies by properly configuring the Secure, HttpOnly, and SameSite attributes.",
        "excerpt": "Session hijacking is a severe threat. Learn how to implement the Secure, HttpOnly, and SameSite flags to harden your session cookies.",
        "content": "Session cookies are the keys to user accounts. If they are intercepted or stolen, attackers can completely bypass authentication. This guide explains <strong>how to fix insecure cookie flags</strong> to protect session integrity.",
        "sections": [
            {
                "id": "why-it-matters",
                "title": "The Risk of Insecure Cookies",
                "content": "When a web application sets a session cookie without proper security attributes, the browser may transmit the cookie over unencrypted HTTP connections or allow client-side JavaScript to access it. This exposes the session to network interception (man-in-the-middle attacks) and Cross-Site Scripting (XSS) theft."
            },
            {
                "id": "secure-flag",
                "title": "The Secure Flag",
                "content": "The <code>Secure</code> attribute instructs the browser that the cookie must only be transmitted over an encrypted HTTPS connection. If a user inadvertently accesses your site via plain HTTP, the browser will withhold the cookie, preventing it from being intercepted on the network."
            },
            {
                "id": "httponly-flag",
                "title": "The HttpOnly Flag",
                "content": "The <code>HttpOnly</code> attribute prevents client-side scripts (like JavaScript) from directly accessing the cookie via <code>document.cookie</code>. However, injected JavaScript may still perform authenticated same-origin actions."
            },
            {
                "id": "samesite-flag",
                "title": "The SameSite Flag",
                "content": "The <code>SameSite</code> attribute helps restrict cross-site requests. Setting <code>SameSite=Strict</code> ensures the cookie is only sent for first-party requests. <code>SameSite=Lax</code> permits normal same-site cookie use and restricts many cross-site requests, though it can permit cookies on certain top-level safe navigations."
            },
            {
                "id": "implementation",
                "title": "How to Configure Cookie Flags",
                "content": "Cookie attributes are appended to the <code>Set-Cookie</code> HTTP response header.<br><br><strong>Example:</strong><br><br><code>Set-Cookie: session_id=abc123xyz; Secure; HttpOnly; SameSite=Strict</code><br><br>Implementation depends on your backend framework (Node.js, Django, Laravel, Spring, etc.). Consult your framework's documentation on session management to check these flags are enabled by default."
            },
            {
                "id": "cta",
                "title": "Check Your Cookie Configuration",
                "content": "URLScanOnline analyzes the <code>Set-Cookie</code> headers returned by your web server to identify missing Secure or HttpOnly flags on your critical session identifiers."
            }
        ],
        "faqs": [
            {
                "question": "Can I use the Secure flag on a local development server?",
                "answer": "Modern browsers usually allow the <code>Secure</code> flag on <code>localhost</code> or <code>127.0.0.1</code> even over HTTP. However, in staging or production, it requires a valid HTTPS connection."
            }
        ]
    },
    {
        "id": "fix-cors-misconfiguration",
        "title": "How to Check CORS Misconfiguration Safely",
        "slug": "fix-cors-misconfiguration",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "Remediation",
        "primaryKeyword": "how to fix CORS misconfiguration",
        "secondaryKeywords": [
            "CORS security",
            "CORS misconfiguration",
            "Access-Control-Allow-Origin security"
        ],
        "seoTitle": "How to Fix a CORS Misconfiguration | URLScanOnline",
        "metaDescription": "A troubleshooting guide on how to fix CORS misconfigurations and correctly restrict the Access-Control-Allow-Origin response header.",
        "excerpt": "Cross-Origin Resource Sharing (CORS) is often misunderstood. Learn how a permissive CORS policy can leak private data and how to correctly restrict it.",
        "content": "Cross-Origin Resource Sharing (CORS) is a vital mechanism that allows browsers to securely make cross-domain API requests. This troubleshooting guide explains <strong>how to fix CORS misconfigurations</strong> and properly restrict the Access-Control-Allow-Origin header.",
        "sections": [
            {
                "id": "why-it-matters",
                "title": "The Danger of Permissive CORS",
                "content": "By default, the Same-Origin Policy prevents a malicious website from making authenticated API requests to your application on behalf of a victim. CORS relaxes this policy. A wildcard <code>*</code> allows cross-origin reading of non-credentialed responses. However, modern browsers reject credentialed requests if the allowed origin is a wildcard. A dangerous pattern is reflecting an arbitrary or untrusted Origin in the <code>Access-Control-Allow-Origin</code> header while also allowing credentials."
            },
            {
                "id": "implementation",
                "title": "Correcting the Access-Control-Allow-Origin Header",
                "content": "Never use the wildcard <code>*</code> if your API handles sensitive data or requires authentication. Instead, your server must dynamically read the <code>Origin</code> request header, validate it against a strict server-side allowlist of trusted domains, and echo that exact trusted domain back in the <code>Access-Control-Allow-Origin</code> response header."
            },
            {
                "id": "credentials",
                "title": "Handling Access-Control-Allow-Credentials",
                "content": "If your API relies on cookies or HTTP authentication, the client will set <code>credentials: 'include'</code>. In this scenario, the server MUST return <code>Access-Control-Allow-Credentials: true</code>. Crucially, modern browsers will reject the request if the Allow-Origin header is a wildcard <code>*</code> while credentials are true. You must explicitly specify the allowed origin."
            },
            {
                "id": "preflight",
                "title": "Understanding Preflight Requests",
                "content": "For complex requests (like POST with JSON data or custom headers), the browser first sends an HTTP <code>OPTIONS</code> request (a preflight request) to verify if the server permits the actual request. Ensure your server correctly responds to <code>OPTIONS</code> requests with the appropriate CORS headers, including <code>Access-Control-Allow-Methods</code> and <code>Access-Control-Allow-Headers</code>."
            },
            {
                "id": "cta",
                "title": "Test Your API Headers",
                "content": "URLScanOnline can help observe the CORS headers returned by your web application and identify if overly permissive configurations, such as wildcard origins, are exposed to the public."
            }
        ],
        "faqs": [
            {
                "question": "Can I allow multiple origins in the CORS header?",
                "answer": "The <code>Access-Control-Allow-Origin</code> header can only contain a single origin or a wildcard <code>*</code>. To allow multiple specific domains, your server logic must read the incoming <code>Origin</code> header, check it against a whitelist, and echo it back dynamically."
            }
        ]
    },
    {
        "id": "passive-vs-active-scanning",
        "title": "Passive Vulnerability Scanner vs Active Penetration Testing",
        "slug": "passive-vulnerability-scanner-vs-active-penetration-testing",
        "author": "URLScanOnline",
        "image": "https://www.urlscanonline.com/logo-v6.png",
        "category": "Concepts",
        "primaryKeyword": "passive vulnerability scanner",
        "secondaryKeywords": [
            "passive vulnerability scanning",
            "active penetration testing",
            "passive scanner vs penetration test"
        ],
        "seoTitle": "Passive Vulnerability Scanner vs Penetration Testing | URLScanOnline",
        "metaDescription": "Discover how a passive vulnerability scanner fits into your security workflow compared to high-interaction active penetration testing.",
        "excerpt": "Understand the fundamental differences between passive scanning and active penetration testing to choose the right tool for your security workflow.",
        "content": "When deciding how to allocate security resources, organizations often wonder whether they need automated tools, manual testing, or both. Discovering how a <strong>passive vulnerability scanner vs active penetration testing</strong> fits into a modern workflow is key to building a robust security program.",
        "sections": [
            {
                "id": "what-is-passive-scanner",
                "title": "The Role of a Passive Vulnerability Scanner",
                "content": "A passive vulnerability scanner provides low-impact external security checks designed to identify observable security misconfigurations. It analyzes HTTP headers and certificates without sending exploit payloads. It minimizes operational risk, though any automated scan generates network requests and should be run only against authorized systems. Scans can be repeated periodically to check baseline security hygiene."
            },
            {
                "id": "what-is-active-pentesting",
                "title": "The Role of Active Penetration Testing",
                "content": "Active penetration testing is a deep, human-led assessment where security engineers actively attempt to exploit vulnerabilities. They use intrusive techniques, malformed data, and creative logic to chain exploits together, bypassing defenses to achieve a specific goal (like accessing a database). Penetration testing is essential for finding complex business logic flaws, authorization bypasses (like BOLA), and deep code execution vulnerabilities."
            },
            {
                "id": "workflow-integration",
                "title": "Integrating Both into Your Workflow",
                "content": "These approaches are complementary. A passive scanner acts as your baseline radar to catch misconfigurations. Penetration testing is your deep dive to validate the application's core logic against a determined human attacker."
            },
            {
                "id": "cost-efficiency",
                "title": "Maximizing Cost Efficiency",
                "content": "Penetration testing is expensive and time-consuming. If you hire a penetration tester to assess a site with poor baseline hygiene, they will spend their time documenting easily found missing headers and weak TLS configurations instead of hunting for critical logic flaws. By using a passive scanner to fix the basics first, you check your penetration testing budget is spent on discovering high-value, complex vulnerabilities."
            },
            {
                "id": "cta",
                "title": "Establish Your Security Baseline",
                "content": "URLScanOnline is designed to be your first line of visibility. Use our passive scanner to identify and fix missing security headers, weak TLS, and exposed files before scheduling your next deep penetration test."
            }
        ],
        "faqs": [
            {
                "question": "Can a passive scanner replace penetration testing?",
                "answer": "No. A passive scanner is excellent for continuous hygiene and configuration checks, but it cannot find the complex logic flaws that a human penetration tester can uncover."
            },
            {
                "question": "Why should I use a passive scanner if I already do penetration testing?",
                "answer": "Configuration drift happens daily. A passive scanner provides continuous monitoring to catch regressions (like a misconfigured server update) in the months between your annual penetration tests."
            }
        ]
    }
];
