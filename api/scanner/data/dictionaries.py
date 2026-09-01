# --- REMEDIATION SNIPPETS DATABASE ---
REMEDIATION_SNIPPETS = {
    "Missing Strict-Transport-Security (HSTS)": {
        "nginx": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
        "apache": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
        "vercel": '{\n  "headers": [{\n    "source": "/(.*)",\n    "headers": [{ "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload" }]\n  }]\n}',
        "cloudflare": 'Rules -> Transform Rules -> Modify Response Header -> Set "Strict-Transport-Security" to "max-age=31536000; includeSubDomains; preload"'
    },
    "Missing Content-Security-Policy (CSP)": {
        "nginx": 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\';" always;',
        "apache": 'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\';"',
        "vercel": '{\n  "headers": [{\n    "source": "/(.*)",\n    "headers": [{ "key": "Content-Security-Policy", "value": "default-src \'self\';" }]\n  }]\n}',
        "cloudflare": 'Rules -> Modify Response Header -> Set "Content-Security-Policy" to "default-src \'self\';"'
    },
    "Weak Content-Security-Policy (CSP)": {
        "nginx": 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\';" always;',
        "apache": 'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\';"',
        "vercel": 'Remove \'unsafe-inline\' and \'unsafe-eval\' from script-src in your vercel.json header config.',
        "cloudflare": 'Update Content-Security-Policy header rule to remove unsafe directives.'
    },
    "Missing X-Frame-Options": {
        "nginx": 'add_header X-Frame-Options "DENY" always;',
        "apache": 'Header always set X-Frame-Options "DENY"',
        "vercel": '{\n  "headers": [{ "source": "/(.*)", "headers": [{ "key": "X-Frame-Options", "value": "DENY" }] }]\n}',
        "cloudflare": 'Rules -> Modify Response Header -> Set "X-Frame-Options" to "DENY"'
    },
    "Missing X-Content-Type-Options": {
        "nginx": 'add_header X-Content-Type-Options "nosniff" always;',
        "apache": 'Header always set X-Content-Type-Options "nosniff"',
        "vercel": '{\n  "headers": [{ "source": "/(.*)", "headers": [{ "key": "X-Content-Type-Options", "value": "nosniff" }] }]\n}',
        "cloudflare": 'Rules -> Modify Response Header -> Set "X-Content-Type-Options" to "nosniff"'
    },
    "Missing Referrer-Policy": {
        "nginx": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        "apache": 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        "vercel": '{\n  "headers": [{ "source": "/(.*)", "headers": [{ "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" }] }]\n}',
        "cloudflare": 'Rules -> Modify Response Header -> Set "Referrer-Policy" to "strict-origin-when-cross-origin"'
    },
    "Missing Permissions-Policy": {
        "nginx": 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
        "apache": 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"',
        "vercel": '{\n  "headers": [{ "source": "/(.*)", "headers": [{ "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()" }] }]\n}',
        "cloudflare": 'Rules -> Modify Response Header -> Set "Permissions-Policy" to "camera=(), microphone=(), geolocation=()"'
    },
    "Exposed .env Configuration File": {
        "nginx": 'location ~ /\\.env {\n    deny all;\n    return 404;\n}',
        "apache": '<Files ".env">\n    Require all denied\n</Files>',
        "vercel": 'Ensure .env is listed in .gitignore and not exported in public directory builds.',
        "cloudflare": 'Security -> WAF -> Custom Rules -> Block URI Path equals "/.env"'
    },
    "Exposed .git Repository": {
        "nginx": 'location ~ /\\.git {\n    deny all;\n    return 404;\n}',
        "apache": '<DirectoryMatch "/\\.git">\n    Require all denied\n</DirectoryMatch>',
        "vercel": 'Ensure .git folder is excluded from deployed output.',
        "cloudflare": 'Security -> WAF -> Custom Rules -> Block URI Path starts_with "/.git"'
    },
    "Missing SPF Record": {
        "dns_record": 'Type: TXT | Name: @ | Value: v=spf1 include:_spf.google.com ~all',
        "note": 'Publish an SPF TXT record at your domain root authorizing valid mail servers.'
    },
    "Missing DMARC Policy": {
        "dns_record": 'Type: TXT | Name: _dmarc | Value: v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@yourdomain.com',
        "note": 'Publish a DMARC TXT record at _dmarc.yourdomain.com with enforcement policy.'
    },
    "Missing CAA Record": {
        "dns_record": 'Type: CAA | Name: @ | Value: 0 issue "letsencrypt.org"',
        "note": 'Publish CAA DNS records restricting SSL issuance to specific Certificate Authorities.'
    }
}

# --- GLOBAL COMPLIANCE FRAMEWORK MAPPING DATABASE ---
COMPLIANCE_MAP = {
    "Exposed .env Configuration File": {
        "pci_dss": "3.2 (Protect Stored Account Data)",
        "nist": "IA-5 (Authenticator Management)",
        "iso27001": "A.8.12 (Data Leakage Prevention)"
    },
    "Exposed .git Repository": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "iso27001": "A.8.28 (Secure Coding)"
    },
    "Missing Strict-Transport-Security (HSTS)": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "iso27001": "A.8.20 (Network Security)"
    },
    "Missing Content-Security-Policy (CSP)": {
        "pci_dss": "6.4.3 (Manage Payment Page Scripts)",
        "iso27001": "A.8.20 (Network Security)"
    },
    "Weak Content-Security-Policy (CSP)": {
        "pci_dss": "6.4.3 (Manage Payment Page Scripts)",
        "iso27001": "A.8.28 (Secure Coding)"
    },
    "Missing X-Frame-Options": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "iso27001": "A.8.20 (Network Security)"
    },
    "Missing X-Content-Type-Options": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "iso27001": "A.8.28 (Secure Coding)"
    },
    "Missing Permissions-Policy": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "iso27001": "A.8.20 (Network Security)"
    },
    "Missing Referrer-Policy": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "nist": "SC-13 (Cryptographic Protection)",
        "iso27001": "A.8.12 (Data Leakage Prevention)"
    },
    "Missing SPF Record": {
        "pci_dss": "5.4.1 (Anti-Phishing & Email Structure)",
        "nist": "SI-8 (Spam & Phishing Protection)",
        "iso27001": "A.8.19 (Information Security in Systems)"
    },
    "Weak SPF Record (+all)": {
        "pci_dss": "5.4.1 (Anti-Phishing & Email Structure)",
        "nist": "SI-8 (Spam & Phishing Protection)",
        "iso27001": "A.8.19 (Information Security in Systems)"
    },
    "Missing DMARC Policy": {
        "pci_dss": "5.4.1 (Anti-Phishing & Spoofing)",
        "nist": "SI-8 (Spam & Phishing Protection)",
        "iso27001": "A.8.19 (Information Security in Systems)"
    },
    "Weak DMARC Policy (p=none)": {
        "pci_dss": "5.4.1 (Anti-Phishing & Spoofing)",
        "nist": "SI-8 (Spam & Phishing Protection)",
        "iso27001": "A.8.19 (Information Security in Systems)"
    },
    "Missing CAA Record": {
        "pci_dss": "4.1.2 (Encrypt Management Sessions)",
        "nist": "SC-13 (Cryptographic Protection)",
        "iso27001": "A.8.24 (Use of Cryptography)"
    },
    "Wildcard CORS Policy": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "iso27001": "A.8.3 (Access Control)"
    },
    "Valid SSL/TLS Certificate": {
        "pci_dss": "4.1.2 (Encrypt Management Sessions)",
        "nist": "SC-8 (Transmission Confidentiality)",
        "iso27001": "A.8.24 (Use of Cryptography)"
    },
    "SPF Record Configured": {
        "pci_dss": "5.4.1 (Anti-Phishing & Email Structure)",
        "nist": "SI-8 (Spam & Phishing Protection)",
        "iso27001": "A.8.19 (Information Security in Systems)"
    },
    "Strong DMARC Policy Configured": {
        "pci_dss": "5.4.1 (Anti-Phishing & Spoofing)",
        "nist": "SI-8 (Spam & Phishing Protection)",
        "iso27001": "A.8.19 (Information Security in Systems)"
    },
    "CAA Records Configured": {
        "pci_dss": "4.1.2 (Encrypt Management Sessions)",
        "nist": "SC-13 (Cryptographic Protection)",
        "iso27001": "A.8.24 (Use of Cryptography)"
    },
    "security.txt Found": {
        "pci_dss": "N/A",
        "nist": "RA-5 (Vulnerability Scanning)",
        "iso27001": "A.8.8 (Management of Technical Vulnerabilities)"
    },
    "HTTPS Redirection Configured": {
        "pci_dss": "4.1.2 (Encrypt Management Sessions)",
        "nist": "SC-8 (Transmission Confidentiality)",
        "iso27001": "A.8.24 (Use of Cryptography)"
    },
    "Permissions-Policy Configured": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "iso27001": "A.8.20 (Network Security)"
    },
    "Strict-Transport-Security Configured": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "iso27001": "A.8.20 (Network Security)"
    },
    "Content-Security-Policy Configured": {
        "pci_dss": "6.4.3 (Manage Payment Page Scripts)",
        "iso27001": "A.8.20 (Network Security)"
    },
    "Referrer-Policy Configured": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "nist": "SC-13 (Cryptographic Protection)",
        "iso27001": "A.8.12 (Data Leakage Prevention)"
    }
}

IMPACT_MAP = {
    "Missing Strict-Transport-Security (HSTS)": "Allows attackers to downgrade HTTPS connections to unencrypted HTTP via man-in-the-middle SSL stripping attacks.",
    "Missing Content-Security-Policy (CSP)": "Permissive directives like 'unsafe-inline' or 'unsafe-eval' weaken browser defenses, leaving your site vulnerable to Cross-Site Scripting (XSS) and data theft.",
    "Weak Content-Security-Policy (CSP)": "Permissive directives like 'unsafe-inline' or 'unsafe-eval' weaken browser defenses, leaving your site vulnerable to Cross-Site Scripting (XSS) and data theft.",
    "Missing X-Frame-Options": "Permits attackers to embed the site in an iframe, leading to Clickjacking and unauthorized actions.",
    "Missing X-Content-Type-Options": "Enables MIME-sniffing attacks where malicious files are executed as scripts.",
    "Missing Permissions-Policy": "Allows third-party scripts to access sensitive browser features like the camera, microphone, or geolocation.",
    "Missing Referrer-Policy": "Leaks sensitive URLs and tokens in the Referer header to external domains.",
    "Missing SPF Record": "Allows attackers to easily spoof emails from your domain for phishing campaigns.",
    "Missing DMARC Policy": "Prevents enforcement of SPF/DKIM, allowing spoofed emails to reach users' inboxes.",
    "Wildcard CORS Policy": "Malicious external websites can make authenticated API requests on behalf of logged-in users and exfiltrate private session data.",
    "Weak TLS Cipher Negotiated": "Deprecated ciphers allow attackers performing Man-in-the-Middle (MitM) network eavesdropping to decrypt confidential user traffic.",
    "Insecure or Obsolete TLS Ciphers Enforced": "Deprecated ciphers allow attackers performing Man-in-the-Middle (MitM) network eavesdropping to decrypt confidential user traffic.",
    "Legacy Weak TLS Ciphers Supported": "Deprecated ciphers allow attackers performing Man-in-the-Middle (MitM) network eavesdropping to decrypt confidential user traffic.",
    "Exposed Server Header": "Revealing exact backend technologies helps attackers run automated recon to target known, published vulnerabilities in your tech stack.",
    "Exposed X-Powered-By Header": "Revealing exact backend technologies helps attackers run automated recon to target known, published vulnerabilities in your tech stack.",
    "X-Powered-By Header Exposed": "Revealing exact backend technologies helps attackers run automated recon to target known, published vulnerabilities in your tech stack.",
    "Missing DNS CAA Record": "Allows any unauthorized Certificate Authority (CA) to issue SSL/TLS certificates for your domain without restriction."
}
