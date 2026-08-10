export const CATEGORY_METADATA = {
  "Encryption": { 
    title: "Transport & TLS Encryption", 
    icon: "Lock", 
    description: "Cryptographic protocol & SSL/TLS integrity checks ensuring secure data transmission." 
  },
  "Browser Protection": { 
    title: "Browser Defense & Headers", 
    icon: "Shield", 
    description: "Protections against XSS, clickjacking, MIME sniffing, and advanced browser attacks." 
  },
  "Privacy Protection": { 
    title: "Privacy & Leak Prevention", 
    icon: "EyeOff", 
    description: "Controls to prevent side-channel timing attacks, cross-origin leaks, and server fingerprinting." 
  },
  "Email Trust": { 
    title: "Email & Domain Security", 
    icon: "Mail", 
    description: "Spoofing defenses including SPF, DKIM, and DMARC records to protect sender reputation." 
  },
  "Domain Trust": { 
    title: "Domain Authority & PKI", 
    icon: "Globe", 
    description: "DNS controls like CAA records restricting unauthorized SSL certificate issuance." 
  },
  "Website Trust": { 
    title: "Compliance & Disclosure", 
    icon: "FileCheck", 
    description: "Standardized paths for vulnerability disclosure and public-facing trust markers." 
  },
  "Session Security": { 
    title: "Session & Cookie Security", 
    icon: "Key", 
    description: "Flags protecting authentication cookies from theft, interception, and CSRF attacks." 
  }
};

export const TRANSLATIONS = {
  "Missing Strict-Transport-Security Header": {
    name: "Insecure Connection Fallback",
    category: "Encryption"
  },
  "Missing Strict-Transport-Security (HSTS)": {
    name: "Missing Forced Encryption (HSTS)",
    category: "Encryption"
  },
  "Missing Content-Security-Policy (CSP)": {
    name: "Weak Data Injection Guard (CSP)",
    category: "Browser Protection"
  },
  "Weak Content-Security-Policy (CSP)": {
    name: "Weak Data Injection Guard (CSP)",
    category: "Browser Protection"
  },
  "Missing X-Frame-Options": {
    name: "Missing Clickjacking Protection (X-Frame-Options)",
    category: "Browser Protection"
  },
  "Missing X-Frame-Options Header": {
    name: "Missing Clickjacking Protection (X-Frame-Options)",
    category: "Browser Protection"
  },
  "Missing X-Content-Type-Options": {
    name: "Missing Malicious File Guard (nosniff)",
    category: "Browser Protection"
  },
  "Missing Referrer-Policy": {
    name: "Missing External Link Privacy (Referrer-Policy)",
    category: "Privacy Protection"
  },
  "Missing Permissions-Policy": {
    name: "Unrestricted Browser Capabilities (Permissions-Policy)",
    category: "Privacy Protection"
  },
  "Missing Cross-Origin-Opener-Policy": {
    name: "Missing Cross-Window Isolation (COOP)",
    category: "Browser Protection"
  },
  "Missing Cross-Origin-Embedder-Policy": {
    name: "Missing Cross-Origin Resource Isolation (COEP)",
    category: "Browser Protection"
  },
  "Missing Cross-Origin-Resource-Policy": {
    name: "Unprotected Cross-Origin Assets (CORP)",
    category: "Privacy Protection"
  },
  "Missing SPF Record": {
    name: "Missing Email Anti-Spoofing (SPF)",
    category: "Email Trust"
  },
  "Missing DMARC Policy": {
    name: "Inactive Email Phishing Defense (DMARC)",
    category: "Email Trust"
  },
  "Weak DMARC Policy (p=none)": {
    name: "Inactive Email Phishing Defense (DMARC)",
    category: "Email Trust"
  },
  "Missing DNS CAA Record": {
    name: "Missing Certificate Authority Lock (CAA)",
    category: "Domain Trust"
  },
  "Missing security.txt": {
    name: "Missing Vulnerability Disclosure Contact (security.txt)",
    category: "Website Trust"
  },
  "Missing HttpOnly Flag on Cookie": {
    name: "Unsecured Session Cookie (HttpOnly)",
    category: "Session Security"
  },
  "Missing Secure Flag on Cookie": {
    name: "Unencrypted Cookie Transmission (Secure Flag)",
    category: "Session Security"
  },
  "Missing SameSite Attribute on Cookie": {
    name: "Unprotected Cross-Site Cookie (SameSite)",
    category: "Session Security"
  },
  "Exposed Server Header": {
    name: "Exposed Web Server Technology",
    category: "Privacy Protection"
  },
  "Exposed X-Powered-By Header": {
    name: "Exposed Web Server Technology",
    category: "Privacy Protection"
  },
  "X-Powered-By Header Exposed": {
    name: "X-Powered-By Header Exposed",
    category: "Privacy Protection"
  },
  "Missing Automatic HTTPS Forwarding": {
    name: "Missing Automatic HTTPS Forwarding",
    category: "Encryption"
  },
  "Wildcard SSL Certificate": {
    name: "Broad Subdomain Certificate Scope",
    category: "Encryption"
  },
  "Directory Listing Enabled": {
    name: "Exposed Website Files",
    category: "Privacy Protection"
  },
  "Wildcard CORS Policy": {
    name: "Permissive CORS Policy",
    category: "Session Security"
  },
  "Weak TLS Cipher Negotiated": {
    name: "Weak TLS Cipher",
    category: "Encryption"
  },
  "Insecure or Obsolete TLS Ciphers Enforced": {
    name: "Obsolete TLS Ciphers Enforced",
    category: "Encryption"
  },
  "Legacy Weak TLS Ciphers Supported": {
    name: "Legacy Weak TLS Ciphers Supported",
    category: "Encryption"
  },
  "Missing HTTPS Redirection": {
    name: "Missing HTTPS Redirection",
    category: "Encryption"
  },
  "SSL/TLS Connection Failure": {
    name: "SSL/TLS Connection Failure",
    category: "Encryption"
  }
};
