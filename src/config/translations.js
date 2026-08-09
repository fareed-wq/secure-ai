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
    problem: "Your website does not always force visitors to use a secure connection.",
    why: "If visitors type 'http://' instead of 'https://', their connection might not be encrypted, allowing attackers to intercept their data.",
    category: "Encryption"
  },
  "Missing Strict-Transport-Security (HSTS)": {
    name: "Missing Forced Encryption (HSTS)",
    problem: "Your website does not force browsers to use secure HTTPS connections automatically.",
    why: "Allows attackers to downgrade HTTPS connections to unencrypted HTTP via man-in-the-middle SSL stripping attacks.",
    category: "Encryption"
  },
  "Missing Content-Security-Policy (CSP)": {
    name: "Weak Data Injection Guard (CSP)",
    problem: "Your site either lacks a Content Security Policy or has permissive rules that allow unauthorized scripts.",
    why: "Permissive directives like 'unsafe-inline' or 'unsafe-eval' weaken browser defenses, leaving your site vulnerable to Cross-Site Scripting (XSS) and data theft.",
    category: "Browser Protection"
  },
  "Weak Content-Security-Policy (CSP)": {
    name: "Weak Data Injection Guard (CSP)",
    problem: "Your site has a permissive Content Security Policy that allows unauthorized scripts.",
    why: "Permissive directives like 'unsafe-inline' or 'unsafe-eval' weaken browser defenses, leaving your site vulnerable to Cross-Site Scripting (XSS) and data theft.",
    category: "Browser Protection"
  },
  "Missing X-Frame-Options": {
    name: "Missing Clickjacking Protection (X-Frame-Options)",
    problem: "Your website lacks rules preventing external sites from embedding your web pages inside hidden frames.",
    why: "Attackers can overlay invisible buttons over your website to trick users into clicking malicious links or submitting data.",
    category: "Browser Protection"
  },
  "Missing X-Frame-Options Header": {
    name: "Missing Clickjacking Protection (X-Frame-Options)",
    problem: "Your website lacks rules preventing external sites from embedding your web pages inside hidden frames.",
    why: "Attackers can overlay invisible buttons over your website to trick users into clicking malicious links or submitting data.",
    category: "Browser Protection"
  },
  "Missing X-Content-Type-Options": {
    name: "Missing Malicious File Guard (nosniff)",
    problem: "Your server does not explicitly instruct browsers to strictly enforce file types.",
    why: "Browsers may try to guess a file's format and accidentally execute a fake image or document containing hidden script code.",
    category: "Browser Protection"
  },
  "Missing Referrer-Policy": {
    name: "Missing External Link Privacy (Referrer-Policy)",
    problem: "Your website does not control what URL details are shared when visitors click links leading to external websites.",
    why: "Sensitive internal page URLs or parameters could leak to third-party web servers when users leave your site.",
    category: "Privacy Protection"
  },
  "Missing Permissions-Policy": {
    name: "Unrestricted Browser Capabilities (Permissions-Policy)",
    problem: "Your site does not define rules for accessing browser hardware features (like camera, microphone, or geolocation).",
    why: "Embedded third-party scripts could attempt to request or misuse browser hardware permissions.",
    category: "Privacy Protection"
  },
  "Missing Cross-Origin-Opener-Policy": {
    name: "Missing Cross-Window Isolation (COOP)",
    problem: "Your website does not isolate its browser process from external sites opened via links.",
    why: "Malicious pop-ups or external links could attempt side-channel timing attacks against active user sessions.",
    category: "Browser Protection"
  },
  "Missing Cross-Origin-Embedder-Policy": {
    name: "Missing Cross-Origin Resource Isolation (COEP)",
    problem: "Your site loads external assets without requiring explicit cross-origin loading permission.",
    why: "Prevents advanced browser-level data isolation needed to defend against processor-level memory leaks.",
    category: "Browser Protection"
  },
  "Missing Cross-Origin-Resource-Policy": {
    name: "Unprotected Cross-Origin Assets (CORP)",
    problem: "Your web server does not restrict which external domains are allowed to read your site's images and scripts.",
    why: "Other websites could embed or read your private media assets directly without authorization.",
    category: "Privacy Protection"
  },
  "Missing SPF Record": {
    name: "Missing Email Anti-Spoofing (SPF)",
    problem: "Your domain is missing an authorization record that specifies who can send email on your behalf.",
    why: "Scammers can send fake emails pretending to come from your company, damaging your reputation and tricking your customers.",
    category: "Email Trust"
  },
  "Missing DMARC Policy": {
    name: "Inactive Email Phishing Defense (DMARC)",
    problem: "Your domain has email verification set to 'monitoring only' mode (p=none) or lacks a DMARC policy entirely.",
    why: "Receiving mail servers are instructed to deliver spoofed emails pretending to be from your domain rather than blocking them.",
    category: "Email Trust"
  },
  "Weak DMARC Policy (p=none)": {
    name: "Inactive Email Phishing Defense (DMARC)",
    problem: "Your domain has email verification set to 'monitoring only' mode (p=none) or lacks a DMARC policy entirely.",
    why: "Receiving mail servers are instructed to deliver spoofed emails pretending to be from your domain rather than blocking them.",
    category: "Email Trust"
  },
  "Missing DNS CAA Record": {
    name: "Missing Certificate Authority Lock (CAA)",
    problem: "Your domain DNS settings lack a CAA record restricting who can issue SSL certificates for your site.",
    why: "Allows any unauthorized Certificate Authority (CA) to issue SSL/TLS certificates for your domain without restriction.",
    category: "Domain Trust"
  },
  "Missing security.txt": {
    name: "Missing Vulnerability Disclosure Contact (security.txt)",
    problem: "Your domain does not publish a standard security contact file at /.well-known/security.txt.",
    why: "Ethical security researchers who find vulnerabilities on your site have no official path to privately report them to your team.",
    category: "Website Trust"
  },
  "Missing HttpOnly Flag on Cookie": {
    name: "Unsecured Session Cookie (HttpOnly)",
    problem: "A cookie saved in your browser is missing the HttpOnly security restriction.",
    why: "If a malicious script runs on your site, it can steal this cookie and hijack active user logins or sessions.",
    category: "Session Security"
  },
  "Missing Secure Flag on Cookie": {
    name: "Unencrypted Cookie Transmission (Secure Flag)",
    problem: "Session cookies are missing the 'Secure' flag.",
    why: "Browsers may send sensitive authentication cookies over unencrypted HTTP connections if requested.",
    category: "Session Security"
  },
  "Missing SameSite Attribute on Cookie": {
    name: "Unprotected Cross-Site Cookie (SameSite)",
    problem: "Your website sets browser cookies without defining strict cross-site sharing restrictions.",
    why: "Browsers may send these cookies automatically on third-party links, making users vulnerable to Cross-Site Request Forgery (CSRF).",
    category: "Session Security"
  },
  "Exposed Server Header": {
    name: "Exposed Web Server Technology",
    problem: "Your web server advertises its exact software name and version in response headers.",
    why: "Revealing exact backend technologies helps attackers run automated recon to target known, published vulnerabilities in your tech stack.",
    category: "Privacy Protection"
  },
  "Exposed X-Powered-By Header": {
    name: "Exposed Web Server Technology",
    problem: "Your web server advertises its exact software name and version in response headers.",
    why: "Revealing exact backend technologies helps attackers run automated recon to target known, published vulnerabilities in your tech stack.",
    category: "Privacy Protection"
  },
  "X-Powered-By Header Exposed": {
    name: "X-Powered-By Header Exposed",
    problem: "Backend technology is explicitly declared.",
    why: "Revealing exact backend technologies helps attackers run automated recon to target known, published vulnerabilities in your tech stack.",
    category: "Privacy Protection"
  },
  "Missing Automatic HTTPS Forwarding": {
    name: "Missing Automatic HTTPS Forwarding",
    problem: "Visitors opening your website via unencrypted http:// are not automatically redirected to secure https://.",
    why: "Unencrypted traffic can be intercepted, exposed, or modified by attackers on local networks.",
    category: "Encryption"
  },
  "Wildcard SSL Certificate": {
    name: "Broad Subdomain Certificate Scope",
    problem: "Your site uses a wildcard SSL certificate (*.yourdomain.com).",
    why: "If any single sub-domain server is compromised, the private key can be used to intercept traffic across all subdomains.",
    category: "Encryption"
  },
  "Directory Listing Enabled": {
    name: "Exposed Website Files",
    problem: "Anyone can browse the files and folders on your web server.",
    why: "Attackers can download source code, backup files, or sensitive documents that were not meant for public viewing.",
    category: "Privacy Protection"
  },
  "Wildcard CORS Policy": {
    name: "Permissive CORS Policy",
    problem: "Your API allows cross-origin requests from any domain using a wildcard origin.",
    why: "Malicious external websites can make authenticated API requests on behalf of logged-in users and exfiltrate private session data.",
    category: "Session Security"
  },
  "Weak TLS Cipher Negotiated": {
    name: "Weak TLS Cipher",
    problem: "Your server negotiates weak or obsolete TLS ciphers.",
    why: "Deprecated ciphers allow attackers performing Man-in-the-Middle (MitM) network eavesdropping to decrypt confidential user traffic.",
    category: "Encryption"
  },
  "Insecure or Obsolete TLS Ciphers Enforced": {
    name: "Obsolete TLS Ciphers Enforced",
    problem: "Your server enforces deprecated legacy TLS ciphers or protocols.",
    why: "Deprecated ciphers allow attackers performing Man-in-the-Middle (MitM) network eavesdropping to decrypt confidential user traffic.",
    category: "Encryption"
  },
  "Legacy Weak TLS Ciphers Supported": {
    name: "Legacy Weak TLS Ciphers Supported",
    problem: "Server accepts connections configured with deprecated weak ciphers (e.g. 3DES / RC4).",
    why: "Deprecated ciphers allow attackers performing Man-in-the-Middle (MitM) network eavesdropping to decrypt confidential user traffic.",
    category: "Encryption"
  },
  "Missing HTTPS Redirection": {
    name: "Missing HTTPS Redirection",
    problem: "Your website does not redirect visitors from unencrypted HTTP to secure HTTPS.",
    why: "Unencrypted HTTP traffic can be intercepted by eavesdroppers on public networks, exposing passwords, cookies, and sensitive user data.",
    category: "Encryption"
  },
  "SSL/TLS Connection Failure": {
    name: "SSL/TLS Connection Failure",
    problem: "Your server's SSL/TLS certificate is invalid, expired, or the secure handshake is failing.",
    why: "Browsers display severe security warnings or block access entirely, destroying user trust and preventing secure data transmission.",
    category: "Encryption"
  }
};
