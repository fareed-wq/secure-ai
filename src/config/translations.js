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
  },
  "Network Services": { 
    title: "Network & Port Security", 
    icon: "Activity", 
    description: "Detection of exposed administrative ports, databases, and unencrypted network services." 
  }
};

export const TRANSLATIONS = {
  "CSP Missing Default Source Fallback": {
    name: "CSP Missing Default Source Fallback",
    category: "Browser Protection",
    impact: "Low",
    problem: "Your website restricts some resources but lacks a default-src fallback to cover unspecified resource types.",
    why: "While explicitly configured individual directives are valid, missing default-src is not automatically an XSS vulnerability, but it weakens defense-in-depth."
  },
  "CSP Object Sources Not Restricted": {
    name: "CSP Object Sources Not Restricted",
    category: "Browser Protection",
    impact: "Low",
    problem: "Your website does not explicitly restrict object sources.",
    why: "Explicitly restricting object-src reduces unnecessary executable or embed attack surfaces via <object> and <embed> tags."
  },

  "Port 21 Publicly Reachable (FTP-associated)": {
    name: "Port 21 Publicly Reachable (FTP-associated)",
    category: "Network Services",
    problem: "TCP port 21, commonly associated with FTP, is publicly reachable.",
    why: "If FTP is actually running, its exposure should be reviewed. It may allow unauthorized access or brute-force attacks if not properly secured."
  },
  "Port 22 Publicly Reachable (SSH-associated)": {
    name: "Port 22 Publicly Reachable (SSH-associated)",
    category: "Network Services",
    problem: "TCP port 22, commonly associated with SSH, is publicly reachable.",
    why: "If SSH is actually running, public management exposure increases the attack surface, though SSH itself is not automatically vulnerable."
  },
  "Port 23 Publicly Reachable (Telnet-associated)": {
    name: "Port 23 Publicly Reachable (Telnet-associated)",
    category: "Network Services",
    problem: "TCP port 23 is commonly associated with Telnet, a legacy unencrypted protocol.",
    why: "If Telnet is actually running, public exposure should be avoided."
  },
  "Port 25 Publicly Reachable (SMTP-associated)": {
    name: "Port 25 Publicly Reachable (SMTP-associated)",
    category: "Network Services",
    problem: "TCP port 25, commonly associated with SMTP, is publicly reachable.",
    why: "If a mail service is actually running, public exposure may be intentional, but can be targeted by spammers or attackers if misconfigured."
  },
  "Database-Associated Port Publicly Reachable": {
    name: "Database-Associated Port Publicly Reachable",
    category: "Network Services",
    problem: "A TCP port commonly associated with a database is publicly reachable.",
    why: "If a database is actually running, direct Internet reachability should be reviewed and normally restricted when the database is intended to be private."
  },
  "Missing Strict-Transport-Security Header": {
    name: "Insecure Connection Fallback",
    category: "Encryption",
    impact: "High",
    problem: "The scanner checked if your website strictly forces secure connections and found this rule is missing.",
    why: "Without this, visitors might accidentally connect insecurely, allowing eavesdroppers to read their private data."
  },
  "Missing Strict-Transport-Security (HSTS)": {
    name: "Missing Forced Encryption (HSTS)",
    category: "Encryption",
    impact: "High",
    problem: "The scanner checked if your website strictly forces secure connections and found this rule is missing.",
    why: "Without this, visitors might accidentally connect insecurely, allowing eavesdroppers to read their private data."
  },
  "Missing Content-Security-Policy (CSP)": {
    name: "Weak Data Injection Guard (CSP)",
    category: "Browser Protection",
    impact: "High",
    problem: "The scanner found your website lacks strict policies to block unauthorized scripts from running.",
    why: "Hackers could sneak malicious code onto your web pages to view or steal visitor information."
  },
  "Weak Content-Security-Policy (CSP)": {
    name: "Weak Data Injection Guard (CSP)",
    category: "Browser Protection",
    impact: "Medium",
    problem: "The scanner checked your website's rules for loading scripts and found them to be too permissive.",
    why: "Loose rules increase the risk of malicious code running and stealing private visitor information."
  },
  "Missing Clickjacking Protection": {
    name: "Missing Clickjacking Protection",
    category: "Browser Protection",
    impact: "Medium",
    problem: "The scanner found your website lacks clickjacking protections such as X-Frame-Options or CSP frame-ancestors.",
    why: "Another site could place your pages behind invisible buttons to trick visitors into unwanted actions."
  },
  "Missing or Invalid X-Content-Type-Options": {
    name: "Missing MIME Sniffing Protection",
    category: "Browser Protection",
    impact: "Low",
    problem: "The scanner detected your server doesn't securely configure X-Content-Type-Options: nosniff.",
    why: "Browsers might misidentify files, accidentally running scripts hidden in normal images or documents."
  },
  "Missing Referrer-Policy": {
    name: "Missing External Link Privacy (Referrer-Policy)",
    category: "Privacy Protection",
    impact: "Low",
    problem: "The scanner found your website shares excessive details when visitors click links to outside websites.",
    why: "Private page addresses or sensitive details could be unintentionally leaked to external tracking companies."
  },
  "Missing Permissions-Policy": {
    name: "Unrestricted Browser Capabilities (Permissions-Policy)",
    category: "Privacy Protection",
    impact: "Low",
    problem: "The scanner noted your website doesn't restrict external tools from requesting device camera or location access.",
    why: "Third-party ads or widgets could potentially ask for a visitor's device features without your oversight."
  },
  "COOP Not Configured": {
    name: "COOP Not Configured",
    category: "Browser Protection",
    impact: "Informational",
    problem: "The scanner observed your website does not enforce Cross-Origin Opener Policy (COOP).",
    why: "COOP provides advanced browsing-context isolation where stronger cross-origin isolation is required, though it is not strictly necessary for ordinary sites."
  },
  "COEP Not Configured": {
    name: "COEP Not Configured",
    category: "Browser Protection",
    impact: "Informational",
    problem: "The scanner observed your website does not enforce Cross-Origin Embedder Policy (COEP).",
    why: "COEP is an advanced browser hardening feature that restricts third-party embeds. It is not universally appropriate for standard websites."
  },
  "Missing Cross-Origin-Resource-Policy": {
    name: "Unprotected Cross-Origin Assets (CORP)",
    category: "Privacy Protection",
    impact: "Informational",
    problem: "The scanner found your server doesn't restrict external websites from displaying your site's images directly.",
    why: "Other websites could potentially display your private media or files directly without authorization."
  },
  "Missing SPF Record": {
    name: "Missing Email Anti-Spoofing (SPF)",
    category: "Email Trust",
    impact: "Medium",
    problem: "The scanner checked your domain and found you lack an official list of approved email senders.",
    why: "Scammers can easily forge emails claiming to be your company, targeting your customers with scams."
  },
  "Missing DMARC Policy": {
    name: "Inactive Email Phishing Defense (DMARC)",
    category: "Email Trust",
    impact: "Medium",
    problem: "The scanner detected your domain doesn't instruct email providers to block fake emails impersonating you.",
    why: "Email providers might deliver forged emails pretending to be your business to customers' inboxes."
  },
  "Weak DMARC Policy (p=none)": {
    name: "Inactive Email Phishing Defense (DMARC)",
    category: "Email Trust",
    impact: "Informational",
    problem: "The scanner found your domain's email verification is currently set to a 'monitoring only' mode.",
    why: "While helpful, email providers will still deliver forged emails claiming to be your business."
  },
  "Missing DNS CAA Record": {
    name: "Missing Certificate Authority Lock (CAA)",
    category: "Domain Trust",
    impact: "Low",
    problem: "The scanner found your domain lacks controls over which security companies can issue your certificates.",
    why: "Attackers could trick random security companies into issuing valid certificates for convincing fake websites."
  },
  "Missing security.txt": {
    name: "Missing Vulnerability Disclosure Contact (security.txt)",
    category: "Website Trust",
    impact: "Informational",
    problem: "The scanner looked for a standard security contact file on your website but found nothing.",
    why: "Friendly researchers discovering a flaw may not have a clear way to privately report it."
  },
  "Missing HttpOnly Flag on Cookie": {
    name: "Unsecured Session Cookie (HttpOnly)",
    category: "Session Security",
    impact: "Medium",
    problem: "The scanner found your website's digital ID cookies are not locked away from browser scripts.",
    why: "If malicious code sneaks onto your site, it could read these cookies and access accounts."
  },
  "Missing Secure Flag on Cookie": {
    name: "Unencrypted Cookie Transmission (Secure Flag)",
    category: "Session Security",
    impact: "Medium",
    problem: "The scanner detected digital ID cookies could be sent over unencrypted internet connections.",
    why: "On a public network, a user's digital ID badge could be intercepted and misused by attackers."
  },
  "Missing SameSite Attribute on Cookie": {
    name: "Unprotected Cross-Site Cookie (SameSite)",
    category: "Session Security",
    impact: "Low",
    problem: "The scanner found your website doesn't restrict its digital ID cookies from being used externally.",
    why: "A malicious website could potentially send commands to your website on a customer's behalf."
  },
  "Exposed Server Header": {
    name: "Exposed Web Server Technology",
    category: "Privacy Protection",
    impact: "Informational",
    problem: "The scanner received technical responses openly advertising the exact software running your website.",
    why: "Revealing specific software versions makes it easier for outsiders to look up known weaknesses."
  },
  "Exposed X-Powered-By Header": {
    name: "Exposed Web Server Technology",
    category: "Privacy Protection",
    impact: "Informational",
    problem: "The scanner received technical responses openly advertising the exact underlying technology running your website.",
    why: "Revealing specific software versions makes it easier for outsiders to look up known weaknesses."
  },
  "X-Powered-By Header Exposed": {
    name: "X-Powered-By Header Exposed",
    category: "Privacy Protection",
    impact: "Informational",
    problem: "The scanner received technical responses openly advertising the exact underlying technology running your website.",
    why: "Revealing specific software versions makes it easier for outsiders to look up known weaknesses."
  },
  "Missing Automatic HTTPS Forwarding": {
    name: "Missing Automatic HTTPS Forwarding",
    category: "Encryption",
    impact: "High",
    problem: "The scanner tried visiting the unsecure version of your website and found it doesn't automatically redirect.",
    why: "Visitors browsing over an unencrypted connection could have their sensitive information intercepted over public networks."
  },
  "Wildcard SSL Certificate": {
    name: "Broad Subdomain Certificate Scope",
    category: "Encryption",
    impact: "Informational",
    problem: "The scanner found your website uses a single master security key valid for every subdomain.",
    why: "If one minor section is compromised, that master key could intercept secure traffic across the business."
  },
  "Directory Listing Enabled": {
    name: "Exposed Website Files",
    category: "Privacy Protection",
    impact: "High",
    problem: "The scanner found a folder on your web server that openly lists its files publicly.",
    why: "Anyone could discover private backup files, business documents, or internal code meant to remain private."
  },
  "Wildcard CORS Policy": {
    name: "Permissive CORS Policy",
    category: "Session Security",
    impact: "High",
    problem: "The scanner found your website openly allows any other website to read your visitor data.",
    why: "Malicious websites could ask for private data on behalf of a logged-in user, causing privacy breaches."
  },
  "Weak TLS Cipher Negotiated": {
    name: "Weak TLS Cipher",
    category: "Encryption",
    impact: "Medium",
    problem: "The scanner tested your server's connection rules and found it accepts outdated, weak encryption methods.",
    why: "Modern computers can easily decipher these old methods. Intercepted connections may no longer be secure."
  },
  "Insecure or Obsolete TLS Ciphers Enforced": {
    name: "Obsolete TLS Ciphers Enforced",
    category: "Encryption",
    impact: "High",
    problem: "The scanner found your server actively prioritizes obsolete encryption methods over modern, secure ones.",
    why: "Favoring old encryption leaves your customers' data inadequately protected during transit, increasing interception risks."
  },
  "Legacy Weak TLS Ciphers Supported": {
    name: "Legacy Weak TLS Ciphers Supported",
    category: "Encryption",
    impact: "Medium",
    problem: "The scanner found your server still supports deprecated, weak encryption methods for older devices.",
    why: "Keeping old encryption enabled increases the risk that modern attackers could decipher your visitors' information."
  },
  "Missing HTTPS Redirection": {
    name: "Missing HTTPS Redirection",
    category: "Encryption",
    impact: "High",
    problem: "The scanner tried visiting the unsecure version of your website and found it doesn't automatically redirect.",
    why: "Visitors browsing over an unencrypted connection could have their sensitive information intercepted over public networks."
  },
  "SSL/TLS Connection Failure": {
    name: "SSL/TLS Connection Failure",
    category: "Encryption",
    impact: "High",
    problem: "The scanner failed to securely connect to your website, likely due to an expired certificate.",
    why: "Browsers may display severe warning screens, destroying customer trust and preventing access to your site."
  },
  "Open Port Detected": {
    name: "Unexpected Port Open",
    category: "Network Services",
    impact: "Informational",
    problem: "The scanner discovered an unexpected digital door (port) open on your server facing the internet.",
    why: "Every open door is a potential entry point, increasing the overall attack surface of your server."
  },
  "SMTP Service Exposed": {
    name: "Mail Server Exposed",
    category: "Network Services",
    impact: "Informational",
    problem: "The scanner found your server's email processing service is directly accessible to the public internet.",
    why: "Exposed email servers are heavily targeted by automated tools to send spam or gain unauthorized access."
  },
  "FTP Service Exposed": {
    name: "Unencrypted File Transfer (FTP)",
    category: "Network Services",
    impact: "Informational",
    problem: "The scanner discovered an unencrypted file transfer service running publicly on your web server.",
    why: "This service sends passwords without encryption, allowing network snoops to easily steal your login credentials."
  },
  "SSH Service Exposed": {
    name: "Remote Management Exposed (SSH)",
    category: "Network Services",
    impact: "Informational",
    problem: "The scanner found the remote management portal for your server is visible to the internet.",
    why: "Automated tools frequently attempt to guess passwords here to gain unauthorized control over your server."
  },
  "Telnet Service Exposed": {
    name: "Obsolete Remote Access (Telnet)",
    category: "Network Services",
    impact: "Informational",
    problem: "The scanner detected an outdated, entirely unencrypted remote access service running on your web server.",
    why: "Passwords and commands sent over this connection can easily be intercepted by anyone monitoring the network."
  },
  "Database Service Exposed": {
    name: "Database Directly Exposed",
    category: "Network Services",
    impact: "Informational",
    problem: "The scanner found your business database is directly exposed to the entire public internet.",
    why: "Exposing databases to the internet severely increases the risk of unauthorized access or data theft."
  },
  "HTTP Service Exposed": {
    name: "Unencrypted Web Port (HTTP)",
    category: "Network Services",
    impact: "Informational",
    problem: "The scanner detected a completely unencrypted web service port running directly on your main server.",
    why: "Any customer using this port without redirection sends their data completely unprotected over the network."
  },
  "Missing crossorigin for SRI Resource": {
    name: "Missing crossorigin for SRI Resource",
    category: "Browser Protection",
    impact: "Low",
    problem: "A third-party script uses SRI but is missing a valid CORS mode attribute like crossorigin='anonymous'.",
    why: "The browser requires CORS to verify SRI hashes for third-party scripts. Without it, the script might fail to load."
  },
  "Malformed Subresource Integrity (SRI) Attribute": {
    name: "Malformed SRI Hash",
    category: "Browser Protection",
    impact: "Low",
    problem: "The integrity attribute on an external resource does not contain valid SRI metadata.",
    why: "The browser may reject the resource because its integrity information cannot be validated correctly."
  },
  "Missing Subresource Integrity": {
    name: "Missing Subresource Integrity",
    category: "Browser Protection",
    impact: "Informational",
    problem: "An externally hosted script was loaded without Subresource Integrity (SRI).",
    why: "SRI protects stable third-party resources against unexpected modification, but it is not practical for resources that change dynamically."
  }
};
