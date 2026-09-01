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
  "Missing X-Frame-Options": {
    name: "Missing Clickjacking Protection (X-Frame-Options)",
    category: "Browser Protection",
    impact: "Medium",
    problem: "The scanner found your website lacks rules stopping others from embedding your pages inside hidden frames.",
    why: "Another site could place your pages behind invisible buttons to trick visitors into unwanted actions."
  },
  "Missing X-Frame-Options Header": {
    name: "Missing Clickjacking Protection (X-Frame-Options)",
    category: "Browser Protection",
    impact: "Medium",
    problem: "The scanner found your website lacks rules stopping others from embedding your pages inside hidden frames.",
    why: "Another site could place your pages behind invisible buttons to trick visitors into unwanted actions."
  },
  "Missing X-Content-Type-Options": {
    name: "Missing Malicious File Guard (nosniff)",
    category: "Browser Protection",
    impact: "Low",
    problem: "The scanner detected your server doesn't tell browsers to strictly trust the file types it sends.",
    why: "Browsers might misidentify files, accidentally running harmful programs disguised as normal images or documents."
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
  "Missing Cross-Origin-Opener-Policy": {
    name: "Missing Cross-Window Isolation (COOP)",
    category: "Browser Protection",
    impact: "Informational",
    problem: "The scanner found your website shares its working memory with external links opening in new tabs.",
    why: "A malicious page opened from a link on your site could potentially monitor user activity."
  },
  "Missing Cross-Origin-Embedder-Policy": {
    name: "Missing Cross-Origin Resource Isolation (COEP)",
    category: "Browser Protection",
    impact: "Informational",
    problem: "The scanner found your website loads external files without requiring strict permission safety checks.",
    why: "This prevents web browsers from isolating your site's memory, potentially exposing user data to leaks."
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
  "Missing Cross-Origin Attribute for SRI Verification": {
    name: "Missing Cross-Origin Attribute (SRI)",
    category: "Browser Protection",
    impact: "Low",
    problem: "A cross-origin resource using Subresource Integrity may require compatible cross-origin fetching so the browser can successfully perform integrity verification.",
    why: "The external resource may fail integrity validation/loading depending on the resource and CORS configuration."
  },
  "Malformed Subresource Integrity (SRI) Attribute": {
    name: "Malformed SRI Hash",
    category: "Browser Protection",
    impact: "Low",
    problem: "The integrity attribute on an external resource does not contain valid SRI metadata.",
    why: "The browser may reject the resource because its integrity information cannot be validated correctly."
  },
  "Missing Subresource Integrity (SRI) on Third-Party Asset": {
    name: "Missing Subresource Integrity (SRI)",
    category: "Browser Protection",
    problem: "The page loads a static third-party script or supported external asset without cryptographically verifying its contents.",
    why: "If that third-party hosted resource or delivery path is compromised, modified code could be delivered to site visitors."
  }
};
