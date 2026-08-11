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
    problem: "The scanner checked if your website strictly requires all visitors to use a secure connection and found this requirement is missing.",
    why: "If a customer types your web address without \"https\", they may connect over an unencrypted channel. This increases the risk that someone on the same network could read their data."
  },
  "Missing Strict-Transport-Security (HSTS)": {
    name: "Missing Forced Encryption (HSTS)",
    category: "Encryption",
    impact: "High",
    problem: "The scanner checked if your website strictly requires all visitors to use a secure connection and found this requirement is missing.",
    why: "If a customer types your web address without \"https\", they may connect over an unencrypted channel. This increases the risk that someone on the same network could read their data."
  },
  "Missing Content-Security-Policy (CSP)": {
    name: "Weak Data Injection Guard (CSP)",
    category: "Browser Protection",
    impact: "High",
    problem: "The scanner checked your website's rules for loading programs and found it does not have strict policies to block unauthorized scripts from running.",
    why: "Without strict rules, there is an increased risk that malicious code could be sneaked onto your web pages, which could potentially be used to view or steal visitor information."
  },
  "Weak Content-Security-Policy (CSP)": {
    name: "Weak Data Injection Guard (CSP)",
    category: "Browser Protection",
    impact: "Medium",
    problem: "The scanner checked your website's rules for loading programs and found they are too permissive.",
    why: "Relaxed rules increase the risk that malicious code could be allowed to run on your web pages, which could potentially be used to view or steal visitor information."
  },
  "Missing X-Frame-Options": {
    name: "Missing Clickjacking Protection (X-Frame-Options)",
    category: "Browser Protection",
    impact: "Medium",
    problem: "The scanner verified whether your website has rules preventing other websites from embedding your pages inside hidden frames, and found these rules are missing.",
    why: "Without this protection, another website could secretly place your web pages behind invisible buttons. This may trick visitors into interacting with your site without realizing it."
  },
  "Missing X-Frame-Options Header": {
    name: "Missing Clickjacking Protection (X-Frame-Options)",
    category: "Browser Protection",
    impact: "Medium",
    problem: "The scanner verified whether your website has rules preventing other websites from embedding your pages inside hidden frames, and found these rules are missing.",
    why: "Without this protection, another website could secretly place your web pages behind invisible buttons. This may trick visitors into interacting with your site without realizing it."
  },
  "Missing X-Content-Type-Options": {
    name: "Missing Malicious File Guard (nosniff)",
    category: "Browser Protection",
    impact: "Low",
    problem: "The scanner detected that your server does not explicitly tell web browsers to strictly trust the file types it sends.",
    why: "If the browser tries to guess a file's format, it may accidentally run a harmful program disguised as a normal image or document."
  },
  "Missing Referrer-Policy": {
    name: "Missing External Link Privacy (Referrer-Policy)",
    category: "Privacy Protection",
    impact: "Low",
    problem: "The scanner found that your website does not control what details are shared when visitors click a link leading to an outside website.",
    why: "Sensitive details or private page addresses could unintentionally be shared with external tracking companies or other websites when users leave your site."
  },
  "Missing Permissions-Policy": {
    name: "Unrestricted Browser Capabilities (Permissions-Policy)",
    category: "Privacy Protection",
    impact: "Low",
    problem: "The scanner noted that your website does not set strict rules about who can request access to a visitor's device features, like their camera or location.",
    why: "If your site loads third-party tools or ads, those tools could potentially request access to the visitor's device features without your direct oversight."
  },
  "Missing Cross-Origin-Opener-Policy": {
    name: "Missing Cross-Window Isolation (COOP)",
    category: "Browser Protection",
    impact: "Informational",
    problem: "The scanner found that your website shares its working memory space with external links that open in new tabs.",
    why: "If a user clicks a link on your site that opens a malicious page in a new tab, that malicious page could potentially monitor what the user is doing on your website."
  },
  "Missing Cross-Origin-Embedder-Policy": {
    name: "Missing Cross-Origin Resource Isolation (COEP)",
    category: "Browser Protection",
    impact: "Informational",
    problem: "The scanner checked your media sharing rules and found that your website loads external files without requiring strict permission checks.",
    why: "This prevents modern web browsers from isolating your website's data, which may leave user information exposed to advanced data leaks."
  },
  "Missing Cross-Origin-Resource-Policy": {
    name: "Unprotected Cross-Origin Assets (CORP)",
    category: "Privacy Protection",
    impact: "Informational",
    problem: "The scanner found that your web server does not explicitly restrict which external websites are allowed to display your site's images and files.",
    why: "Other websites could potentially display your private media or files directly on their own pages without your authorization."
  },
  "Missing SPF Record": {
    name: "Missing Email Anti-Spoofing (SPF)",
    category: "Email Trust",
    impact: "Medium",
    problem: "The scanner checked your domain records and found you do not have an official list of approved email senders for your company.",
    why: "Without this list, it is easier for unauthorized people to send fake emails that look like they came from your company, which increases the risk of scams targeting your customers."
  },
  "Missing DMARC Policy": {
    name: "Inactive Email Phishing Defense (DMARC)",
    category: "Email Trust",
    impact: "Medium",
    problem: "The scanner detected that your domain does not instruct email providers on what to do if they receive fake emails pretending to be from you.",
    why: "Email providers may still deliver fake emails claiming to be your business to your customers' inboxes instead of automatically blocking them."
  },
  "Weak DMARC Policy (p=none)": {
    name: "Inactive Email Phishing Defense (DMARC)",
    category: "Email Trust",
    impact: "Informational",
    problem: "The scanner found that your domain's email verification is set to 'monitoring only' mode.",
    why: "While monitoring is helpful, email providers will still deliver fake emails claiming to be your business to your customers' inboxes instead of blocking them."
  },
  "Missing DNS CAA Record": {
    name: "Missing Certificate Authority Lock (CAA)",
    category: "Domain Trust",
    impact: "Low",
    problem: "The scanner found that your domain name lacks a digital lock that controls which security companies are allowed to issue trust certificates for your website.",
    why: "An unauthorized person could potentially trick a random security company into issuing a valid certificate for your website, which may help them create a convincing fake version of your business."
  },
  "Missing security.txt": {
    name: "Missing Vulnerability Disclosure Contact (security.txt)",
    category: "Website Trust",
    impact: "Informational",
    problem: "The scanner looked for a standard security contact file on your website but could not find one.",
    why: "If a friendly researcher discovers a flaw in your website, they may not have an official, clear way to privately report it to your team."
  },
  "Missing HttpOnly Flag on Cookie": {
    name: "Unsecured Session Cookie (HttpOnly)",
    category: "Session Security",
    impact: "Medium",
    problem: "The scanner found that the digital ID badges (cookies) your website gives to users are not locked away from browser scripts.",
    why: "If harmful code is ever sneaked onto your website, it could potentially read these digital ID badges and access your customers' accounts."
  },
  "Missing Secure Flag on Cookie": {
    name: "Unencrypted Cookie Transmission (Secure Flag)",
    category: "Session Security",
    impact: "Medium",
    problem: "The scanner detected that the digital ID badges (cookies) used to recognize users could be sent over unencrypted connections.",
    why: "If a user connects to a public network, their digital ID badge could potentially be intercepted and misused."
  },
  "Missing SameSite Attribute on Cookie": {
    name: "Unprotected Cross-Site Cookie (SameSite)",
    category: "Session Security",
    impact: "Low",
    problem: "The scanner found that your website does not restrict its digital ID badges (cookies) from being used by other websites.",
    why: "If a logged-in customer visits a malicious website, that site could potentially send commands to your website on the customer's behalf without their knowledge."
  },
  "Exposed Server Header": {
    name: "Exposed Web Server Technology",
    category: "Privacy Protection",
    impact: "Informational",
    problem: "The scanner received technical responses from your server that openly advertise the exact brand and version of the software running your website.",
    why: "Revealing your exact software version gives outsiders a convenient blueprint of your systems, making it easier for them to look up known weaknesses for that specific software."
  },
  "Exposed X-Powered-By Header": {
    name: "Exposed Web Server Technology",
    category: "Privacy Protection",
    impact: "Informational",
    problem: "The scanner received technical responses from your server that openly advertise the exact underlying technology running your website.",
    why: "Revealing your exact software version gives outsiders a convenient blueprint of your systems, making it easier for them to look up known weaknesses for that specific software."
  },
  "X-Powered-By Header Exposed": {
    name: "X-Powered-By Header Exposed",
    category: "Privacy Protection",
    impact: "Informational",
    problem: "The scanner received technical responses from your server that openly advertise the exact underlying technology running your website.",
    why: "Revealing your exact software version gives outsiders a convenient blueprint of your systems, making it easier for them to look up known weaknesses for that specific software."
  },
  "Missing Automatic HTTPS Forwarding": {
    name: "Missing Automatic HTTPS Forwarding",
    category: "Encryption",
    impact: "High",
    problem: "The scanner tried to visit the unsecure version of your website and found that it does not automatically redirect to the secure version.",
    why: "Visitors might end up browsing your site over an unencrypted connection. Any information they submit could potentially be intercepted by someone on the same network."
  },
  "Wildcard SSL Certificate": {
    name: "Broad Subdomain Certificate Scope",
    category: "Encryption",
    impact: "Informational",
    problem: "The scanner found that your website uses a single master security key that is valid for every possible sub-section of your domain.",
    why: "While convenient, if one minor section of your company's network is compromised, that master key could potentially be used to intercept secure traffic across your entire business."
  },
  "Directory Listing Enabled": {
    name: "Exposed Website Files",
    category: "Privacy Protection",
    impact: "High",
    problem: "The scanner found a folder on your web server that openly lists all the files inside it to the public.",
    why: "Anyone can casually browse through your server's files. They may discover private backup files, business documents, or internal code that was not meant to be public."
  },
  "Wildcard CORS Policy": {
    name: "Permissive CORS Policy",
    category: "Session Security",
    impact: "High",
    problem: "The scanner checked your data-sharing rules and found that your website openly allows any other website on the internet to read your data.",
    why: "If your website holds private customer data, malicious websites may be able to ask for that data on behalf of a logged-in user, which increases the risk of a privacy breach."
  },
  "Weak TLS Cipher Negotiated": {
    name: "Weak TLS Cipher",
    category: "Encryption",
    impact: "Medium",
    problem: "The scanner tested your server's connection rules and found that it accepts outdated, weak encryption methods.",
    why: "Modern computers can often decipher these older encryption methods. If the connection is intercepted, the data may no longer be secure."
  },
  "Insecure or Obsolete TLS Ciphers Enforced": {
    name: "Obsolete TLS Ciphers Enforced",
    category: "Encryption",
    impact: "High",
    problem: "The scanner found that your server actively prioritizes obsolete encryption methods instead of modern, secure ones.",
    why: "By favoring older encryption methods, your customers' data may be inadequately protected during transit, increasing the risk of interception."
  },
  "Legacy Weak TLS Ciphers Supported": {
    name: "Legacy Weak TLS Ciphers Supported",
    category: "Encryption",
    impact: "Medium",
    problem: "The scanner found that your server still supports deprecated weak encryption methods for older devices.",
    why: "Keeping old encryption methods enabled increases the risk that modern attackers could decipher the information being sent between your website and your visitors."
  },
  "Missing HTTPS Redirection": {
    name: "Missing HTTPS Redirection",
    category: "Encryption",
    impact: "High",
    problem: "The scanner tried to visit the unsecure version of your website and found that it does not automatically redirect to the secure version.",
    why: "Visitors might end up browsing your site over an unencrypted connection. Any information they submit could potentially be intercepted by someone on the same network."
  },
  "SSL/TLS Connection Failure": {
    name: "SSL/TLS Connection Failure",
    category: "Encryption",
    impact: "High",
    problem: "The scanner attempted to securely connect to your website but the connection failed, usually because the security certificate is expired or improperly installed.",
    why: "Web browsers may display a warning screen to your visitors telling them your site is not secure. This can impact customer trust and prevent them from reaching your site."
  },
  "Open Port Detected": {
    name: "Unexpected Port Open",
    category: "Network Services",
    impact: "Informational",
    problem: "The scanner discovered an unexpected digital door (port) open on your server facing the public internet.",
    why: "Every open door is a potential entry point into your systems. Having unnecessary open doors increases the attack surface of your server."
  },
  "SMTP Service Exposed": {
    name: "Mail Server Exposed",
    category: "Network Services",
    impact: "Informational",
    problem: "The scanner found that the service your server uses to process emails is directly accessible to the public internet.",
    why: "Exposed email servers are frequently targeted by automated tools. This increases the risk that your server could be misused to send spam or accessed without authorization."
  },
  "FTP Service Exposed": {
    name: "Unencrypted File Transfer (FTP)",
    category: "Network Services",
    impact: "Informational",
    problem: "The scanner discovered an unencrypted file transfer service running publicly on your server.",
    why: "This service sends files and passwords without encryption. Anyone monitoring the network could potentially see your login credentials and gain access to your website's files."
  },
  "SSH Service Exposed": {
    name: "Remote Management Exposed (SSH)",
    category: "Network Services",
    impact: "Informational",
    problem: "The scanner found that the remote management portal for your server is visible to the entire internet.",
    why: "Automated tools frequently attempt to guess passwords on exposed management portals. If they guess correctly, they could gain unauthorized control over your server."
  },
  "Telnet Service Exposed": {
    name: "Obsolete Remote Access (Telnet)",
    category: "Network Services",
    impact: "Informational",
    problem: "The scanner detected an outdated, unencrypted remote access service running on your server.",
    why: "This service does not use encryption. Passwords and commands sent over this connection could be intercepted by someone monitoring the network."
  },
  "Database Service Exposed": {
    name: "Database Directly Exposed",
    category: "Network Services",
    impact: "Informational",
    problem: "The scanner found that your business database is directly exposed to the public internet.",
    why: "Databases hold sensitive information and should typically only communicate with your web server. Exposing them to the internet increases the risk of unauthorized access or data theft."
  },
  "HTTP Service Exposed": {
    name: "Unencrypted Web Port (HTTP)",
    category: "Network Services",
    impact: "Informational",
    problem: "The scanner detected an unencrypted web service running on your server.",
    why: "If this service doesn't immediately redirect visitors to a secure connection, any customer who happens to use it may be sending their data unprotected over the network."
  }
};
