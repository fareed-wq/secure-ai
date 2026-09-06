export const REMEDIATION_SNIPPETS = {
  // 1. Weak Ciphers / Legacy TLS
  "Legacy Weak TLS Ciphers Supported": [
    {
      platform: "Nginx",
      code: `ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\nssl_prefer_server_ciphers off;`,
      notes: "Update your /etc/nginx/sites-available/default configuration."
    },
    {
      platform: "Apache",
      code: `SSLProtocol -all +TLSv1.2 +TLSv1.3\nSSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!RC4\nSSLHonorCipherOrder off`,
      notes: "Add to /etc/apache2/mods-available/ssl.conf"
    },
    {
      platform: "Cloudflare",
      code: `1. Go to Cloudflare Dashboard -> SSL/TLS -> Edge Certificates\n2. Set 'Minimum TLS Version' to 'TLS 1.2'\n3. Enable 'TLS 1.3' toggle.`,
      notes: "No code changes required on server."
    }
  ],

  // 2. COOP Not Configured
  "COOP Not Configured": [
    {
      platform: "Nginx",
      code: `add_header Cross-Origin-Opener-Policy "same-origin" always;`,
      notes: "Place inside server {} or location {} block."
    },
    {
      platform: "Apache",
      code: `Header always set Cross-Origin-Opener-Policy "same-origin"`,
      notes: "Requires mod_headers to be enabled."
    },
    {
      platform: "Vercel / Next.js",
      code: `// next.config.js\nmodule.exports = {\n  async headers() {\n    return [\n      {\n        source: '/(:path*)',\n        headers: [\n          { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' }\n        ]\n      }\n    ]\n  }\n}`,
      notes: "Add to your Next.js config file."
    },
    {
      platform: "Cloudflare",
      code: `1. Go to Rules -> Transform Rules -> Modify Response Header\n2. Create Rule: Set Header 'Cross-Origin-Opener-Policy' = 'same-origin'`,
      notes: "Applies instantly at edge."
    }
  ],

  // 3. COEP Not Configured
  "COEP Not Configured": [
    {
      platform: "Nginx",
      code: `add_header Cross-Origin-Embedder-Policy "require-corp" always;`
    },
    {
      platform: "Apache",
      code: `Header always set Cross-Origin-Embedder-Policy "require-corp"`
    },
    {
      platform: "Vercel / Next.js",
      code: `// next.config.js\n{ key: 'Cross-Origin-Embedder-Policy', value: 'require-corp' }`
    }
  ],

  // 4. Missing CORP Header
  "Missing CORP Header": [
    {
      platform: "Nginx",
      code: `add_header Cross-Origin-Resource-Policy "same-origin" always;`
    },
    {
      platform: "Apache",
      code: `Header always set Cross-Origin-Resource-Policy "same-origin"`
    },
    {
      platform: "Vercel / Next.js",
      code: `// next.config.js\n{ key: 'Cross-Origin-Resource-Policy', value: 'same-origin' }`
    }
  ],

  // 5. Server Header Exposed
  "Server Header Exposed": [
    {
      platform: "Nginx",
      code: `# Inside /etc/nginx/nginx.conf\nhttp {\n    server_tokens off;\n}`,
      notes: "Hides Nginx version number from response headers."
    },
    {
      platform: "Apache",
      code: `# Inside apache2.conf\nServerTokens Prod\nServerSignature Off`,
      notes: "Hides Apache OS and module versions."
    },
    {
      platform: "Vercel / Next.js",
      code: `// next.config.js\nmodule.exports = {\n  poweredByHeader: false,\n}`,
      notes: "Removes X-Powered-By: Next.js header."
    }
  ],

  // 6. Missing Content-Security-Policy (CSP)
  "Missing Content-Security-Policy (CSP)": [
    {
      platform: "Nginx",
      code: `add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;" always;`
    },
    {
      platform: "Apache",
      code: `Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"`
    },
    {
      platform: "Vercel / Next.js",
      code: `// next.config.js\n{ key: 'Content-Security-Policy', value: "default-src 'self'; img-src 'self' data: https:;" }`
    }
  ],

  // 7. Missing HSTS
  "Missing Strict-Transport-Security (HSTS)": [
    {
      platform: "Nginx",
      code: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`
    },
    {
      platform: "Apache",
      code: `Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`
    },
    {
      platform: "Vercel / Next.js",
      code: `// next.config.js\n{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' }`
    },
    {
      platform: "Cloudflare",
      code: `1. Dashboard -> SSL/TLS -> Edge Certificates\n2. Scroll to 'HTTP Strict Transport Security (HSTS)'\n3. Enable and set max-age to 12 months, include subdomains.`
    }
  ],

  // 8. Missing Clickjacking Protection
  "Missing Clickjacking Protection": [
    {
      platform: "Nginx",
      code: `add_header X-Frame-Options "SAMEORIGIN" always;`
    },
    {
      platform: "Apache",
      code: `Header always set X-Frame-Options "SAMEORIGIN"`
    },
    {
      platform: "Vercel / Next.js",
      code: `// next.config.js\n{ key: 'X-Frame-Options', value: 'SAMEORIGIN' }`
    }
  ],

  // 9. Missing or Invalid X-Content-Type-Options
  "Missing or Invalid X-Content-Type-Options": [
    {
      platform: "Nginx",
      code: `add_header X-Content-Type-Options "nosniff" always;`
    },
    {
      platform: "Apache",
      code: `Header always set X-Content-Type-Options "nosniff"`
    },
    {
      platform: "Vercel / Next.js",
      code: `// next.config.js\n{ key: 'X-Content-Type-Options', value: 'nosniff' }`
    }
  ],

  // 10. Missing Referrer-Policy
  "Missing Referrer-Policy": [
    {
      platform: "Nginx",
      code: `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`
    },
    {
      platform: "Apache",
      code: `Header always set Referrer-Policy "strict-origin-when-cross-origin"`
    },
    {
      platform: "Vercel / Next.js",
      code: `// next.config.js\n{ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }`
    }
  ],

  // 11. Missing Permissions-Policy
  "Missing Permissions-Policy": [
    {
      platform: "Nginx",
      code: `add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;`
    },
    {
      platform: "Apache",
      code: `Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"`
    },
    {
      platform: "Vercel / Next.js",
      code: `// next.config.js\n{ key: 'Permissions-Policy', value: 'geolocation=(), microphone=(), camera=()' }`
    }
  ],

  // 11b. Additional Security Headers
  "Missing X-Permitted-Cross-Domain-Policies": [
    {
      platform: "Nginx",
      code: `add_header X-Permitted-Cross-Domain-Policies "none" always;`
    },
    {
      platform: "Apache",
      code: `Header always set X-Permitted-Cross-Domain-Policies "none"`
    },
    {
      platform: "Vercel / Next.js",
      code: `// next.config.js\n{ key: 'X-Permitted-Cross-Domain-Policies', value: 'none' }`
    }
  ],
  "Missing X-DNS-Prefetch-Control": [
    {
      platform: "Nginx",
      code: `add_header X-DNS-Prefetch-Control "off" always;`
    },
    {
      platform: "Apache",
      code: `Header always set X-DNS-Prefetch-Control "off"`
    },
    {
      platform: "Vercel / Next.js",
      code: `// next.config.js\n{ key: 'X-DNS-Prefetch-Control', value: 'off' }`
    }
  ],

  // 12. SPF & DMARC Records
  "Missing SPF Record": [
    {
      platform: "DNS TXT Record",
      code: `Name/Host: @\nValue: v=spf1 include:_spf.google.com ~all\nTTL: 3600`,
      notes: "Adjust include statements for your actual email providers (e.g. Google, Outlook, SendGrid)."
    }
  ],
  "Missing DMARC Policy": [
    {
      platform: "DNS TXT Record",
      code: `Name/Host: _dmarc\nValue: v=DMARC1; p=quarantine; rua=mailto:postmaster@yourdomain.com;\nTTL: 3600`,
      notes: "Start with p=quarantine or p=none to monitor, then move to p=reject."
    }
  ],
  "Weak DMARC Policy (p=none)": [
    {
      platform: "DNS TXT Record",
      code: `Name/Host: _dmarc\nValue: v=DMARC1; p=quarantine; rua=mailto:postmaster@yourdomain.com;\nTTL: 3600`,
      notes: "Update your existing p=none policy to p=quarantine or p=reject to enforce spoofing protection."
    }
  ],

  // 13. Information Disclosure
  "X-Powered-By Header Exposed": [
    {
      platform: "Express.js",
      code: `app.disable('x-powered-by');`
    },
    {
      platform: "PHP",
      code: `; php.ini\nexpose_php = Off`
    },
    {
      platform: "Vercel / Next.js",
      code: `// next.config.js\nmodule.exports = {\n  poweredByHeader: false,\n}`
    }
  ],

  // 14. Missing Basic Files
  "security.txt Missing": [
    {
      platform: "File Creation",
      code: `# Create /.well-known/security.txt\nContact: mailto:security@yourdomain.com\nExpires: 2026-12-31T23:59:00.000Z\nPreferred-Languages: en`,
      notes: "Upload this file to the /.well-known/ folder at the root of your web server."
    }
  ],
  "robots.txt Missing": [
    {
      platform: "File Creation",
      code: `# Create robots.txt at root\nUser-agent: *\nDisallow: /admin/\nSitemap: https://yourdomain.com/sitemap.xml`
    }
  ],
  "sitemap.xml Missing": [
    {
      platform: "File Creation",
      code: `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url>\n    <loc>https://yourdomain.com/</loc>\n  </url>\n</urlset>`
    }
  ],

  // 15. Advanced Cookies
  "Cookie Missing Secure Flag": [
    {
      platform: "Nginx (Proxy)",
      code: `proxy_cookie_path / "/; HTTPOnly; Secure";`
    },
    {
      platform: "Node.js (Express)",
      code: `res.cookie('session', 'value', { secure: true });`
    },
    {
      platform: "PHP",
      code: `session_set_cookie_params(['secure' => true]);`
    }
  ],
  "Cookie Missing HttpOnly Flag": [
    {
      platform: "Nginx (Proxy)",
      code: `proxy_cookie_path / "/; HTTPOnly; Secure";`
    },
    {
      platform: "Node.js (Express)",
      code: `res.cookie('session', 'value', { httpOnly: true });`
    },
    {
      platform: "PHP",
      code: `session_set_cookie_params(['httponly' => true]);`
    }
  ],
  "Cookie Missing SameSite Attribute": [
    {
      platform: "Node.js (Express)",
      code: `res.cookie('session', 'value', { sameSite: 'strict' });`
    },
    {
      platform: "PHP",
      code: `session_set_cookie_params(['samesite' => 'Strict']);`
    }
  ],

  // 16. CORS Issues
  "Wildcard CORS Policy": [
    {
      platform: "Nginx",
      code: `# Remove or specify origin instead of '*'\nadd_header Access-Control-Allow-Origin "https://trusted-domain.com" always;`
    },
    {
      platform: "Apache",
      code: `Header set Access-Control-Allow-Origin "https://trusted-domain.com"`
    }
  ],

  // 17. Exposed Files & Paths
  "Exposed .env Configuration File": [
    {
      platform: "Nginx",
      code: `location ~ /\\.env {\n    deny all;\n    return 404;\n}`
    },
    {
      platform: "Apache",
      code: `<FilesMatch "^\\.env">\n    Require all denied\n</FilesMatch>`
    }
  ],
  "Exposed .git Repository": [
    {
      platform: "Nginx",
      code: `location ~ /\\.git {\n    deny all;\n    return 404;\n}`
    },
    {
      platform: "Apache",
      code: `<DirectoryMatch "^/.*/\\.git/">\n    Require all denied\n</DirectoryMatch>`
    }
  ],
  "X-AspNet-Version Header Exposed": [
    {
      platform: "IIS / web.config",
      code: `<httpRuntime enableVersionHeader="false" />`
    }
  ],

  // 18. Additional DNS Records
  "Missing CAA Record": [
    {
      platform: "DNS TXT Record",
      code: `Name/Host: @\nType: CAA\nValue: 0 issue "letsencrypt.org"`,
      notes: "Restricts which Certificate Authorities can issue certificates for your domain."
    }
  ],
  "Missing MTA-STS Record": [
    {
      platform: "DNS TXT Record",
      code: `Name/Host: _mta-sts\nType: TXT\nValue: v=STSv1; id=20240101000000Z;`,
      notes: "Requires hosting an mta-sts.txt policy file as well."
    }
  ],
  "Weak SPF Record (+all)": [
    {
      platform: "DNS TXT Record",
      code: `Name/Host: @\nValue: v=spf1 include:_spf.google.com ~all\nTTL: 3600`,
      notes: "Replace '+all' (allow all) or '?all' with '~all' (softfail) or '-all' (hardfail)."
    }
  ],

  // 19. Misconfigurations
  "Missing HTTPS Redirection": [
    {
      platform: "Nginx",
      code: `server {\n    listen 80;\n    server_name yourdomain.com;\n    return 301 https://$host$request_uri;\n}`
    },
    {
      platform: "Apache",
      code: `RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]`
    }
  ],
  "Weak Content-Security-Policy (CSP)": [
    {
      platform: "Nginx",
      code: `add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;`
    }
  ],
  "Verbose Server Banner": [
    {
      platform: "Nginx",
      code: `server_tokens off;`
    },
    {
      platform: "Apache",
      code: `ServerTokens Prod\nServerSignature Off`
    }
  ]
};
