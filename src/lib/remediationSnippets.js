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

  // 2. Missing COOP Header
  "Missing COOP Header": [
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

  // 3. Missing COEP Header
  "Missing COEP Header": [
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

  // 8. Missing X-Frame-Options
  "Missing X-Frame-Options": [
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
  ]
};
