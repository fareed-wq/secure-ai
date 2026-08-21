import os, ast
ambiguous = [
    'Sensitive Response Tracking Indicator (ETag/Last-Modified)',
    'HTTP Authentication Scheme Disclosed',
    'Privileged / Administrative Surface Discovered',
    'Authentication Form Uses External Origin',
    'Password Autocomplete Policy Detected',
    'No Mixed Content Detected',
    'Private IP Disclosure',
    'Interactive GraphQL Developer IDE Exposed',
    'Public OpenAPI / Swagger Specification Exposed',
    'API Authorization Scheme Disclosed',
    'Spring Boot Actuator Endpoint Exposed',
    'Missing Permissions-Policy',
    'Permissions-Policy Configured',
    'Missing X-Permitted-Cross-Domain-Policies',
    'Missing X-DNS-Prefetch-Control',
    'Missing X-Content-Type-Options',
    'Missing Referrer-Policy',
    'No Web Application Firewall (WAF) / Rate-Limiting Headers Detected',
    'Referrer-Policy Configured',
    'Content-Security-Policy in Report-Only Mode',
    'Content-Security-Policy-Report-Only Also Present',
    'Content-Security-Policy Configured',
    'Missing COOP Header',
    'Missing COEP Header',
    'Missing CORP Header',
    'Strict-Transport-Security Configured',
    'Client-Side API Key Detected',
    'Privileged Client-Side Authorization Logic Disclosed',
    'Authorization Roles / Permissions Disclosed',
    'Privileged API Surface Discovered in Client-Side Code',
    'Subdomains Discovered',
    'No Subdomain Takeover Risk Detected',
    'Public GraphQL Introspection Enabled',
    'Legacy TLS Protocols Disabled',
    'Certificate Subject Alternative Names (SANs)'
]

findings_data = {}
directory = 'd:/secure-AI/api/scanner/modules'
for filename in os.listdir(directory):
    if filename.endswith('.py'):
        filepath = os.path.join(directory, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = getattr(node.func, 'attr', getattr(node.func, 'id', ''))
                    if func == 'make_finding':
                        kwargs = {kw.arg: kw.value.value for kw in node.keywords if isinstance(kw.value, ast.Constant)}
                        args = [a.value for a in node.args if isinstance(a, ast.Constant)]
                        name = args[0] if len(args) > 0 else kwargs.get('name', '')
                        if name in ambiguous:
                            findings_data[name] = {
                                'severity': args[1] if len(args) > 1 else kwargs.get('severity', ''),
                                'description': args[2] if len(args) > 2 else kwargs.get('description', ''),
                                'remediation': kwargs.get('remediation', ''),
                                'owasp': kwargs.get('owasp', '')
                            }

for k, v in findings_data.items():
    print(f"\n--- {k} ---")
    print(f"Severity: {v['severity']}")
    print(f"OWASP: {v['owasp']}")
    print(f"Desc: {v['description']}")
    print(f"Remed: {v['remediation']}")
