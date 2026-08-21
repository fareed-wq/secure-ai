import os, re

mapping = {
    'Outdated Client-Side JavaScript Library Detected': 'A06: Vulnerable and Outdated Components',
    'Sensitive Response Tracking Indicator (ETag/Last-Modified)': 'Not Mapped',
    'Public OpenAPI / Swagger Specification Exposed': 'Not Mapped',
    'Client-Side API Key Detected': 'Not Mapped',
    'Privileged Client-Side Authorization Logic Disclosed': 'Not Mapped',
    'Missing X-Permitted-Cross-Domain-Policies': 'Not Mapped',
    'Missing X-DNS-Prefetch-Control': 'Not Mapped',
    'Private IP Disclosure': 'A05: Security Misconfiguration',
    'Interactive GraphQL Developer IDE Exposed': 'A05: Security Misconfiguration',
    'Spring Boot Actuator Endpoint Exposed': 'A05: Security Misconfiguration',
    'Authentication Form Uses External Origin': 'A07: Identification and Authentication Failures'
}

def get_mapping(name, current_owasp, sev):
    if name in mapping:
        return mapping[name]
    
    if current_owasp.startswith('A00'):
        return 'Not Mapped'
    if 'robots.txt' in name or 'sitemap.xml' in name:
        return 'Not Mapped'
    if 'security.txt' in name:
        return 'Not Mapped'
    if name in ['Session Technology Fingerprinted', 'CNAME Alias Configured', 'HTTP Authentication Scheme Disclosed', 'Privileged / Administrative Surface Discovered', 'API Authorization Scheme Disclosed', 'Authorization Roles / Permissions Disclosed', 'Privileged API Surface Discovered in Client-Side Code', 'Subdomains Discovered', 'Certificate Subject Alternative Names (SANs)']:
        return 'Not Mapped'
    if 'DNSSEC' in name or 'CAA' in name:
        return 'Not Mapped'
    if sev == 'Informational' and any(x in name for x in ['SPF', 'DMARC', 'MTA-STS', 'DKIM']):
        return 'Not Mapped'
    if sev != 'Informational' and any(x in name for x in ['SPF', 'DMARC', 'MTA-STS']):
        return 'A05: Security Misconfiguration'
    if any(x in name for x in ['Certificate Issuer', 'Certificate SANs', 'Modern TLS 1.3', 'Wildcard Certificate']):
        return 'Not Mapped'
    if 'Expiring Soon' in name or 'Exceeds Maximum Lifespan' in name:
        return 'A02: Cryptographic Failures'
    if 'Source Maps Exposed' in name:
        return 'A05: Security Misconfiguration'
    if any(x in name for x in ['Authentication Interface Detected', 'Password Recovery Interface', 'Authentication Technology Detected', 'Administrative Portal Discovered', 'Password Autocomplete Policy Detected']):
        return 'Not Mapped'
    if 'Inconclusive' in name:
        return 'Not Mapped'
    if any(x in name for x in ['Version Disclosed', 'Version Information Disclosed', 'Technology Information Disclosure', 'Server Header Exposed', 'Server Banner', 'Framework Detected', 'Infrastructure Identified']):
        return 'Not Mapped'
    if 'Privileged' in name and ('Documented' in name or 'Operation' in name):
        return 'A01: Broken Access Control'
    if 'Privileged API Surface Discovered' in name or 'Authorization Roles' in name or 'Privileged Client-Side' in name:
        return 'Not Mapped'
    if sev == 'Passed':
        if any(x in name for x in ['CORS', 'WAF', 'HSTS', 'CSP', 'Isolation', 'Redirect', 'Cipher', 'Certificate', 'No Mixed Content Detected', 'Permissions-Policy Configured', 'Referrer-Policy Configured', 'Content-Security-Policy Configured', 'Strict-Transport-Security Configured', 'No Subdomain Takeover Risk Detected', 'Legacy TLS Protocols Disabled']):
            return current_owasp
        else:
            return 'Not Mapped'
    if sev == 'Informational':
        if any(x in name for x in ['Cookie', 'CORS', 'CSP', 'Missing Permissions-Policy', 'Missing X-Content-Type-Options', 'Missing Referrer-Policy', 'Content-Security-Policy in Report-Only Mode', 'Content-Security-Policy-Report-Only Also Present', 'Missing COOP Header', 'Missing COEP Header', 'Missing CORP Header', 'Public GraphQL Introspection Enabled']):
            return current_owasp
        else:
            return 'Not Mapped'
    if 'Missing' in name and any(x in name for x in ['X-Permitted', 'X-DNS', 'X-Content-Type']):
        return 'Not Mapped'
    if any(x in name for x in ['Subdomain Discovered', 'API Endpoints Discovered', 'GraphQL Endpoint Reference', 'WebSocket Endpoint']):
        return 'Not Mapped'
    
    return current_owasp

changes = 0
files_changed = 0
directory = 'd:/secure-AI/api/scanner/modules'

for filename in os.listdir(directory):
    if not filename.endswith('.py'): continue
    filepath = os.path.join(directory, filename)
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    lines = content.split('\n')
    new_lines = []
    i = 0
    file_modified = False
    
    while i < len(lines):
        line = lines[i]
        if 'make_finding(' in line:
            block_start = i
            open_parens = 0
            name = None
            sev = None
            owasp_val = None
            owasp_line_idx = -1
            
            j = i
            while j < len(lines):
                # Using simple regex to extract name, sev, owasp
                m_name = re.search(r'[\(\s]name=[\"\'](.*?)[\"\']', lines[j])
                if not m_name:
                    m_name = re.search(r'make_finding\(\s*[\"\'](.*?)[\"\']', lines[j])
                if m_name and not name:
                    name = m_name.group(1)
                
                m_sev = re.search(r'[\,\s]severity=[\"\'](.*?)[\"\']', lines[j])
                if not m_sev and name:
                    m_sev = re.search(r'make_finding\(\s*[\"\'].*?[\"\'],\s*[\"\'](.*?)[\"\']', lines[j])
                if m_sev and not sev:
                    sev = m_sev.group(1)
                    
                m_owasp = re.search(r'owasp=[\"\'](.*?)[\"\']', lines[j])
                if m_owasp:
                    owasp_val = m_owasp.group(1)
                    owasp_line_idx = j
                
                for char in lines[j]:
                    if char == '(': open_parens += 1
                    elif char == ')': open_parens -= 1
                
                if open_parens == 0:
                    break
                j += 1
                
            if name and sev and owasp_val:
                new_owasp = get_mapping(name, owasp_val, sev)
                if new_owasp != owasp_val:
                    lines[owasp_line_idx] = lines[owasp_line_idx].replace(f'owasp="{owasp_val}"', f'owasp="{new_owasp}"').replace(f"owasp='{owasp_val}'", f"owasp='{new_owasp}'")
                    changes += 1
                    file_modified = True
            
            new_lines.extend(lines[i:j+1])
            i = j + 1
        else:
            new_lines.append(line)
            i += 1
            
    if file_modified:
        files_changed += 1
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(new_lines))

print(f'Files changed: {files_changed}')
print(f'Total mapping updates: {changes}')
