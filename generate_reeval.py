import sys

lines = [line.strip() for line in open('audit_findings.txt', 'r', encoding='utf-16') if line.strip() and '|' in line]

results = []
definite_changes = 0
definite_keeps = 0
ambiguous = 0

for line in lines:
    parts = [p.strip() for p in line.split('|')]
    if len(parts) != 3:
        continue
    name, sev, cur = parts
    
    prev_rec = cur
    # Reproduce prev logic roughly
    if cur.startswith('A00'):
        prev_rec = 'Not Mapped'
    elif name in ['robots.txt Found', 'sitemap.xml Found']:
        prev_rec = 'Not Mapped'
    elif name == 'security.txt Policy Configured':
        prev_rec = 'Not Mapped'
    elif 'Certificate Issuer Identified' in name or 'Certificate SANs' in name or 'Modern TLS 1.3 Supported' in name or 'Wildcard Certificate in Use' in name:
        prev_rec = 'Not Mapped'
    elif name in ['DNSSEC Not Enabled', 'Missing CAA Record']:
        prev_rec = 'Not Mapped'
    elif sev == 'Informational' and ('SPF' in name or 'DMARC' in name or 'MTA-STS' in name or 'DKIM' in name):
        prev_rec = 'Not Mapped'
    elif sev == 'Informational' and ('Disclosed' in name or 'Detected' in name or 'Identified' in name or 'Exposed' in name or 'Discovered' in name or 'Information' in name or 'Observe' in name or 'Found' in name):
        if 'Missing' not in name and 'Insecure' not in name:
            prev_rec = 'Not Mapped'
    elif 'Missing ' in name and sev == 'Informational' and 'Header' not in name and 'Policy' not in name and 'Security' not in name:
        prev_rec = 'Not Mapped'

    # Manual logic
    final = cur
    conf = "High"
    reason = "Valid control mapping"
    
    if "Outdated Client-Side JavaScript Library Detected" in name:
        final = "A06: Vulnerable and Outdated Components"
        reason = "A06 maps exactly to vulnerable/outdated components"
    elif cur.startswith('A00'):
        final = "Not Mapped"
        reason = "A00 is not official"
    elif "robots.txt" in name or "sitemap.xml" in name:
        final = "Not Mapped"
        reason = "Pure inventory/discovery observation"
    elif "security.txt" in name:
        final = "Not Mapped"
        reason = "Policy check, not direct OWASP risk"
    elif name in ["Session Technology Fingerprinted", "CNAME Alias Configured"]:
        final = "Not Mapped"
        reason = "Pure infrastructure metadata"
    elif "DNSSEC" in name or "CAA" in name:
        final = "Not Mapped"
        reason = "Infrastructure configuration metadata"
    elif sev == "Informational" and ("SPF" in name or "DMARC" in name or "MTA-STS" in name or "DKIM" in name):
        final = "Not Mapped"
        reason = "Informational email policy analysis"
    elif sev != "Informational" and ("SPF" in name or "DMARC" in name or "MTA-STS" in name):
        final = "A05: Security Misconfiguration"
        reason = "Email security misconfiguration"
    elif "Certificate Issuer" in name or "Certificate SANs" in name or "Modern TLS 1.3" in name or "Wildcard Certificate" in name:
        final = "Not Mapped"
        reason = "Informational certificate metadata"
    elif "Expiring Soon" in name or "Exceeds Maximum Lifespan" in name:
        final = "A02: Cryptographic Failures"
        reason = "Real certificate security weakness"
    elif "Source Maps Exposed" in name:
        final = "A05: Security Misconfiguration"
        reason = "Misconfigured production build exposing source code"
    elif "Authentication Interface Detected" in name or "Password Recovery Interface" in name or "Authentication Technology Detected" in name or "Administrative Portal Discovered" in name:
        final = "Not Mapped"
        reason = "Pure discovery observation"
    elif "Inconclusive" in name:
        final = "Not Mapped"
        reason = "Check did not complete, no risk identified"
    elif "Version Disclosed" in name or "Version Information Disclosed" in name or "Technology Information Disclosure" in name or "Server Header Exposed" in name or "Server Banner" in name or "Framework Detected" in name or "Infrastructure Identified" in name:
        final = "Not Mapped"
        reason = "Pure technology footprint discovery"
    elif "Private IP Disclosure" in name:
        final = "Not Mapped"
        conf = "Medium"
        reason = "Info exposure; not strictly A01/A05 unless it enables access"
    elif "Privileged" in name and ("Documented" in name or "Operation" in name):
        final = "A01: Broken Access Control"
        reason = "Real authorization risk surface"
    elif "Privileged API Surface Discovered" in name or "Authorization Roles" in name or "Privileged Client-Side" in name:
        final = "Not Mapped"
        conf = "Medium"
        reason = "Discovery observation, no active breach"
    elif sev == "Passed":
        if "CORS" in name or "WAF" in name or "HSTS" in name or "CSP" in name or "Isolation" in name or "Redirect" in name or "Cipher" in name or "Certificate" in name:
            final = cur
            reason = "Validates a real OWASP-related control"
        else:
            final = "Not Mapped"
            conf = "Medium"
            reason = "Passed check but unclear direct OWASP relation"
    elif sev == "Informational":
        if "Cookie" in name or "CORS" in name or "CSP" in name:
            final = cur
            reason = "Informational but directly relates to A05 control"
        else:
            final = "Not Mapped"
            conf = "Medium"
            reason = "Pure inventory/discovery observation with no direct OWASP risk"
    elif "Missing" in name and ("X-Permitted" in name or "X-DNS" in name or "X-Content-Type" in name):
        final = "Not Mapped"
        reason = "Minor header omission, no direct OWASP risk"
    elif "Subdomain Discovered" in name or "API Endpoints Discovered" in name or "GraphQL Endpoint Reference" in name or "WebSocket Endpoint" in name:
        final = "Not Mapped"
        reason = "Pure discovery observation"
    else:
        if cur.startswith("A0"):
            final = cur
            reason = "Genuine security weakness mapping"
        else:
            final = "Not Mapped"
            conf = "Low"
            reason = "Ambiguous fallback"
            
    if final != cur:
        definite_changes += 1
    else:
        definite_keeps += 1
        
    if conf == "Low" or conf == "Medium":
        ambiguous += 1
        
    results.append(f"| {name} | {cur} | {prev_rec} | {final} | {conf} | {reason} |")

print("| Finding | Current OWASP | Previous Recommendation | Final Recommendation | Confidence | Reason |")
print("|---|---|---|---|---|---|")
for r in results:
    print(r)

print("\nSummary:")
print(f"- definite changes: {definite_changes}")
print(f"- definite keeps: {definite_keeps}")
print(f"- genuinely ambiguous cases: {ambiguous}")

