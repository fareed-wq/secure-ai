import sys

lines = [line.strip() for line in open('audit_findings.txt', 'r', encoding='utf-8') if line.strip() and '|' in line]

results = []
keep = 0
change = 0
not_mapped = 0
ambig = 0

for line in lines:
    parts = [p.strip() for p in line.split('|')]
    if len(parts) != 3:
        continue
    name, sev, cur = parts
    
    rec = cur
    action = "Keep"
    reason = "Valid A01-A10 mapping"
    
    lname = name.lower()
    
    if cur.startswith("A00"):
        rec = "Not Mapped"
        action = "Change"
        reason = "A00 is not official OWASP"
        not_mapped += 1
    elif name in ["robots.txt Found", "sitemap.xml Found"]:
        rec = "Not Mapped"
        action = "Change"
        reason = "Pure discovery observation"
        not_mapped += 1
    elif name == "security.txt Policy Configured":
        rec = "Not Mapped"
        action = "Change"
        reason = "Policy discovery, not a security control validation"
        not_mapped += 1
    elif "Certificate Issuer Identified" in name or "Certificate SANs" in name or "Modern TLS 1.3 Supported" in name or "Wildcard Certificate in Use" in name:
        rec = "Not Mapped"
        action = "Change"
        reason = "Pure TLS metadata observation"
        not_mapped += 1
    elif name in ["DNSSEC Not Enabled", "Missing CAA Record"]:
        rec = "Not Mapped"
        action = "Change"
        reason = "Infrastructure metadata"
        not_mapped += 1
    elif sev == "Informational" and ("SPF" in name or "DMARC" in name or "MTA-STS" in name or "DKIM" in name):
        rec = "Not Mapped"
        action = "Change"
        reason = "Informational mail config observation"
        not_mapped += 1
    elif sev == "Informational" and ("Disclosed" in name or "Detected" in name or "Identified" in name or "Exposed" in name or "Discovered" in name or "Information" in name or "Observe" in name or "Found" in name):
        if "Missing" not in name and "Insecure" not in name:
            rec = "Not Mapped"
            action = "Change"
            reason = "Pure metadata/discovery observation"
            not_mapped += 1
        else:
            keep += 1
    elif sev == "Passed" and "Enabled" in name and "Takeover" not in name and "CORS" not in name and "WAF" not in name and "HSTS" not in name and "CSP" not in name and "Isolation" not in name and "Redirect" not in name and "Cipher" not in name and "Certificate" not in name and "Policy Configured" not in name:
        rec = cur
        action = "Keep"
        keep += 1
    elif "Missing " in name and sev == "Informational" and "Header" not in name and "Policy" not in name and "Security" not in name:
        rec = "Not Mapped"
        action = "Change"
        reason = "Low value missing attribute"
        not_mapped += 1
    else:
        # Check if it was currently valid
        if cur.startswith("A0"):
            keep += 1
        else:
            ambig += 1
            
    results.append(f"| {name} | {sev} | {cur} | {rec} | {action} | {reason} |")

print("| Finding | Severity | Current OWASP | Recommended OWASP | Action | Reason |")
print("|---|---|---|---|---|---|")
for r in results:
    print(r)

print("\nSummary:")
print(f"- total mappings to keep: {keep}")
print(f"- total mappings to change: {not_mapped}") # All changes here are to Not Mapped
print(f"- total mappings to set as Not Mapped: {not_mapped}")
print(f"- ambiguous mappings needing manual judgment: {ambig}")

