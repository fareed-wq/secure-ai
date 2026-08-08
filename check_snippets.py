import re

def get_backend_findings(filepath):
    findings = set()
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        # Look for make_finding("Finding Name", ...)
        matches = re.findall(r'make_finding\(\s*["\']([^"\']+)["\']', content)
        for match in matches:
            findings.add(match)
    return findings

def get_frontend_snippets(filepath):
    snippets = set()
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        # Look for keys in REMEDIATION_SNIPPETS
        # format: "Finding Name": [
        matches = re.findall(r'["\']([^"\']+)["\']\s*:\s*\[', content)
        for match in matches:
            snippets.add(match)
    return snippets

backend_findings = get_backend_findings('api/index.py')
frontend_snippets = get_frontend_snippets('src/lib/remediationSnippets.js')

print(f"Total Backend Findings: {len(backend_findings)}")
print(f"Total Frontend Snippets: {len(frontend_snippets)}")

missing = backend_findings - frontend_snippets
print("\nFindings WITHOUT Snippets (Expected for Informational or Application-specific issues):")
for f in sorted(missing):
    print(f" - {f}")
