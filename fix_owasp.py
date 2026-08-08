import re

with open('api/index.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace all occurrences where category= is present but owasp= is missing in make_finding
def replacer(m):
    block = m.group(0)
    if 'owasp=' not in block:
        # insert owasp="A05: Security Misconfiguration" before category=
        block = block.replace('category=', 'owasp="A05: Security Misconfiguration",\n                                category=')
    return block

content = re.sub(r'self\.make_finding\([\s\S]*?category=[\s\S]*?\)', replacer, content)

with open('api/index.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("OWASP mappings added!")
