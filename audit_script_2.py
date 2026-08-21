import os, re
findings = []
directory = 'd:/secure-AI/api/scanner/modules'

pattern = r'(?:Finding|add_finding)\s*\(\s*name\s*=\s*[\'"]([^\'"]+)[\'"]\s*,.*?severity\s*=\s*[\'"]([^\'"]+)[\'"].*?owasp\s*=\s*[\'"]([^\'"]+)[\'"]'

for filename in os.listdir(directory):
    if filename.endswith('.py'):
        filepath = os.path.join(directory, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            matches = re.finditer(pattern, content, re.DOTALL)
            for m in matches:
                findings.append((m.group(1), m.group(2), m.group(3)))

print(f'Total findings extracted: {len(findings)}')
for f in findings:
    print(f'| {f[0]} | {f[1]} | {f[2]} |')
