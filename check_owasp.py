import re

with open('api/index.py', 'r', encoding='utf-8') as f:
    content = f.read()

matches = re.finditer(r'make_finding\(\s*[\"\'']([^\"\'']+)[\"\'']([\s\S]*?)\)', content)
for m in matches:
    name = m.group(1)
    args = m.group(2)
    if 'owasp=' in args:
        pass
    else:
        print(f'{name}: MISSING')
