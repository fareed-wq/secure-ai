import os
for root, dirs, files in os.walk('api/scanner/modules'):
    for f in files:
        if f.endswith('.py'):
            p = os.path.join(root, f)
            with open(p, 'r', encoding='utf-8') as f_obj:
                c = f_obj.read()
            if 'owasp="N/A"' in c:
                c = c.replace('owasp="N/A"', 'owasp="A00: N/A"')
                with open(p, 'w', encoding='utf-8') as f_obj:
                    f_obj.write(c)
