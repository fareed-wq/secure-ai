import os, ast

findings = []
directory = 'd:/secure-AI/api/scanner/modules'

for filename in os.listdir(directory):
    if filename.endswith('.py'):
        filepath = os.path.join(directory, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = None
                    if isinstance(node.func, ast.Attribute):
                        func = node.func.attr
                    elif isinstance(node.func, ast.Name):
                        func = node.func.id
                        
                    if func == 'make_finding':
                        name = ""
                        severity = ""
                        owasp = "Not Specified"
                        
                        # Args
                        if len(node.args) > 0 and isinstance(node.args[0], ast.Constant):
                            name = node.args[0].value
                        if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                            severity = node.args[1].value
                            
                        # Kwargs
                        for kw in node.keywords:
                            if kw.arg == 'name' and isinstance(kw.value, ast.Constant):
                                name = kw.value.value
                            elif kw.arg == 'severity' and isinstance(kw.value, ast.Constant):
                                severity = kw.value.value
                            elif kw.arg == 'owasp' and isinstance(kw.value, ast.Constant):
                                owasp = kw.value.value
                                
                        if name:
                            findings.append({
                                'name': name,
                                'severity': severity,
                                'owasp': owasp,
                                'file': filename
                            })

# Also we need to check the base classes or orchestrator where findings might be appended.
# orchestrator.py might have some.
orchestrator_path = 'd:/secure-AI/api/scanner/orchestrator.py'
if os.path.exists(orchestrator_path):
    with open(orchestrator_path, 'r', encoding='utf-8') as f:
        tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = None
                if isinstance(node.func, ast.Attribute):
                    func = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func = node.func.id
                if func == 'append' and isinstance(node.func, ast.Attribute) and getattr(node.func.value, 'attr', '') == 'findings':
                    # Might be appending a dict
                    if len(node.args) == 1 and isinstance(node.args[0], ast.Dict):
                        d = node.args[0]
                        name = ""
                        severity = ""
                        owasp = "Not Specified"
                        for k, v in zip(d.keys, d.values):
                            if isinstance(k, ast.Constant):
                                if k.value == 'name' and isinstance(v, ast.Constant):
                                    name = v.value
                                elif k.value == 'severity' and isinstance(v, ast.Constant):
                                    severity = v.value
                                elif k.value == 'owasp' and isinstance(v, ast.Constant):
                                    owasp = v.value
                        if name:
                            findings.append({
                                'name': name,
                                'severity': severity,
                                'owasp': owasp,
                                'file': 'orchestrator.py'
                            })

print(f"Total: {len(findings)}\n")
for f in findings:
    print(f"{f['name']} | {f['severity']} | {f['owasp']}")
