import ast
import os
import glob
import json

def analyze():
    modules_path = "api/scanner/modules/*.py"
    files = glob.glob(modules_path)
    report = []
    
    for fpath in files:
        with open(fpath, "r", encoding="utf-8") as f:
            code = f.read()
        
        tree = ast.parse(code)
        
        current_class = "Unknown"
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                current_class = node.name
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        if isinstance(child.func, ast.Attribute) and child.func.attr == "make_finding":
                            # Base signature: make_finding(name, severity, description, evidence, **kwargs)
                            name, severity, description, evidence = [None]*4
                            
                            if len(child.args) >= 1: name = child.args[0].value if isinstance(child.args[0], ast.Constant) else "<dynamic>"
                            if len(child.args) >= 2: severity = child.args[1].value if isinstance(child.args[1], ast.Constant) else "<dynamic>"
                            if len(child.args) >= 3: description = child.args[2].value if isinstance(child.args[2], ast.Constant) else "<dynamic>"
                            if len(child.args) >= 4: evidence = child.args[3].value if isinstance(child.args[3], ast.Constant) else "<dynamic>"
                            
                            kwargs = {}
                            for kw in child.keywords:
                                kwargs[kw.arg] = kw.value.value if isinstance(kw.value, ast.Constant) else "<dynamic>"
                                
                            report.append({
                                "module": current_class,
                                "name": name,
                                "severity": severity,
                                "description": description,
                                "evidence": evidence,
                                **kwargs
                            })

    # Consistency Checks
    inconsistencies = []
    
    for f in report:
        sev = f.get("severity")
        if sev not in ["Critical", "High", "Medium", "Low", "Informational", "Passed", "<dynamic>"]:
            inconsistencies.append(f"Invalid severity {sev} in {f['module']}: {f['name']}")
            
        conf = f.get("confidence", "High") # default is High
        if conf not in ["High", "Medium", "Low", "Informational", "<dynamic>"]:
            inconsistencies.append(f"Invalid confidence {conf} in {f['module']}: {f['name']}")
            
        if not f.get("owasp"):
            inconsistencies.append(f"Missing OWASP mapping in {f['module']}: {f['name']}")
            
        if not f.get("category"):
            inconsistencies.append(f"Missing category in {f['module']}: {f['name']}")
            
        if sev == "High" and conf == "Low":
            inconsistencies.append(f"Suspicious High severity + Low confidence in {f['module']}: {f['name']}")

        # Check for missing description/evidence
        if not f.get("description") or f.get("description") == "":
            inconsistencies.append(f"Missing description in {f['module']}: {f['name']}")
            
        if not f.get("evidence") or f.get("evidence") == "":
            inconsistencies.append(f"Missing evidence in {f['module']}: {f['name']}")
            
    print("Inconsistencies found:")
    for i in inconsistencies:
        print(i)

if __name__ == "__main__":
    analyze()
