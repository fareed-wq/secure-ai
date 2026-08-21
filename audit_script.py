import ast
import os
import glob
import json

def audit_findings():
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
                            finding_info = {
                                "file": os.path.basename(fpath),
                                "class": current_class,
                                "line": child.lineno,
                                "args": [],
                                "kwargs": {}
                            }
                            
                            for arg in child.args:
                                if isinstance(arg, ast.Constant):
                                    finding_info["args"].append(arg.value)
                                else:
                                    finding_info["args"].append("<dynamic>")
                                    
                            for kw in child.keywords:
                                if isinstance(kw.value, ast.Constant):
                                    finding_info["kwargs"][kw.arg] = kw.value.value
                                else:
                                    finding_info["kwargs"][kw.arg] = "<dynamic>"
                                    
                            report.append(finding_info)
    
    with open("audit_results.json", "w") as f:
        json.dump(report, f, indent=2)

if __name__ == "__main__":
    audit_findings()
