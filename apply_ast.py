import os, ast

# Parse the audit_reeval.md to get the final mapping dictionary
audit_file = 'C:/Users/Fareed/.gemini/antigravity/brain/b69c3879-8a02-4a26-ab0f-dbec564beb6a/audit_reeval.md'
mappings = {}
with open(audit_file, 'r', encoding='utf-8') as f:
    for line in f:
        if line.startswith('|') and 'Finding' not in line and '---' not in line:
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 5:
                name = parts[1]
                final_owasp = parts[4]
                mappings[name] = final_owasp

# Apply manual final decisions (overriding the markdown)
mappings['Sensitive Response Tracking Indicator (ETag/Last-Modified)'] = 'Not Mapped'
mappings['Public OpenAPI / Swagger Specification Exposed'] = 'Not Mapped'
mappings['Client-Side API Key Detected'] = 'Not Mapped'
mappings['Privileged Client-Side Authorization Logic Disclosed'] = 'Not Mapped'
mappings['Missing X-Permitted-Cross-Domain-Policies'] = 'Not Mapped'
mappings['Missing X-DNS-Prefetch-Control'] = 'Not Mapped'

directory = 'd:/secure-AI/api/scanner/modules'
files_changed = 0
total_changes = 0

for filename in os.listdir(directory):
    if not filename.endswith('.py'): continue
    filepath = os.path.join(directory, filename)
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    try:
        tree = ast.parse(content)
    except Exception:
        continue
        
    lines = content.split('\n')
    file_modified = False
    
    # We collect modifications to apply from bottom to top to preserve line numbers
    modifications = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = getattr(node.func, 'attr', getattr(node.func, 'id', ''))
            if func_name == 'make_finding':
                # Get finding name
                name = None
                if node.args and isinstance(node.args[0], ast.Constant):
                    name = node.args[0].value
                else:
                    for kw in node.keywords:
                        if kw.arg == 'name' and isinstance(kw.value, ast.Constant):
                            name = kw.value.value
                            break
                            
                # Get owasp keyword
                owasp_node = None
                current_owasp = None
                for kw in node.keywords:
                    if kw.arg == 'owasp' and isinstance(kw.value, ast.Constant):
                        owasp_node = kw.value
                        current_owasp = kw.value.value
                        break
                        
                if name and owasp_node and current_owasp:
                    target_owasp = mappings.get(name, current_owasp)
                    # For A00 removal fallback if not in mappings
                    if target_owasp == current_owasp and current_owasp.startswith('A00'):
                        target_owasp = 'Not Mapped'
                        
                    if target_owasp != current_owasp:
                        line_idx = owasp_node.lineno - 1
                        col_offset = owasp_node.col_offset
                        end_col_offset = owasp_node.end_col_offset
                        modifications.append({
                            'line_idx': line_idx,
                            'start': col_offset,
                            'end': end_col_offset,
                            'new_val': f'"{target_owasp}"'
                        })
                        total_changes += 1
                        file_modified = True

    if file_modified:
        # Sort modifications by line descending, then column descending
        modifications.sort(key=lambda x: (x['line_idx'], x['start']), reverse=True)
        for mod in modifications:
            line_idx = mod['line_idx']
            orig_line = lines[line_idx]
            new_line = orig_line[:mod['start']] + mod['new_val'] + orig_line[mod['end']:]
            lines[line_idx] = new_line
            
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        files_changed += 1

print(f'Files changed: {files_changed}')
print(f'Total mapping updates: {total_changes}')
