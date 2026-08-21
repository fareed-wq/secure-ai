import re

with open('src/components/scanner/ScanForm.jsx', 'r', encoding='utf-8') as f:
    content = f.read()

# Let's just do a regex replace
content = re.sub(r'</div>\s*\)\s*\{isGuest && \(', r'</div>\n          )}\n\n          {isGuest && (', content)

with open('src/components/scanner/ScanForm.jsx', 'w', encoding='utf-8') as f:
    f.write(content)
