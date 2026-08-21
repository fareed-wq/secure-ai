with open('src/components/scanner/ScanForm.jsx', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('            </div>\n          )}}', '            </div>\n          )}')

with open('src/components/scanner/ScanForm.jsx', 'w', encoding='utf-8') as f:
    f.write(content)
