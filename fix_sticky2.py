import re

with open('src/pages/Scanner.jsx', 'r', encoding='utf-8') as f:
    content = f.read()

pattern = r'({\s*/\*\s*5\.\s*VIEW REPORT STATE\s*\*/\s*})([\s\S]*?)(<ReportHeader[\s\S]*?/>)(\s*<ErrorBoundary>[\s\S]*?</ErrorBoundary>\s*)(</motion\.div>\s*})'

def replacer(m):
    comment = m.group(1)
    before_header = m.group(2).replace('<motion.div', '<div').replace('initial={{ opacity: 0, y: 20 }}\n              animate={{ opacity: 1, y: 0 }}', '')
    header = m.group(3)
    after_header = m.group(4)
    end = m.group(5).replace('</motion.div>', '</div>')
    
    # wrap after_header in motion.div
    new_after = '\n              <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>\n' + after_header + '              </motion.div>\n'
    
    return comment + before_header + header + new_after + end

new_content = re.sub(pattern, replacer, content)

with open('src/pages/Scanner.jsx', 'w', encoding='utf-8') as f:
    f.write(new_content)
print("Regex replaced!")
