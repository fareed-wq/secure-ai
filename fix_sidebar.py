import re
content = open('src/components/layout/Sidebar.jsx').read()
content = re.sub(r'title=\"([^\"]+)\"(?! aria-label)', r'title=\"\1\" aria-label=\"\1\"', content)
open('src/components/layout/Sidebar.jsx', 'w').write(content)
