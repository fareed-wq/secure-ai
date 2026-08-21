import re

with open('src/App.jsx', 'r') as f:
    content = f.read()

lazy_pages = [
    'Login', 'Register', 'EmailConfirmed', 'ForgotPassword', 'ResetPassword',
    'Dashboard', 'ScanHistory', 'SavedReports', 'Compare', 'Settings',
    'Services', 'About', 'BlogLanding', 'ArticlePage', 'Contact',
    'SecurityTrust', 'TermsOfService', 'ResponsibleDisclosure', 'ApiDocs', 'Pricing'
]

lazy_decls = []
for page in lazy_pages:
    match = re.search(r"import " + page + r" from '(\./pages/.*?)';", content)
    if match:
        import_path = match.group(1)
        content = re.sub(r"import " + page + r" from '.*?';\n", "", content)
        lazy_decls.append(f"const {page} = React.lazy(() => import('{import_path}'));\n")

if lazy_decls:
    last_import_idx = content.rfind("import ")
    end_of_last_import = content.find("\n", last_import_idx) + 1
    content = content[:end_of_last_import] + "\n" + "".join(lazy_decls) + content[end_of_last_import:]

if '<React.Suspense' not in content:
    content = content.replace('<Routes>', '<React.Suspense fallback={<div className=\"flex h-screen bg-slate-950 items-center justify-center text-slate-500\">Loading...</div>}>\n          <Routes>')
    content = content.replace('</Routes>', '</Routes>\n          </React.Suspense>')

with open('src/App.jsx', 'w') as f:
    f.write(content)
