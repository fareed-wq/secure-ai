import re

content = open('src/pages/Scanner.jsx').read()
if 'import React' not in content:
    content = "import React, { useState, useEffect, useRef } from 'react';\n" + content.split('from \'react\';', 1)[1]

components_to_lazy_load = [
    ('SimpleReport', '../components/scanner/SimpleReport'),
    ('TechnicalReport', '../components/scanner/TechnicalReport'),
    ('AuthModal', '../components/scanner/AuthModal')
]

for name, path in components_to_lazy_load:
    content = re.sub(rf"import {name} from '{path}';", f"const {name} = React.lazy(() => import('{path}'));", content)

# Wrap JSX using these in Suspense... wait, Scanner already has <ErrorBoundary> inside which we can use Suspense?
# It's easier to just do it inline if they aren't already wrapped, or wrap the whole report section.
# Actually, the report section is conditionally rendered. Let's wrap them in Suspense when they are used.
# Or just wrap the whole Scanner return block? No, just wrap the report section.
# Let's search for <SimpleReport
if '<SimpleReport' in content and '<React.Suspense' not in content:
    content = content.replace('<SimpleReport', '<React.Suspense fallback={<div className=\"py-12 flex justify-center text-slate-500\"><Loader2 className=\"animate-spin h-8 w-8\" /></div>}><SimpleReport')
    content = content.replace('reportData={reportData} />', 'reportData={reportData} /></React.Suspense>')
    
if '<TechnicalReport' in content and '<React.Suspense' not in content:
    content = content.replace('<TechnicalReport', '<React.Suspense fallback={<div className=\"py-12 flex justify-center text-slate-500\"><Loader2 className=\"animate-spin h-8 w-8\" /></div>}><TechnicalReport')
    content = content.replace('reportData={reportData} />', 'reportData={reportData} /></React.Suspense>')

if '<AuthModal' in content and '<React.Suspense' not in content:
    content = content.replace('<AuthModal', '<React.Suspense fallback={null}><AuthModal')
    content = content.replace('/>', '/></React.Suspense>', 1) # Might be risky if there are multiple />

open('src/pages/Scanner.jsx', 'w').write(content)
