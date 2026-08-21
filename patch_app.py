def patch_file():
    with open('src/App.jsx', 'r') as f:
        content = f.read()

    # Import
    content = content.replace("const Dashboard = React.lazy(() => import('./pages/Dashboard'));", "const Dashboard = React.lazy(() => import('./pages/Dashboard'));\nconst SharedReport = React.lazy(() => import('./pages/SharedReport'));")

    # Route
    content = content.replace('<Route path="/services" element={<Services />} />', '<Route path="/services" element={<Services />} />\n                <Route path="/shared/:token" element={<SharedReport />} />')
    
    with open('src/App.jsx', 'w') as f:
        f.write(content)

patch_file()
