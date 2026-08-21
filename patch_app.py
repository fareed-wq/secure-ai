def patch_file():
    with open('src/App.jsx', 'r') as f:
        content = f.read()

    # Remove SharedReport and SavedReports imports
    content = content.replace("const SharedReport = React.lazy(() => import('./pages/SharedReport'));\n", "")
    content = content.replace("const SavedReports = React.lazy(() => import('./pages/SavedReports'));\n", "")
    content = content.replace("const ScanHistory = React.lazy(() => import('./pages/ScanHistory'));", "const ScanHistory = React.lazy(() => import('./pages/ScanHistory'));\nconst ScanReport = React.lazy(() => import('./pages/ScanReport'));")

    # Remove Routes
    content = content.replace("                <Route path=\"/shared/:token\" element={<SharedReport />} />\n", "")
    content = content.replace("                <Route path=\"/reports\" element={<SavedReports />} />\n", "")

    # Add /history/:scanId
    content = content.replace("<Route path=\"/history\" element={<ScanHistory />} />", "<Route path=\"/history\" element={<ScanHistory />} />\n                <Route path=\"/history/:scanId\" element={<ScanReport />} />")

    with open('src/App.jsx', 'w') as f:
        f.write(content)

patch_file()
