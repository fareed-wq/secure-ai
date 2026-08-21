def patch_file():
    with open('src/components/scanner/ScanForm.jsx', 'r') as f:
        content = f.read()
    content = content.replace("save reports, download PDF reports, and access your scan history.", "download PDF reports, and access your scan history.")
    with open('src/components/scanner/ScanForm.jsx', 'w') as f:
        f.write(content)
patch_file()
