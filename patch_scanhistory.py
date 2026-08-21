def patch_file():
    with open('src/pages/ScanHistory.jsx', 'r') as f:
        content = f.read()

    # Change the Link for View Report
    content = content.replace("to={`/scan?url=${scan.target}`}", "to={`/history/${scan.id}`}")

    with open('src/pages/ScanHistory.jsx', 'w') as f:
        f.write(content)

patch_file()
