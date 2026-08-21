def patch_file():
    with open('src/pages/Scanner.jsx', 'r') as f:
        content = f.read()

    # Update Guest 3/3 copy in the HTML
    content = content.replace("save reports, download PDF reports, and access your scan history.", "download PDF reports, and access your scan history.")

    with open('src/pages/Scanner.jsx', 'w') as f:
        f.write(content)

patch_file()
