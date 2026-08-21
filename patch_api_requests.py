def patch_file():
    with open('api/index.py', 'r') as f:
        content = f.read()

    # Move Depends import to the top
    content = "import requests\n" + content
    
    with open('api/index.py', 'w') as f:
        f.write(content)

patch_file()
