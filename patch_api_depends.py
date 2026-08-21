def patch_file():
    with open('api/index.py', 'r') as f:
        content = f.read()

    # Move Depends import to the top
    content = content.replace("from fastapi import FastAPI, Request", "from fastapi import FastAPI, Request, Depends")
    content = content.replace("from fastapi import Depends\n", "")
    
    with open('api/index.py', 'w') as f:
        f.write(content)

patch_file()
