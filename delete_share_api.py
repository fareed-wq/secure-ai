import re

def patch_file():
    with open('api/index.py', 'r') as f:
        content = f.read()

    # Find the block starting from ShareCreateRequest to the end of get_shared_report
    start = content.find("class ShareCreateRequest(BaseModel):")
    if start != -1:
        end = content.find("async def get_shared_report", start)
        end = content.find("    }", end)
        # Find the next function or the end of file
        next_fun = content.find("@app", end)
        if next_fun != -1:
            end = next_fun
        else:
            end = len(content)
            
        content = content[:start] + content[end:]

    with open('api/index.py', 'w') as f:
        f.write(content)

patch_file()
