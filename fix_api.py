import re

def fix_api():
    with open('api/index.py', 'r') as f:
        content = f.read()

    # Find the added block
    start_str = "class ShareCreateRequest(BaseModel):"
    end_str = "    # Return constrained public projection\n    return {\n        \"target_url\": scan.get(\"target_url\"),\n        \"score\": scan.get(\"score\"),\n        \"report_data\": scan.get(\"report_data\"),\n        \"created_at\": scan.get(\"created_at\")\n    }\n"
    
    start_idx = content.find(start_str)
    end_idx = content.find(end_str) + len(end_str)
    
    if start_idx != -1 and end_idx != -1:
        extracted = content[start_idx:end_idx]
        
        # Remove from original position
        content = content[:start_idx] + content[end_idx:]
        
        # Add to end of file
        content += "\n\n" + extracted
        
        with open('api/index.py', 'w') as f:
            f.write(content)
            
fix_api()
