import re

def fix_user_none():
    with open('api/index.py', 'r') as f:
        content = f.read()

    # fix user.get("sub") to user and user.get("sub")
    content = content.replace("if not entitlements.can_share_scan or not user.get(\"sub\"):", "if not entitlements.can_share_scan or not user or not user.get(\"sub\"):")
    content = content.replace("if not user.get(\"sub\"):", "if not user or not user.get(\"sub\"):")
    
    with open('api/index.py', 'w') as f:
        f.write(content)
            
fix_user_none()
