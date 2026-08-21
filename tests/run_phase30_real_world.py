import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import requests
from api.scanner.modules.auth_session_security import AuthenticationSessionSecurityModule
from api.scanner.modules.http_security import AdvancedCookieModule, SecurityHeadersModule

def run_real_world(target: str):
    print(f"[*] Running Phase 30 Real-World Validation against {target}")
    
    session = requests.Session()
    
    modules = [
        AuthenticationSessionSecurityModule(),
        AdvancedCookieModule(),
        SecurityHeadersModule()
    ]
    
    for mod in modules:
        print(f"\n[+] Executing {mod.module_name}...")
        findings = mod.run(target, target.replace("https://", "").replace("http://", "").split('/')[0], session)
        for f in findings:
            print(f"  - [{f['severity']}] {f['name']}")
            print(f"    {str(f['evidence'])[:100]}...")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    run_real_world(target)
