import logging
import requests
from unittest.mock import MagicMock
from api.scanner.modules.javascript_security import JavaScriptSecurityModule
import time

logging.basicConfig(level=logging.INFO)

def main():
    targets = [
        "https://example.com",
        "https://react.dev"
    ]
    
    session = requests.Session()
    module = JavaScriptSecurityModule()
    
    print("Starting Phase 27 Real-World Validation (Read-Only)...")
    
    for url in targets:
        print(f"\\n--- Scanning {url} ---")
        start_time = time.time()
        
        try:
            findings = module.run(url, url.replace("https://", ""), session)
            
            print(f"Completed in {time.time() - start_time:.2f}s")
            print(f"Total findings: {len(findings)}")
            
            for finding in findings:
                print(f"- [{finding['severity']}] {finding['name']}")
                print(f"  Confidence: {finding['confidence']}")
                print(f"  Evidence: {str(finding['evidence'])[:100]}...")
                
        except Exception as e:
            print(f"Error scanning {url}: {e}")
            
if __name__ == '__main__':
    main()
