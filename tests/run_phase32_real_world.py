import os
import sys
import time
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from api.index import scan_url

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    print(f"Running Phase 32 Real World Test against {url}")
    
    start_time = time.time()
    result = scan_url(url)
    duration = time.time() - start_time
    
    findings = result.get('findings', [])
    score = result.get('score', 100)
    
    print(f"\\n### PHASE 32 DISCOVERY REPORT ###")
    print(f"Scan Duration: {duration:.2f} seconds")
    print(f"Final Score: {score}")
    print(f"Total Findings: {len(findings)}\\n")
    for f in findings:
        cvss_str = f.get('cvss', 'N/A')
        print(f"[{f.get('severity', 'Info')}] {f.get('name', 'Unknown')} (CVSS: {cvss_str})")
        print(f"  Description: {f.get('description', '')}")
        print(f"  Evidence: {str(f.get('evidence', ''))[:200]}\\n")
