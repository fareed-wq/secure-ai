import sys
import time
from api.scanner.orchestrator import scan_url

def main():
    targets = [
        "https://example.com",
    ]
    
    for target in targets:
        print(f"\nRunning real-world validation against {target}...")
        start_time = time.time()
        
        try:
            result = scan_url(target, probe_subdomains=False)
            end_time = time.time()
            duration = end_time - start_time
            
            print(f"Total Scan Duration: {duration:.2f} seconds")
            print(f"Total Findings: {len(result.get('findings', []))}")
            
            if duration > 25.0:
                print(f"[FAIL] Scan took {duration:.2f}s, exceeding 25-second budget.")
                sys.exit(1)
            else:
                print(f"[PASS] Scan completed efficiently.")
                
            if result.get("error"):
                print(f"[ERROR] Result contained error: {result['error']}")
                
        except Exception as e:
            print(f"[ERROR] Exception during scan: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
