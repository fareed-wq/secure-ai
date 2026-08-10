import sys
import time
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from api.scanner.orchestrator import scan_url

def main():
    target_url = "http://localhost:8000"  # A fast local target, assuming it might be up or down
    print(f"Benchmarking scanner against {target_url}...")
    
    start_time = time.time()
    
    # We will just run the orchestrator once
    result = scan_url(target_url, probe_subdomains=False)
    
    end_time = time.time()
    
    print("\n--- BENCHMARK RESULTS ---")
    print(f"Total Scan Duration: {end_time - start_time:.2f} seconds")
    print(f"Total Findings: {len(result.get('findings', []))}")
    print(f"Score: {result.get('score', 0)}")
    print(f"Metadata IP: {result.get('metadata', {}).get('ip_address', 'Unknown')}")
    
    # Analyze if the duration is well within 25 seconds
    if end_time - start_time > 25:
        print("\n[WARNING] Scan exceeded the 25 second budget!")
    else:
        print("\n[PASS] Scan completed within budget.")

if __name__ == "__main__":
    main()
