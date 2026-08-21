import os
import sys
import time
sys.path.insert(0, os.path.abspath('.'))

from api.scanner.orchestrator import scan_url

if __name__ == "__main__":
    url = "https://google.com"
    print(f"Starting 5 sequential scans of {url}...")
    success_count = 0
    for i in range(5):
        try:
            start_time = time.time()
            print(f"Scan {i+1}/5 starting...")
            result = scan_url(url)
            duration = time.time() - start_time
            print(f"  Score: {result.get('score')}")
            print(f"  Findings: {len(result.get('findings', []))}")
            print(f"  Duration: {duration:.2f}s")
            success_count += 1
        except Exception as e:
            print(f"  Scan {i+1} failed with exception: {e}")
            
    print(f"\nCompleted {success_count}/5 scans successfully.")
    sys.exit(0 if success_count == 5 else 1)
