import time
import json
from api.scanner.orchestrator import scan_url

target = "https://www.hkbk.edu.in"
print(f"Running 5 consecutive scans against {target}...\n")

for i in range(1, 6):
    print(f"--- Scan {i} ---")
    start_time = time.time()
    
    # Run the scan
    result = scan_url(target)
    
    end_time = time.time()
    total_duration = end_time - start_time
    
    # We might not have all timings detailed in the result, but we'll print what we have
    status = result.get('status', 'N/A')
    score = result.get('score', 'N/A')
    issues = result.get('issues', 0)
    passed = result.get('passed', 0)
    informational = result.get('informational', 0)
    inconclusive = result.get('inconclusive', 0)
    
    print(f"Total Duration: {total_duration:.2f}s")
    print(f"Status: {status}")
    print(f"Score: {score}")
    print(f"Findings: Issues={issues}, Passed={passed}, Info={informational}, Inconclusive={inconclusive}")
    
    metrics = result.get('metadata', {}).get('metrics', {})
    if metrics:
        print(f"Baseline Request Duration: {metrics.get('baseline_request_duration', 'N/A')}")
        print(f"Retries: {metrics.get('retry_count', 'N/A')}")
        print(f"Timeouts: {metrics.get('timeout_count', 'N/A')}")
        for mod, duration in metrics.get('module_durations', {}).items():
            print(f"  {mod}: {duration:.2f}s")
    else:
        print("Detailed metrics not found in result.")
    
    print("\n")
