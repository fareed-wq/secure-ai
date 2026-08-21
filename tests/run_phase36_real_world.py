import time
import asyncio
from api.scanner.orchestrator import scan_url

async def run_test():
    target = "https://example.com"
    print(f"Starting Phase 36 Real-World Scan against {target}...")
    
    start_time = time.time()
    
    # Run the passive scan
    report_data = await asyncio.to_thread(scan_url, target, False)
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"Scan completed in {duration:.2f} seconds.")
    
    # Assert performance budget
    if duration > 25.0:
        print("FAIL: Scan exceeded 25-second global budget.")
        exit(1)
        
    print("PASS: Performance budget satisfied.")
    
    # Check that score and findings exist
    if 'score' not in report_data or 'findings' not in report_data:
        print("FAIL: Invalid report_data structure.")
        exit(1)
        
    print("PASS: Report data structure is valid.")
    print("\nPhase 36 Validation Successful.")

if __name__ == '__main__':
    asyncio.run(run_test())
