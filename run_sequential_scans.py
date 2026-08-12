import asyncio
import sys
import time
from api.scanner.orchestrator import scan_url

async def main():
    target = "https://example.com"
    print(f"Running 5 sequential scans against {target}")
    
    results = []
    for i in range(1, 6):
        print(f"\n--- Scan {i} ---")
        start = time.time()
        res = await asyncio.to_thread(scan_url, target, False)
        duration = time.time() - start
        
        status = res.get("status")
        score = res.get("score")
        findings = len(res.get("findings", []))
        
        results.append({
            "status": status,
            "score": score,
            "findings_count": findings,
            "duration": duration
        })
        
        print(f"Status: {status}, Score: {score}, Findings: {findings}, Time: {duration:.2f}s")
        
    print("\n--- Summary ---")
    for idx, r in enumerate(results):
        print(f"Scan {idx+1}: Status={r['status']}, Score={r['score']}, Findings={r['findings_count']}")
        
    # Check consistency
    scores = set(r["score"] for r in results if r["status"] == "COMPLETED")
    findings_counts = set(r["findings_count"] for r in results if r["status"] == "COMPLETED")
    
    if len(scores) <= 1 and len(findings_counts) <= 1:
        print("Consistency: PASS")
    else:
        print("Consistency: FAIL (Scores or findings vary across successful scans)")

if __name__ == "__main__":
    asyncio.run(main())
