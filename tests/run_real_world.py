import json
import time
from api.index import scan_url

TARGETS = [
    "https://example.com",           # Static / minimal
    "https://api.github.com",        # JSON API
    "https://httpbin.org",           # API / Headers
    "https://reactjs.org",           # SPA / Modern
]

results = []

print("Starting real-world scanner validation...")
for target in TARGETS:
    print(f"Scanning {target}...")
    start = time.time()
    try:
        data = scan_url(target, probe_subdomains=False)
        data["_duration"] = time.time() - start
        results.append(data)
        print(f"  [+] Score: {data.get('score')} | Findings: {len(data.get('findings', []))}")
    except Exception as e:
        print(f"  [-] Failed: {e}")

with open("tests/real_world_results.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print("Scan complete. Results saved to tests/real_world_results.json")
