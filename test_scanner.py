import asyncio
from api.index import ScanRequest, scan_single
import json

domains = ["http://google.com"]

for domain in domains:
    print(f"Testing {domain}")
    req = ScanRequest(url=domain)
    
    resp = scan_single(req)
    compliance = resp.get("technical_compliance", {})
    print(json.dumps(compliance, indent=2))

    



