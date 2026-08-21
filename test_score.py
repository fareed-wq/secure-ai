import json
from api.scanner.orchestrator import scan_url

results = []
for i in range(4):
    r = scan_url('https://google.com')
    results.append({'score': r.get('score'), 'findings': sorted([f['name'] for f in r.get('findings', [])])})

for i, res in enumerate(results):
    print(f'\n--- Run {i+1} ---')
    print(f'Score: {res["score"]}')
    print(f'Findings count: {len(res["findings"])}')
    for f in res["findings"]:
        print(f' - {f}')
