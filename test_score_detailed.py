import json
from api.scanner.orchestrator import scan_url

results = []
for i in range(5):
    r = scan_url('https://google.com')
    
    score = r.get('score')
    findings = r.get('findings', [])
    
    high = [f for f in findings if f.get('severity') == 'High']
    medium = [f for f in findings if f.get('severity') == 'Medium']
    low = [f for f in findings if f.get('severity') == 'Low']
    inconclusive = [f for f in findings if f.get('severity') == 'Inconclusive']
    
    # Try to extract penalties if returned (sometimes part of scan_result['penalties'] or from score calculation)
    # The scan_url returns the final dictionary which might contain 'penalties'
    penalties = r.get('penalties', [])
    
    res = {
        'run': i+1,
        'score': score,
        'high_count': len(high),
        'medium_count': len(medium),
        'low_count': len(low),
        'inconclusive_count': len(inconclusive),
        'findings': sorted([f['name'] for f in findings]),
        'penalties': penalties,
        'inconclusive_findings': [f['name'] for f in inconclusive],
    }
    results.append(res)
    
print(json.dumps(results, indent=2))
