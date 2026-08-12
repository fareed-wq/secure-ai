import time
from api.scanner.orchestrator import scan_url

target = 'https://www.hkbk.edu.in'

print('Starting 5 consecutive scans against:', target)
for i in range(1, 6):
    print(f'\n--- Scan {i} ---')
    t0 = time.time()
    try:
        result = scan_url(target)
        duration = time.time() - t0
        
        status = result.status if hasattr(result, 'status') else result.get('status', 'unknown')
        score = result.score if hasattr(result, 'score') else result.get('score', 0)
        
        findings = result.findings if hasattr(result, 'findings') else result.get('findings', [])
        finding_count = len(findings)
        
        error = result.error if hasattr(result, 'error') else result.get('error', None)
        
        print(f'Total scan time: {duration:.2f}s')
        
        if status == 'success':
            print('HTTP connection success: Yes')
        else:
            print('HTTP connection success: No')
            
        if error:
            print(f'Exact failure reason: {error}')
            
        print(f'Final status: {status}')
        print(f'Score: {score}')
        print(f'Finding count: {finding_count}')
        
    except Exception as e:
        duration = time.time() - t0
        print(f'Total scan time: {duration:.2f}s')
        print('HTTP connection success: No')
        print(f'Exact failure reason: {str(e)}')
        print('Final status: exception')
        print('Score: N/A')
        print('Finding count: N/A')
