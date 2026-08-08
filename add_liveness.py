with open('api/index.py', 'r', encoding='utf-8') as f:
    content = f.read()

liveness_code = '''
def check_liveness(hostname: str, timeout: float = 2.5) -> bool:
    try:
        with socket.create_connection((hostname, 443), timeout=timeout):
            return True
    except Exception:
        try:
            with socket.create_connection((hostname, 80), timeout=timeout):
                return True
        except Exception:
            return False

'''

if 'def check_liveness' not in content:
    content = content.replace('def scan_url(url: str, probe_subdomains: bool = False) -> dict:', liveness_code + '\ndef scan_url(url: str, probe_subdomains: bool = False) -> dict:')
    
    abort_code = '''
    if not check_liveness(hostname):
        return {"url": url, "error": "Scan Failed: Target is unresponsive, down, or aggressively blocking our scanner (WAF dropped packets)."}

    metadata = {}
'''
    content = content.replace('    metadata = {}', abort_code)
    
    with open('api/index.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Liveness check added!")
else:
    print("Already exists!")
