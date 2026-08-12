import requests
import socket
import ssl
import sys

target = "www.softiintel.com"
url = f"https://{target}"

print(f"=== Testing requests against {url} ===")
try:
    resp = requests.get(url, timeout=5)
    print(f"SUCCESS: {resp.status_code}")
except Exception as e:
    print(f"FAILED: {e}")

print(f"\n=== Testing requests with verify=False ===")
try:
    resp = requests.get(url, verify=False, timeout=5)
    print(f"SUCCESS: {resp.status_code}")
except Exception as e:
    print(f"FAILED: {e}")

print(f"\n=== Testing raw SSL (default context) ===")
try:
    context = ssl.create_default_context()
    with socket.create_connection((target, 443), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=target) as ssock:
            print(f"SUCCESS: Negotiated {ssock.version()} with cipher {ssock.cipher()}")
except Exception as e:
    print(f"FAILED: {e}")

print(f"\n=== Testing raw SSL (TLSv1.2 only) ===")
try:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((target, 443), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=target) as ssock:
            print(f"SUCCESS: Negotiated {ssock.version()} with cipher {ssock.cipher()}")
except Exception as e:
    print(f"FAILED: {e}")

print(f"\n=== Testing raw SSL (TLSv1.3 only) ===")
try:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection((target, 443), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=target) as ssock:
            print(f"SUCCESS: Negotiated {ssock.version()} with cipher {ssock.cipher()}")
except Exception as e:
    print(f"FAILED: {e}")

print(f"\n=== Testing safe_request from secure-AI (if available) ===")
try:
    sys.path.insert(0, 'd:\\secure-AI')
    from api.scanner.transport import safe_request
    resp = safe_request("GET", url)
    print(f"SUCCESS: {resp.status_code if resp else 'No response'}")
except Exception as e:
    print(f"FAILED: {e}")
