import ssl
import socket

domain = "expired.badssl.com"

print("Trying getpeercert(binary_form=True) with unverified context")
try:
    unverified_ctx = ssl._create_unverified_context()
    with socket.create_connection((domain, 443), timeout=3) as sock:
        with unverified_ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            print(f"cert_der length: {len(cert_der) if cert_der else 0}")
            
            import _ssl
            cert_dict = _ssl._test_decode_cert(cert_der)
            print(f"Decoded dict issuer: {cert_dict.get('issuer')}")
            print(f"Decoded dict notAfter: {cert_dict.get('notAfter')}")
except Exception as e:
    print(f"Error 1: {e}")
