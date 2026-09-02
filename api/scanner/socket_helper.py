import socket
import time
import logging

logger = logging.getLogger(__name__)

def safe_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, socket_options=None):
    """
    A drop-in replacement for socket.create_connection that strictly enforces
    SSRF protections by validating all resolved IPs before connecting, and
    connecting directly to the validated IP to prevent DNS Rebinding (TOCTOU).
    """
    host, port = address
    err = None
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise OSError(f"Could not resolve {host}: {e}")
        
    # Validate EVERY resolved IP address
    from api.scanner.transport import is_public_hostname
    for res in infos:
        af, socktype, proto, canonname, sa = res
        ip = sa[0]
        if not is_public_hostname(ip):
            raise ValueError(f"SSRF Protection blocked raw socket connection to non-public IP: {ip}")
            
    # Connect to the first validated IP
    for res in infos:
        af, socktype, proto, canonname, sa = res
        sock = None
        ip = sa[0]
        family_str = "IPv6" if af == socket.AF_INET6 else ("IPv4" if af == socket.AF_INET else str(af))
        start_time = time.monotonic()
        try:
            sock = socket.socket(af, socktype, proto)
            if socket_options:
                for opt in socket_options:
                    sock.setsockopt(*opt)
            if source_address:
                sock.bind(source_address)
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            sock.connect(sa)
            elapsed = time.monotonic() - start_time
            logger.info(f"safe_connect host={host} port={port} family={family_str} ip={ip} success elapsed={elapsed:.2f}s")
            return sock
        except OSError as _:
            elapsed = time.monotonic() - start_time
            errno_val = getattr(_, 'errno', None)
            logger.info(f"safe_connect host={host} port={port} family={family_str} ip={ip} failed {type(_).__name__} errno={errno_val} elapsed={elapsed:.2f}s")
            err = _
            if sock is not None:
                sock.close()
                
    if err is not None:
        raise err
    raise OSError("getaddrinfo returns an empty list")
