import socket
import errno

def safe_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, socket_options=None):
    """
    A drop-in replacement for socket.create_connection that strictly enforces
    SSRF protections by validating all resolved IPs before connecting, and
    connecting directly to the validated IP to prevent DNS Rebinding (TOCTOU).
    """
    host, port = address
    err = None
    meaningful_err = None
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
            return sock
        except OSError as _:
            err = _
            errno_val = getattr(_, 'errno', None)
            if errno_val != errno.EADDRNOTAVAIL:
                meaningful_err = _
            if sock is not None:
                sock.close()
                
    if meaningful_err is not None:
        raise meaningful_err
    if err is not None:
        raise err
    raise OSError("getaddrinfo returns an empty list")
