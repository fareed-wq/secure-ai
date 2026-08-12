import datetime
import logging
import re
import socket
import ssl
from typing import Any, Optional

import requests
import whois
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from api.scanner.socket_helper import safe_create_connection

logger = logging.getLogger(__name__)

WHITESPACE_REGEX = re.compile(r'\s+')

def get_ip_location(ip: str) -> str:
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=(1.5, 2.5)).json()
        if res.get("status") == "success":
            country = res.get("country", "Global")
            org = res.get("org") or res.get("isp") or "Cloud"
            # Shorten verbose corporate suffixes for compact UI display
            for full, short in [("Limited", "Ltd"), ("Corporation", "Corp"), ("Incorporated", "Inc"), ("Company", "Co"), ("International", "Intl"), ("Technologies", "Tech"), ("Enterprise", "Ent")]:
                org = org.replace(full, short)
            return f"{country} ({org})"
    except Exception:
        pass
    return "Global / Cloud"


def _parse_whois_date(val: Any) -> Optional[datetime.datetime]:
    if isinstance(val, list) and val:
        val = val[0]
    if isinstance(val, datetime.datetime):
        return val
    if isinstance(val, str):
        try:
            return datetime.datetime.fromisoformat(val)
        except ValueError:
            pass
    return None


def _get_whois_data(domain: str) -> dict:
    whois_data = {
        "registrar": "Unknown",
        "creation_date": "Unknown",
        "expiration_date": "Unknown",
        "age": "Unknown"
    }
    
    def do_whois():
        return whois.whois(domain)
        
    try:
        import concurrent.futures
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(do_whois)
        try:
            w = future.result(timeout=3.0)
        except concurrent.futures.TimeoutError:
            logger.error(f"WHOIS lookup timed out for {domain} (exceeded 3.0s limit)")
            executor.shutdown(wait=False, cancel_futures=True)
            return whois_data
            
        executor.shutdown(wait=False)
        if w.registrar:
            whois_data["registrar"] = str(w.registrar)
        c_date = _parse_whois_date(w.creation_date)
        if c_date:
            whois_data["creation_date"] = c_date.strftime("%Y-%m-%d")
            now_naive = datetime.datetime.now()
            c_naive = c_date.replace(tzinfo=None) if c_date.tzinfo else c_date
            age_days = (now_naive - c_naive).days
            whois_data["age"] = (
                f"{age_days // 365} Years Old" if age_days > 365 else f"{age_days} Days Old"
            )

        e_date = _parse_whois_date(w.expiration_date)
        if e_date:
            whois_data["expiration_date"] = e_date.strftime("%Y-%m-%d")
    except concurrent.futures.TimeoutError:
        logger.error(f"WHOIS lookup timed out for {domain} (exceeded 3.0s limit)")
    except Exception as e:
        logger.error(f"WHOIS lookup failed for {domain}: {e}")
    return whois_data


def get_metadata(domain: str, response: Optional[requests.Response], original_url: Optional[str] = None) -> dict:
    # 1. Real IP Address Resolution
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        ip = "Unknown IP"

    location_or_cdn = get_ip_location(ip)

    # 2. Server Banner
    if response:
        server_header = response.headers.get("Server") or getattr(response, 'all_headers', {}).get("server")
        server = server_header if server_header else "Undisclosed (Hardened)"
    else:
        server = "Undisclosed (Hardened)"

    # 3. SSL Cert Info Extraction
    ssl_issuer = "Unknown"
    ssl_days_left = "N/A"
    ssl_days_left_int = None
    tls_version = "TLS"
    ssl_success = False
    is_expired = False
    ssl_cert_error = False
    ssl_badge = "NO SSL / UNKNOWN"

    try:
        # Pass 1: Verified Context
        ctx = ssl.create_default_context()
        with safe_create_connection((domain, 443), timeout=2.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ver = ssock.version()
                ssl_success = True
                if ver:
                    tls_version = ver

                not_after_str = cert.get('notAfter')
                if not_after_str:
                    clean_date = WHITESPACE_REGEX.sub(' ', not_after_str)
                    expiry_date = datetime.datetime.strptime(
                        clean_date, '%b %d %H:%M:%S %Y %Z'
                    ).replace(tzinfo=datetime.timezone.utc)
                    now = datetime.datetime.now(datetime.timezone.utc)
                    days_left = (expiry_date - now).days
                    ssl_days_left_int = days_left
                    ssl_days_left = f"{days_left} Days Left"
                    ssl_badge = "VALID CERTIFICATE"

                issuer_tuple = cert.get('issuer', ())
                for item in issuer_tuple:
                    for key, val in item:
                        if key in ['commonName', 'organizationName']:
                            ssl_issuer = val
                            break
    except Exception:
        ssl_cert_error = True
        # Pass 2: Unverified Fallback
        try:
            unverified_ctx = ssl._create_unverified_context()
            with safe_create_connection((domain, 443), timeout=2.5) as sock:
                with unverified_ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    ver = ssock.version()
                    if ver:
                        tls_version = ver
                    cert_der = ssock.getpeercert(binary_form=True)
                    if cert_der:
                        cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())

                        for attr in cert_obj.issuer:
                            if attr.oid._name in ['commonName', 'organizationName']:
                                ssl_issuer = attr.value
                                break

                        not_after = getattr(
                            cert_obj,
                            'not_valid_after_utc',
                            getattr(cert_obj, 'not_valid_after', None)
                        )
                        if not_after:
                            if not_after.tzinfo is None:
                                not_after = not_after.replace(tzinfo=datetime.timezone.utc)
                            now = datetime.datetime.now(datetime.timezone.utc)
                            days_left = (not_after - now).days
                            ssl_days_left_int = days_left
                            if days_left < 0:
                                is_expired = True
                                ssl_days_left = f"Expired ({abs(days_left)} Days Ago)"
                                ssl_badge = "EXPIRED"
                            elif days_left <= 30:
                                ssl_days_left = f"{days_left} Days Left"
                                ssl_badge = "RENEWAL IMMINENT"
                            else:
                                ssl_days_left = f"{days_left} Days Left"
                                ssl_badge = "VALID CERTIFICATE (UNTRUSTED)"
        except Exception as err:
            logger.error(f"Unverified cert fetch failed: {err}")

    # 4. Decoupled HTTP Status
    if response:
        rtt_ms = int(response.elapsed.total_seconds() * 1000) if hasattr(response, 'elapsed') else 0
        status = f"{response.status_code} {response.reason} ({rtt_ms}ms)"
    else:
        if ssl_cert_error:
            status = "TLS Handshake Aborted"
        else:
            status = "Connection Timeout"

    # 5. Network & Security Posture
    waf_cdn_detection = "Direct Origin"
    org_lower = location_or_cdn.lower()
    if "cloudflare" in org_lower:
        waf_cdn_detection = "Cloudflare WAF / CDN"
    elif "amazon" in org_lower or "aws" in org_lower or (response and "x-amz-cf-id" in response.headers):
        waf_cdn_detection = "AWS CloudFront"
    elif "fastly" in org_lower:
        waf_cdn_detection = "Fastly CDN"
    elif "akamai" in org_lower:
        waf_cdn_detection = "Akamai CDN"

    # WAF & Timeout Override Logic
    is_403 = response is not None and response.status_code == 403
    rtt_val = getattr(response, 'elapsed', None)

    if is_403:
        waf_cdn_detection = "PROTECTED BY WAF" if ssl_success else waf_cdn_detection

    # Performance Rating & HTTP Badge
    if response:
        rtt_ms_val = int(rtt_val.total_seconds() * 1000) if rtt_val else 0
        if rtt_ms_val > 1500 or is_403:
            performance_rating = "TIMEOUT" if is_403 else "High Latency"
        else:
            if response.status_code >= 500:
                performance_rating = "SERVER ERROR"
            elif response.status_code >= 400:
                performance_rating = "CLIENT ERROR"
            else:
                performance_rating = (
                    "Optimal Latency" if rtt_ms_val < 150
                    else "Average Latency" if rtt_ms_val < 500
                    else "High Latency"
                )
    else:
        if ssl_cert_error:
            performance_rating = "NO HTTP RESPONSE"
        else:
            performance_rating = "REQUEST TIMEOUT"

    # IPv6 Support
    ipv6_supported = False
    try:
        ipv6_info = socket.getaddrinfo(domain, None, socket.AF_INET6)
        if ipv6_info:
            ipv6_supported = True
    except Exception:
        pass

    # Protocol & HTTPS Enforcement
    http_protocol = "HTTP/1.1"
    https_enforced = "HTTP Exposed"
    clean_redirect = "No Auto-Redirect"

    if response:
        if response.url.startswith("https"):
            https_enforced = "HTTPS Enforced"

        if original_url and original_url.startswith("https"):
            clean_redirect = "Direct Secure"
        else:
            if response.history and any(r.status_code in [301, 302, 307, 308] for r in response.history):
                clean_redirect = "Clean 301 Redirect"

        alt_svc = response.headers.get("Alt-Svc", "")
        if "h3=" in alt_svc:
            http_protocol = "HTTP/3 (QUIC)"
        elif "h2=" in alt_svc or response.url.startswith("https"):
            http_protocol = "HTTP/2"
    else:
        # Timeout fallback for HTTPS
        if original_url and original_url.startswith("https") and ssl_success:
            https_enforced = "HTTPS Enforced"
            clean_redirect = "HTTPS ACTIVE (PROBE TIMED OUT)"

    # Protocol helper flags for scan_url Network findings
    http2_supported = http_protocol in ["HTTP/2", "HTTP/3 (QUIC)"]
    http3_supported = http_protocol == "HTTP/3 (QUIC)"

    # WHOIS Lookup
    whois_data = _get_whois_data(domain)

    return {
        "ip_address": ip,
        "location_or_cdn": location_or_cdn,
        "server_header": server,
        "http_status": status,
        "ssl_issuer": ssl_issuer if ssl_issuer != "Unknown" else "Valid SSL" if ssl_success else "Unknown",
        "ssl_days_left": ssl_days_left,
        "ssl_days_left_int": ssl_days_left_int,
        "ssl_badge": ssl_badge,
        "tls_version": tls_version,
        "waf_cdn_detection": waf_cdn_detection,
        "performance_rating": performance_rating,
        "ipv6_supported": ipv6_supported,
        "http_protocol": http_protocol,
        "http2_supported": http2_supported,
        "http3_supported": http3_supported,
        "https_enforced": https_enforced,
        "clean_redirect": clean_redirect,
        "whois": whois_data
    }


def check_liveness(hostname: str, timeout: float = 2.5) -> bool:
    try:
        with safe_create_connection((hostname, 443), timeout=timeout):
            return True
    except Exception:
        try:
            with safe_create_connection((hostname, 80), timeout=timeout):
                return True
        except Exception:
            return False
