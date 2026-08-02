import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

app = FastAPI(title="Website Security Posture Checker")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this to your actual front-end origin before shipping
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("url must not be empty")
    if "://" not in value:
        value = "https://" + value
    return value


class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def _normalize(cls, v: str) -> str:
        return normalize_url(v)


class BatchScanRequest(BaseModel):
    urls: list[str]

    @field_validator("urls")
    @classmethod
    def _normalize_all(cls, v: list[str]) -> list[str]:
        return [normalize_url(u) for u in v]


def is_public_hostname(hostname: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True


def check_ssl_tls(hostname: str) -> dict:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "status": "OK",
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter", "N/A"),
                    "version": ssock.version(),
                }
    except Exception as e:
        return {"status": "Error", "message": str(e)}


SECURITY_HEADERS = {
    "Strict-Transport-Security": "Missing HSTS can allow SSL-stripping attacks.",
    "Content-Security-Policy": "A CSP helps mitigate XSS and data-injection attacks.",
    "X-Frame-Options": "Missing this can allow clickjacking.",
    "X-Content-Type-Options": "Missing this can allow MIME-sniffing attacks.",
    "Referrer-Policy": "Controls what leaks via the Referer header.",
    "X-Permitted-Cross-Domain-Policies": "Controls Flash/PDF cross-domain data loading.",
}


def check_security_headers(url: str) -> list:
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return [f"Error fetching URL: {e}"]

    headers = response.headers
    findings = []

    for name, note in SECURITY_HEADERS.items():
        findings.append(f"{name}: {headers[name]}" if name in headers else f"Missing {name}. {note}")

    if "Permissions-Policy" in headers:
        findings.append(f"Permissions-Policy: {headers['Permissions-Policy']}")
    elif "Feature-Policy" in headers:
        findings.append(f"Feature-Policy: {headers['Feature-Policy']}")
    else:
        findings.append("Missing Permissions-Policy/Feature-Policy header.")

    set_cookie = headers.get("Set-Cookie")
    if not set_cookie:
        findings.append("No 'Set-Cookie' header found in response.")
    else:
        for cookie in set_cookie.split(","):
            name = cookie.split("=")[0].strip()
            if "httponly" not in cookie.lower():
                findings.append(f"Cookie `{name}` missing HttpOnly flag.")
            if url.startswith("https") and "secure" not in cookie.lower():
                findings.append(f"Cookie `{name}` missing Secure flag.")

    return findings


def scan_url(url: str) -> dict:
    hostname = urlparse(url).hostname
    if not hostname:
        return {"url": url, "error": "Could not parse a hostname from that URL."}
    if not is_public_hostname(hostname):
        return {"url": url, "error": "That host resolves to a private/internal address and can't be scanned."}

    with ThreadPoolExecutor(max_workers=2) as pool:
        ssl_future = pool.submit(check_ssl_tls, hostname)
        headers_future = pool.submit(check_security_headers, url)
        ssl_info = ssl_future.result()
        header_findings = headers_future.result()

    return {
        "url": url,
        "ssl_tls": ssl_info,
        "header_findings": header_findings,
        "potential_issues_count": sum(1 for f in header_findings if f.startswith("Missing")),
        "disclaimer": (
            "Passive scan only: public TLS certificate info and HTTP security "
            "headers. Not active penetration testing, and not a guarantee of security."
        ),
    }


@app.post("/api/scan")
def scan_single(req: ScanRequest):
    return scan_url(req.url)


@app.post("/api/scan/batch")
def scan_batch(req: BatchScanRequest):
    workers = min(10, len(req.urls)) or 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(scan_url, req.urls))
    return {"results": results}
