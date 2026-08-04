import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import logging
import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from abc import ABC, abstractmethod

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Website Security Posture Checker (Modular)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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


# --- PLUGIN ARCHITECTURE ---

class ScannerModule(ABC):
    @abstractmethod
    def run(self, url: str, hostname: str) -> list[dict]:
        """
        Executes the module check. Must return a list of finding dictionaries:
        {
            "name": str,
            "severity": "Critical"|"High"|"Medium"|"Low"|"Informational"|"Passed",
            "description": str,
            "evidence": str,
            "confidence": str,
            "remediation": str,
            "owasp": str
        }
        """
        pass


class SSLTLSModule(ScannerModule):
    def run(self, url: str, hostname: str) -> list[dict]:
        findings = []
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    
                    findings.append({
                        "name": "Valid SSL/TLS Certificate",
                        "severity": "Passed",
                        "description": "The server presents a valid TLS certificate.",
                        "evidence": f"Version: {version}, Issuer: {cert.get('issuer')}",
                        "confidence": "High",
                        "remediation": "N/A",
                        "owasp": "A02: Cryptographic Failures"
                    })
        except Exception as e:
            findings.append({
                "name": "SSL/TLS Connection Failure",
                "severity": "High",
                "description": "Failed to establish a secure TLS connection with the host.",
                "evidence": str(e),
                "confidence": "High",
                "remediation": "Ensure the server supports standard TLS protocols and has a valid certificate.",
                "owasp": "A02: Cryptographic Failures"
            })
        return findings


class SecurityHeadersModule(ScannerModule):
    def run(self, url: str, hostname: str) -> list[dict]:
        findings = []
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            headers = response.headers
        except requests.exceptions.RequestException as e:
            findings.append({
                "name": "HTTP Request Failed",
                "severity": "High",
                "description": "Failed to fetch HTTP headers from the target.",
                "evidence": str(e),
                "confidence": "High",
                "remediation": "Ensure the target is reachable over HTTP/HTTPS.",
                "owasp": "A05: Security Misconfiguration"
            })
            return findings

        # HSTS
        if "Strict-Transport-Security" not in headers:
            findings.append({
                "name": "Missing Strict-Transport-Security (HSTS)",
                "severity": "High",
                "description": "Missing HSTS allows SSL-stripping attacks.",
                "evidence": "Strict-Transport-Security header is absent.",
                "confidence": "High",
                "remediation": "Add the Strict-Transport-Security header.",
                "owasp": "A05: Security Misconfiguration"
            })
        else:
            findings.append({
                "name": "Strict-Transport-Security (HSTS) Configured",
                "severity": "Passed",
                "description": "HSTS is present.",
                "evidence": headers["Strict-Transport-Security"],
                "confidence": "High",
                "remediation": "N/A",
                "owasp": "A05: Security Misconfiguration"
            })

        # CSP
        if "Content-Security-Policy" not in headers:
            findings.append({
                "name": "Missing Content-Security-Policy (CSP)",
                "severity": "High",
                "description": "Missing CSP allows XSS and data injection attacks.",
                "evidence": "Content-Security-Policy header is absent.",
                "confidence": "High",
                "remediation": "Implement a Content-Security-Policy.",
                "owasp": "A05: Security Misconfiguration"
            })

        # X-Frame-Options
        if "X-Frame-Options" not in headers:
            findings.append({
                "name": "Missing X-Frame-Options",
                "severity": "Medium",
                "description": "Missing XFO allows clickjacking attacks.",
                "evidence": "X-Frame-Options header is absent.",
                "confidence": "High",
                "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN.",
                "owasp": "A05: Security Misconfiguration"
            })

        # X-Content-Type-Options
        if "X-Content-Type-Options" not in headers:
            findings.append({
                "name": "Missing X-Content-Type-Options",
                "severity": "Low",
                "description": "Missing this can allow MIME-sniffing attacks.",
                "evidence": "X-Content-Type-Options header is absent.",
                "confidence": "High",
                "remediation": "Add X-Content-Type-Options: nosniff.",
                "owasp": "A05: Security Misconfiguration"
            })

        # Referrer-Policy
        if "Referrer-Policy" not in headers:
            findings.append({
                "name": "Missing Referrer-Policy",
                "severity": "Low",
                "description": "Controls what leaks via the Referer header.",
                "evidence": "Referrer-Policy header is absent.",
                "confidence": "High",
                "remediation": "Add Referrer-Policy.",
                "owasp": "A05: Security Misconfiguration"
            })

        # Permissions-Policy
        if "Permissions-Policy" not in headers and "Feature-Policy" not in headers:
            findings.append({
                "name": "Missing Permissions-Policy",
                "severity": "Informational",
                "description": "Missing Permissions-Policy header.",
                "evidence": "Permissions-Policy header is absent.",
                "confidence": "High",
                "remediation": "Add Permissions-Policy.",
                "owasp": "A05: Security Misconfiguration"
            })

        # Cookies
        set_cookie = headers.get("Set-Cookie")
        if set_cookie:
            for cookie in set_cookie.split(","):
                name = cookie.split("=")[0].strip()
                if "httponly" not in cookie.lower():
                    findings.append({
                        "name": f"Missing HttpOnly Flag on Cookie: {name}",
                        "severity": "Medium",
                        "description": "Cookie can be accessed via client-side scripts.",
                        "evidence": f"Cookie {name} lacks HttpOnly.",
                        "confidence": "High",
                        "remediation": "Add HttpOnly flag to cookies.",
                        "owasp": "A05: Security Misconfiguration"
                    })
                if url.startswith("https") and "secure" not in cookie.lower():
                    findings.append({
                        "name": f"Missing Secure Flag on Cookie: {name}",
                        "severity": "Medium",
                        "description": "Cookie transmitted in cleartext if sent over HTTP.",
                        "evidence": f"Cookie {name} lacks Secure.",
                        "confidence": "High",
                        "remediation": "Add Secure flag to cookies.",
                        "owasp": "A02: Cryptographic Failures"
                    })
        
        return findings

# Engine Registry
REGISTERED_MODULES = [
    SSLTLSModule(),
    SecurityHeadersModule()
]

def scan_url(url: str) -> dict:
    hostname = urlparse(url).hostname
    if not hostname:
        return {"url": url, "error": "Could not parse a hostname from that URL."}
    if not is_public_hostname(hostname):
        return {"url": url, "error": "That host resolves to a private/internal address and can't be scanned."}

    all_findings = []
    
    # Run modules concurrently with a short timeout to respect Vercel Hobby limits
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(mod.run, url, hostname): mod for mod in REGISTERED_MODULES}
        for future in as_completed(futures):
            mod = futures[future]
            try:
                mod_findings = future.result(timeout=6)
                all_findings.extend(mod_findings)
            except Exception as e:
                logger.error(f"Module {mod.__class__.__name__} failed: {e}")
                all_findings.append({
                    "name": f"Module Crash: {mod.__class__.__name__}",
                    "severity": "Informational",
                    "description": "The scanner module crashed or timed out during execution.",
                    "evidence": str(e),
                    "confidence": "High",
                    "remediation": "Check scanner logs.",
                    "owasp": "N/A"
                })

    # Calculate issues
    issue_count = sum(1 for f in all_findings if f["severity"] in ["Critical", "High", "Medium", "Low"])

    return {
        "url": url,
        "findings": all_findings,
        "potential_issues_count": issue_count,
        "disclaimer": (
            "Passive scan only. Modular engine execution."
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
