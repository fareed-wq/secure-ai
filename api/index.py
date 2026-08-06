import ipaddress
import socket
import ssl
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
import logging
from http.cookiejar import DefaultCookiePolicy
import requests
from requests.adapters import HTTPAdapter
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, HTMLResponse
from pydantic import BaseModel, field_validator
from abc import ABC, abstractmethod
import datetime
from io import BytesIO

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- CENTRAL CONFIGURATION ---
class Config:
    REQUEST_TIMEOUT = 6.0
    MAX_REDIRECTS = 5
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    THREAD_POOL_SIZE = 15
    COMMON_SUBDOMAINS = ["trcadmin", "console", "s3", "s3b", "beta", "api", "dev"]
    SEVERITY_WEIGHTS = {
        "Critical": -15,
        "High": -10,
        "Medium": -5,
        "Low": -2,
        "Informational": 0,
        "Passed": 0
    }
    SCORE_THRESHOLDS = {
        "A+": 95,
        "A": 90,
        "B": 80,
        "C": 70,
        "D": 60,
        "F": 0
    }

# --- REMEDIATION SNIPPETS DATABASE ---
REMEDIATION_SNIPPETS = {
    "Missing Strict-Transport-Security (HSTS)": {
        "nginx": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
        "apache": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
        "vercel": '{\n  "headers": [{\n    "source": "/(.*)",\n    "headers": [{ "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload" }]\n  }]\n}',
        "cloudflare": 'Rules -> Transform Rules -> Modify Response Header -> Set "Strict-Transport-Security" to "max-age=31536000; includeSubDomains; preload"'
    },
    "Missing Content-Security-Policy (CSP)": {
        "nginx": 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\';" always;',
        "apache": 'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\';"',
        "vercel": '{\n  "headers": [{\n    "source": "/(.*)",\n    "headers": [{ "key": "Content-Security-Policy", "value": "default-src \'self\';" }]\n  }]\n}',
        "cloudflare": 'Rules -> Modify Response Header -> Set "Content-Security-Policy" to "default-src \'self\';"'
    },
    "Weak Content-Security-Policy (CSP)": {
        "nginx": 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\';" always;',
        "apache": 'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\';"',
        "vercel": 'Remove \'unsafe-inline\' and \'unsafe-eval\' from script-src in your vercel.json header config.',
        "cloudflare": 'Update Content-Security-Policy header rule to remove unsafe directives.'
    },
    "Missing X-Frame-Options": {
        "nginx": 'add_header X-Frame-Options "DENY" always;',
        "apache": 'Header always set X-Frame-Options "DENY"',
        "vercel": '{\n  "headers": [{ "source": "/(.*)", "headers": [{ "key": "X-Frame-Options", "value": "DENY" }] }]\n}',
        "cloudflare": 'Rules -> Modify Response Header -> Set "X-Frame-Options" to "DENY"'
    },
    "Missing X-Content-Type-Options": {
        "nginx": 'add_header X-Content-Type-Options "nosniff" always;',
        "apache": 'Header always set X-Content-Type-Options "nosniff"',
        "vercel": '{\n  "headers": [{ "source": "/(.*)", "headers": [{ "key": "X-Content-Type-Options", "value": "nosniff" }] }]\n}',
        "cloudflare": 'Rules -> Modify Response Header -> Set "X-Content-Type-Options" to "nosniff"'
    },
    "Missing Referrer-Policy": {
        "nginx": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        "apache": 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        "vercel": '{\n  "headers": [{ "source": "/(.*)", "headers": [{ "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" }] }]\n}',
        "cloudflare": 'Rules -> Modify Response Header -> Set "Referrer-Policy" to "strict-origin-when-cross-origin"'
    },
    "Missing Permissions-Policy": {
        "nginx": 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
        "apache": 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"',
        "vercel": '{\n  "headers": [{ "source": "/(.*)", "headers": [{ "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()" }] }]\n}',
        "cloudflare": 'Rules -> Modify Response Header -> Set "Permissions-Policy" to "camera=(), microphone=(), geolocation=()"'
    },
    "Exposed .env Configuration File": {
        "nginx": 'location ~ /\\.env {\n    deny all;\n    return 404;\n}',
        "apache": '<Files ".env">\n    Require all denied\n</Files>',
        "vercel": 'Ensure .env is listed in .gitignore and not exported in public directory builds.',
        "cloudflare": 'Security -> WAF -> Custom Rules -> Block URI Path equals "/.env"'
    },
    "Exposed .git Repository": {
        "nginx": 'location ~ /\\.git {\n    deny all;\n    return 404;\n}',
        "apache": '<DirectoryMatch "/\\.git">\n    Require all denied\n</DirectoryMatch>',
        "vercel": 'Ensure .git folder is excluded from deployed output.',
        "cloudflare": 'Security -> WAF -> Custom Rules -> Block URI Path starts_with "/.git"'
    },
    "Missing SPF Record": {
        "dns_record": 'Type: TXT | Name: @ | Value: v=spf1 include:_spf.google.com ~all',
        "note": 'Publish an SPF TXT record at your domain root authorizing valid mail servers.'
    },
    "Missing DMARC Policy": {
        "dns_record": 'Type: TXT | Name: _dmarc | Value: v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@yourdomain.com',
        "note": 'Publish a DMARC TXT record at _dmarc.yourdomain.com with enforcement policy.'
    },
    "Missing CAA Record": {
        "dns_record": 'Type: CAA | Name: @ | Value: 0 issue "letsencrypt.org"',
        "note": 'Publish CAA DNS records restricting SSL issuance to specific Certificate Authorities.'
    }
}

# --- GLOBAL COMPLIANCE FRAMEWORK MAPPING DATABASE ---
COMPLIANCE_MAP = {
    "Exposed .env Configuration File": {
        "pci_dss": "3.2 (Protect Stored Account Data)",
        "nist": "IA-5 (Authenticator Management)",
        "iso27001": "A.8.12 (Data Leakage Prevention)"
    },
    "Exposed .git Repository": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "iso27001": "A.8.28 (Secure Coding)"
    },
    "Missing Strict-Transport-Security (HSTS)": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "nist": "SC-28 (Protection of Information at Rest/Transit)",
        "iso27001": "A.8.20 (Network Security)"
    },
    "Missing Content-Security-Policy (CSP)": {
        "pci_dss": "6.4.3 (Manage Payment Page Scripts)",
        "nist": "SC-28 (Protection of Information at Rest/Transit)",
        "iso27001": "A.8.20 (Network Security)"
    },
    "Weak Content-Security-Policy (CSP)": {
        "pci_dss": "6.4.3 (Manage Payment Page Scripts)",
        "iso27001": "A.8.28 (Secure Coding)"
    },
    "Missing X-Frame-Options": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "iso27001": "A.8.20 (Network Security)"
    },
    "Missing X-Content-Type-Options": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "iso27001": "A.8.28 (Secure Coding)"
    },
    "Missing Permissions-Policy": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "iso27001": "A.8.20 (Network Security)"
    },
    "Missing Referrer-Policy": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "nist": "SC-13 (Cryptographic Protection)",
        "iso27001": "A.8.12 (Data Leakage Prevention)"
    },
    "Missing SPF Record": {
        "pci_dss": "5.4.1 (Anti-Phishing & Email Structure)",
        "nist": "SI-8 (Spam & Phishing Protection)",
        "iso27001": "A.8.19 (Information Security in Systems)"
    },
    "Weak SPF Record (+all)": {
        "pci_dss": "5.4.1 (Anti-Phishing & Email Structure)",
        "nist": "SI-8 (Spam & Phishing Protection)",
        "iso27001": "A.8.19 (Information Security in Systems)"
    },
    "Missing DMARC Policy": {
        "pci_dss": "5.4.1 (Anti-Phishing & Spoofing)",
        "nist": "SI-8 (Spam & Phishing Protection)",
        "iso27001": "A.8.19 (Information Security in Systems)"
    },
    "Weak DMARC Policy (p=none)": {
        "pci_dss": "5.4.1 (Anti-Phishing & Spoofing)",
        "nist": "SI-8 (Spam & Phishing Protection)",
        "iso27001": "A.8.19 (Information Security in Systems)"
    },
    "Missing CAA Record": {
        "pci_dss": "4.1.2 (Encrypt Management Sessions)",
        "nist": "SC-13 (Cryptographic Protection)",
        "iso27001": "A.8.24 (Use of Cryptography)"
    },
    "Wildcard CORS Policy": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "iso27001": "A.8.3 (Access Control)"
    },
    "Valid SSL/TLS Certificate": {
        "pci_dss": "4.1.2 (Encrypt Management Sessions)",
        "nist": "SC-8 (Transmission Confidentiality)",
        "iso27001": "A.8.24 (Use of Cryptography)"
    },
    "SPF Record Configured": {
        "pci_dss": "5.4.1 (Anti-Phishing & Email Structure)",
        "nist": "SI-8 (Spam & Phishing Protection)",
        "iso27001": "A.8.19 (Information Security in Systems)"
    },
    "Strong DMARC Policy Configured": {
        "pci_dss": "5.4.1 (Anti-Phishing & Spoofing)",
        "nist": "SI-8 (Spam & Phishing Protection)",
        "iso27001": "A.8.19 (Information Security in Systems)"
    },
    "CAA Records Configured": {
        "pci_dss": "4.1.2 (Encrypt Management Sessions)",
        "nist": "SC-13 (Cryptographic Protection)",
        "iso27001": "A.8.24 (Use of Cryptography)"
    },
    "security.txt Found": {
        "pci_dss": "N/A",
        "nist": "RA-5 (Vulnerability Scanning)",
        "iso27001": "A.8.8 (Management of Technical Vulnerabilities)"
    },
    "HTTPS Redirection Configured": {
        "pci_dss": "4.1.2 (Encrypt Management Sessions)",
        "nist": "SC-8 (Transmission Confidentiality)",
        "iso27001": "A.8.24 (Use of Cryptography)"
    },
    "Permissions-Policy Configured": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "iso27001": "A.8.20 (Network Security)"
    },
    "Strict-Transport-Security Configured": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "nist": "SC-28 (Protection of Information at Rest/Transit)",
        "iso27001": "A.8.20 (Network Security)"
    },
    "Content-Security-Policy Configured": {
        "pci_dss": "6.4.3 (Manage Payment Page Scripts)",
        "nist": "SC-28 (Protection of Information at Rest/Transit)",
        "iso27001": "A.8.20 (Network Security)"
    },
    "Referrer-Policy Configured": {
        "pci_dss": "6.4.1 (Public Web Application Protection)",
        "nist": "SC-13 (Cryptographic Protection)",
        "iso27001": "A.8.12 (Data Leakage Prevention)"
    }
}

IMPACT_MAP = {
    "Missing Strict-Transport-Security (HSTS)": "Allows man-in-the-middle (MitM) attacks to downgrade connections to insecure HTTP, exposing session tokens.",
    "Missing Content-Security-Policy (CSP)": "Leaves the application vulnerable to Cross-Site Scripting (XSS) and data injection attacks.",
    "Weak Content-Security-Policy (CSP)": "Allows bypass of CSP restrictions, enabling XSS scripts to execute and steal sensitive data.",
    "Missing X-Frame-Options": "Permits attackers to embed the site in an iframe, leading to Clickjacking and unauthorized actions.",
    "Missing X-Content-Type-Options": "Enables MIME-sniffing attacks where malicious files are executed as scripts.",
    "Missing Permissions-Policy": "Allows third-party scripts to access sensitive browser features like the camera, microphone, or geolocation.",
    "Missing Referrer-Policy": "Leaks sensitive URLs and tokens in the Referer header to external domains.",
    "Missing SPF Record": "Allows attackers to easily spoof emails from your domain for phishing campaigns.",
    "Missing DMARC Policy": "Prevents enforcement of SPF/DKIM, allowing spoofed emails to reach users' inboxes.",
    "Wildcard CORS Policy": "Permits any malicious domain to read sensitive data from the API on behalf of authenticated users."
}

app = FastAPI(title="Website Security Posture Checker (Advanced Modular)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health_check():
    return {"status": "online"}

def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("URL must not be empty")
    if "://" not in value:
        value = "https://" + value
    return value

class ScanRequest(BaseModel):
    url: str
    probe_subdomains: bool = False
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
    if not hostname:
        return False
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True

# Inherit from DefaultCookiePolicy to prevent AttributeError crashes
class BlockAllCookies(DefaultCookiePolicy):
    def set_ok(self, cookie, request): return False
    def return_ok(self, cookie, request): return False
    def domain_return_ok(self, cookie, request): return False
    def path_return_ok(self, cookie, request): return False

def get_http_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": Config.USER_AGENT})
    session.cookies.set_policy(BlockAllCookies())
    
    adapter = HTTPAdapter(pool_connections=25, pool_maxsize=25)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

from requests.structures import CaseInsensitiveDict

def get_all_headers(resp):
    if not resp:
        return {}
    return getattr(resp, 'all_headers', None) or getattr(resp, 'headers', {})

def get_header(resp, header_name, default=None):
    headers = get_all_headers(resp)
    if hasattr(headers, 'get'):
        return headers.get(header_name, default)
    return default

# --- SSRF-SAFE REQUEST WRAPPER ---
def safe_request(method: str, url: str, session: requests.Session = None, max_redirects: int = Config.MAX_REDIRECTS, timeout: float = Config.REQUEST_TIMEOUT, **kwargs) -> requests.Response:
    current_url = url
    own_session = False
    
    if session is None:
        session = get_http_session()
        own_session = True

    kwargs["allow_redirects"] = False
    accumulated_headers = CaseInsensitiveDict()
    resp = None

    try:
        for hop in range(max_redirects + 1):
            parsed = urlparse(current_url)
            hostname = parsed.hostname

            if not is_public_hostname(hostname):
                raise requests.exceptions.RequestException(
                    f"SSRF Protection blocked request to non-public host: {hostname}"
                )

            resp = session.request(method, current_url, timeout=timeout, **kwargs)
            
            # Merge headers from all redirect hops
            if hasattr(resp, 'headers') and resp.headers:
                accumulated_headers.update(resp.headers)

            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    break
                current_url = urljoin(current_url, location)
            else:
                break

        if resp is not None:
            resp.all_headers = accumulated_headers
        return resp
    except Exception as e:
        logger.error(f"safe_request error for {url}: {e}")
        return resp
    finally:
        if own_session and session:
            session.close()

# --- PLUGIN ARCHITECTURE ---
class ScannerModule(ABC):
    module_name = "BaseModule"
    version = "1.0.0"
    description = "Base scanner module."
    author = "Secure-AI"
    enabled = True
    timeout = 8.0

    @abstractmethod
    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        pass

    def make_finding(self, name, severity, description, evidence, confidence="High", remediation="N/A", owasp="N/A", compliance=None, category="information_exposure", cvss=None):
        if compliance is None:
            compliance = COMPLIANCE_MAP.get(name, {
                "pci_dss": "6.4.1 (Public Web Application Protection)",
                "iso27001": "A.8.20 (Network Security)"
            })
            
        impact = IMPACT_MAP.get(name, "Potential exposure of sensitive information or risk of unauthorized actions.")
        if severity == "Passed":
            impact = "N/A"
            
        snippets = REMEDIATION_SNIPPETS.get(name, {})
        
        return {
            "name": name,
            "severity": severity,
            "category": category,
            "description": description,
            "evidence": evidence,
            "confidence": confidence,
            "remediation": remediation,
            "remediation_snippets": snippets,
            "owasp": owasp,
            "compliance": compliance,
            "module": self.module_name,
            "impact": impact,
            "cvss": cvss
        }

# --- MODULES ---

class ExposedFilesModule(ScannerModule):
    module_name = "ExposedFiles"
    description = "Checks for publicly exposed sensitive files (.env, .git)."

    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        scheme = "https" if url.startswith("https") else "http"
        
        try:
            env_url = f"{scheme}://{hostname}/.env"
            resp = safe_request("GET", env_url, session=session, timeout=4.0)
            if resp.status_code == 200 and any(k in resp.text.upper() for k in ["DB_", "SECRET", "PASSWORD", "APP_KEY", "API_KEY"]):
                findings.append(self.make_finding(
                    "Exposed .env Configuration File",
                    "Critical",
                    "A .env file containing sensitive credentials or API keys is publicly accessible.",
                    env_url,
                    remediation="Restrict web server access to dotfiles or move .env outside the web root immediately.",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
        except Exception:
            pass

        try:
            git_url = f"{scheme}://{hostname}/.git/HEAD"
            resp = safe_request("GET", git_url, session=session, timeout=4.0)
            if resp.status_code == 200 and "ref: refs/" in resp.text:
                findings.append(self.make_finding(
                    "Exposed .git Repository",
                    "High",
                    "The Git source code repository is publicly exposed, allowing source code downloading.",
                    git_url,
                    remediation="Configure the web server to block access to the /.git directory.",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
        except Exception:
            pass

        return findings

class DNSCAAModule(ScannerModule):
    module_name = "DNSCAA"
    description = "Probes CAA records via Google DNS-over-HTTPS."

    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        domain = hostname[4:] if hostname.startswith("www.") else hostname

        try:
            caa_url = f"https://dns.google/resolve?name={domain}&type=CAA"
            resp = safe_request("GET", caa_url, session=session, timeout=4.0)
            
            if resp.status_code == 200:
                data = resp.json()
                if "Answer" in data and len(data["Answer"]) > 0:
                    caa_issuers = [rec.get("data", "") for rec in data["Answer"]]
                    findings.append(self.make_finding(
                        "CAA Records Configured",
                        "Passed",
                        "Certificate Authority Authorization (CAA) DNS records restrict which CAs can issue certificates.",
                        ", ".join(caa_issuers),
                        category="domain_email"
                    ))
                else:
                    findings.append(self.make_finding(
                        "Missing CAA Record",
                        "Low",
                        "No CAA DNS records found. Any valid Certificate Authority can issue SSL certificates for this domain.",
                        "CAA DNS record absent.",
                        remediation="Add CAA records in DNS specifying authorized CAs (e.g., 'issue letsencrypt.org').",
                        owasp="A02: Cryptographic Failures",
                        category="domain_email"
                    ))
        except Exception as e:
            logger.error(f"DNSCAAModule failed: {e}")
        return findings

class DNSEmailSecurityModule(ScannerModule):
    module_name = "DNSEmailSecurity"
    description = "Probes SPF, DMARC, and MX records via DNS-over-HTTPS."

    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        domain = hostname[4:] if hostname.startswith("www.") else hostname

        try:
            spf_url = f"https://dns.google/resolve?name={domain}&type=TXT"
            resp = safe_request("GET", spf_url, session=session, timeout=4.0)
            spf_found = False
            
            if resp.status_code == 200:
                data = resp.json()
                for rec in data.get("Answer", []):
                    data_str = rec.get("data", "")
                    if "v=spf1" in data_str:
                        spf_found = True
                        if "+all" in data_str:
                            findings.append(self.make_finding(
                                "Weak SPF Record (+all)",
                                "High",
                                "SPF record explicitly allows any IP address to spoof emails for this domain.",
                                data_str,
                                remediation="Change '+all' to '~all' or '-all' in your SPF TXT record.",
                                owasp="A05: Security Misconfiguration",
                                category="domain_email"
                            ))
                        else:
                            findings.append(self.make_finding(
                                "SPF Record Configured",
                                "Passed",
                                "Sender Policy Framework (SPF) record is validly configured.",
                                data_str,
                                category="domain_email"
                            ))
                        break

            if not spf_found:
                findings.append(self.make_finding(
                    "Missing SPF Record",
                    "Medium",
                    "No SPF TXT record found. The domain is exposed to email spoofing and phishing attacks.",
                    "TXT record absent.",
                    remediation="Publish a valid SPF TXT record (e.g., 'v=spf1 include:_spf.google.com ~all').",
                    owasp="A05: Security Misconfiguration",
                    category="domain_email"
                ))

            dmarc_url = f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT"
            d_resp = safe_request("GET", dmarc_url, session=session, timeout=4.0)
            dmarc_found = False
            
            if d_resp.status_code == 200:
                d_data = d_resp.json()
                for rec in d_data.get("Answer", []):
                    d_str = rec.get("data", "")
                    if "v=DMARC1" in d_str:
                        dmarc_found = True
                        if "p=none" in d_str.lower():
                            findings.append(self.make_finding(
                                "Weak DMARC Policy (p=none)",
                                "Low",
                                "DMARC policy is set to 'none', which monitors but does not block spoofed emails.",
                                d_str,
                                remediation="Upgrade DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject'.",
                                owasp="A05: Security Misconfiguration",
                                category="domain_email"
                            ))
                        else:
                            findings.append(self.make_finding(
                                "Strong DMARC Policy Configured",
                                "Passed",
                                "DMARC record is enforced with quarantine or reject policy.",
                                d_str,
                                category="domain_email"
                            ))
                        break

            if not dmarc_found:
                findings.append(self.make_finding(
                    "Missing DMARC Policy",
                    "Medium",
                    f"No DMARC record found at _dmarc.{domain}. Increases domain impersonation risk.",
                    "_dmarc TXT record absent.",
                    remediation=f"Publish a DMARC TXT record at _dmarc.{domain} with a valid enforcement policy.",
                    owasp="A05: Security Misconfiguration",
                    category="domain_email"
                ))
        except Exception as e:
            logger.error(f"DNSEmailSecurityModule failed: {e}")
        return findings

class TechFingerprintModule(ScannerModule):
    module_name = "TechFingerprint"
    description = "Identifies technologies via headers."
    
    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=Config.REQUEST_TIMEOUT)
            headers = get_all_headers(resp)
            server = headers.get("Server")
            if server:
                findings.append(self.make_finding("Server Header Exposed", "Informational", "The server software and version might be exposed.", server, category="information_exposure"))
            x_powered = headers.get("X-Powered-By")
            if x_powered:
                findings.append(self.make_finding("X-Powered-By Header Exposed", "Low", "Backend technology is explicitly declared.", x_powered, remediation="Remove X-Powered-By header.", owasp="A05: Security Misconfiguration", category="information_exposure"))
        except Exception:
            pass
        return findings

class InformationDisclosureModule(ScannerModule):
    module_name = "InformationDisclosure"
    description = "Checks for verbose server banners."
    
    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=Config.REQUEST_TIMEOUT)
            headers = get_all_headers(resp)
            server = headers.get("Server", "")
            if any(char.isdigit() for char in server) and ("/" in server or "-" in server):
                findings.append(self.make_finding("Verbose Server Banner", "Low", "Server header leaks exact version numbers.", server, remediation="Configure server to only return generic names (e.g., 'nginx').", owasp="A05: Security Misconfiguration", category="information_exposure"))
        except Exception:
            pass
        return findings

class RobotsTxtModule(ScannerModule):
    module_name = "RobotsTxt"
    description = "Fetches and analyzes robots.txt."
    
    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        try:
            target = f"https://{hostname}/robots.txt" if url.startswith("https") else f"http://{hostname}/robots.txt"
            resp = safe_request("GET", target, session=session, timeout=Config.REQUEST_TIMEOUT)
            if resp.status_code == 200 and "user-agent" in resp.text.lower():
                lines = len(resp.text.splitlines())
                findings.append(self.make_finding("robots.txt Found", "Informational", f"Found robots.txt with {lines} lines.", target, category="information_exposure"))
        except Exception:
            pass
        return findings

class SitemapModule(ScannerModule):
    module_name = "SitemapXml"
    description = "Checks for sitemap.xml."
    
    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        try:
            target = f"https://{hostname}/sitemap.xml" if url.startswith("https") else f"http://{hostname}/sitemap.xml"
            resp = safe_request("GET", target, session=session, timeout=Config.REQUEST_TIMEOUT)
            if resp.status_code == 200 and ("<urlset" in resp.text or "<sitemapindex" in resp.text):
                findings.append(self.make_finding("sitemap.xml Found", "Informational", "Found XML sitemap.", target, category="information_exposure"))
        except Exception:
            pass
        return findings

class SecurityTxtModule(ScannerModule):
    module_name = "SecurityTxt"
    description = "Checks for security.txt."
    
    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        try:
            target = f"https://{hostname}/.well-known/security.txt" if url.startswith("https") else f"http://{hostname}/.well-known/security.txt"
            resp = safe_request("GET", target, session=session, timeout=Config.REQUEST_TIMEOUT)
            if resp.status_code == 200 and "contact" in resp.text.lower():
                findings.append(self.make_finding("security.txt Found", "Passed", "Organization has published security.txt.", target, category="information_exposure"))
            else:
                findings.append(self.make_finding("security.txt Missing", "Informational", "No standard security.txt found.", target, remediation="Publish a security.txt file at /.well-known/security.txt.", category="information_exposure"))
        except Exception:
            pass
        return findings

class CORSModule(ScannerModule):
    module_name = "CORS"
    description = "Analyzes CORS headers."
    
    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=Config.REQUEST_TIMEOUT)
            headers = get_all_headers(resp)
            acao = headers.get("Access-Control-Allow-Origin")
            if acao == "*":
                findings.append(self.make_finding("Wildcard CORS Policy", "Medium", "The API allows cross-origin requests from any domain.", "Access-Control-Allow-Origin: *", remediation="Restrict CORS to specific trusted origins.", owasp="A05: Security Misconfiguration", category="http_headers"))
            elif acao:
                findings.append(self.make_finding("CORS Enabled", "Informational", "Cross-Origin Resource Sharing is enabled.", f"Access-Control-Allow-Origin: {acao}", category="http_headers"))
        except Exception:
            pass
        return findings

class AdvancedCookieModule(ScannerModule):
    module_name = "AdvancedCookie"
    description = "Evaluates HttpOnly, Secure, SameSite, and Max-Age."
    NON_SENSITIVE_COOKIES = {"SEARCH_SAMESITE", "1P_JAR", "NID", "AEC", "OGPC"}
    
    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=Config.REQUEST_TIMEOUT)
            
            raw_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp, "raw") and hasattr(resp.raw, "headers") else []
            headers = get_all_headers(resp)
            if not raw_cookies and "Set-Cookie" in headers:
                raw_cookies = [headers["Set-Cookie"]]

            seen_cookies = set()

            for cookie_str in raw_cookies:
                parts = [p.strip() for p in cookie_str.split(";") if p.strip()]
                if not parts:
                    continue
                
                cookie_name = parts[0].split("=")[0].strip()
                if cookie_name in seen_cookies:
                    continue
                seen_cookies.add(cookie_name)

                directives = [p.lower() for p in parts[1:]]
                cookie_sev = "Informational" if cookie_name.upper() in self.NON_SENSITIVE_COOKIES else "Medium"
                
                if "httponly" not in directives:
                    findings.append(self.make_finding(
                        f"Missing HttpOnly Flag on Cookie: {cookie_name}", 
                        cookie_sev, 
                        "Cookie can be accessed via client-side scripts.", 
                        f"Cookie: {cookie_name}", 
                        remediation="Add HttpOnly flag to cookies.", 
                        owasp="A05: Security Misconfiguration",
                        category="session_cookies"
                    ))
                
                if url.startswith("https") and "secure" not in directives:
                    findings.append(self.make_finding(
                        f"Missing Secure Flag on Cookie: {cookie_name}", 
                        cookie_sev, 
                        "Cookie transmitted in cleartext if sent over HTTP.", 
                        f"Cookie: {cookie_name}", 
                        remediation="Add Secure flag to cookies.", 
                        owasp="A02: Cryptographic Failures",
                        category="session_cookies"
                    ))
                
                samesite_found = any(p.startswith("samesite") for p in directives)
                if not samesite_found:
                    findings.append(self.make_finding(
                        f"Missing SameSite Attribute on Cookie: {cookie_name}", 
                        "Low", 
                        "Cookie lacks SameSite attribute, increasing CSRF risk.", 
                        f"Cookie: {cookie_name}", 
                        remediation="Add SameSite=Lax or SameSite=Strict.", 
                        owasp="A01: Broken Access Control",
                        category="session_cookies"
                    ))
        except Exception:
            pass
        return findings

class HTTPSRedirectModule(ScannerModule):
    module_name = "HTTPSRedirect"
    description = "Validates HTTP to HTTPS redirection across multi-hop chains safely."
    
    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        target = f"http://{hostname}"
        try:
            resp = safe_request("GET", target, session=session, timeout=Config.REQUEST_TIMEOUT)
            if resp.url.startswith("https://"):
                findings.append(self.make_finding("HTTPS Redirection Configured", "Passed", "HTTP traffic is correctly redirected to HTTPS.", f"Final Target: {resp.url}", category="encryption_tls"))
            else:
                findings.append(self.make_finding("Missing HTTPS Redirection", "High", "The server accepts cleartext HTTP connections without redirecting to HTTPS.", f"Final URL: {resp.url}", remediation="Configure the server to redirect all port 80 traffic to 443 (HTTPS).", owasp="A02: Cryptographic Failures", category="encryption_tls"))
        except requests.exceptions.RequestException:
            pass
        return findings

class EnhancedTLSModule(ScannerModule):
    module_name = "EnhancedTLS"
    description = "Parses SANs, signature algorithms, and expiration."
    
    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443), timeout=Config.REQUEST_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    
                    findings.append(self.make_finding("Valid SSL/TLS Certificate", "Passed", "The server presents a valid TLS certificate.", f"Version: {version}", owasp="A02: Cryptographic Failures", category="encryption_tls"))
                    
                    subject = dict(x[0] for x in cert.get("subject", []))
                    cn = subject.get("commonName", "")
                    if cn.startswith("*"):
                        findings.append(self.make_finding("Wildcard Certificate in Use", "Informational", "Wildcard certificates carry broader risk if compromised.", f"CN: {cn}", remediation="Consider using specific SANs instead of wildcards.", owasp="A02: Cryptographic Failures", category="encryption_tls"))
                    
                    not_after = cert.get("notAfter")
                    if not_after:
                        clean_date = re.sub(r'\s+', ' ', not_after)
                        expire_date = datetime.datetime.strptime(clean_date, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                        now = datetime.datetime.now(datetime.timezone.utc)
                        days_left = (expire_date - now).days
                        
                        if days_left < 30:
                            findings.append(self.make_finding("Certificate Expiring Soon", "Medium", f"Certificate expires in {days_left} days.", not_after, remediation="Renew the TLS certificate immediately.", owasp="A02: Cryptographic Failures", category="encryption_tls"))
        except Exception as e:
            findings.append(self.make_finding("SSL/TLS Connection Failure", "High", "Failed to establish a secure TLS connection.", str(e), remediation="Ensure the server supports standard TLS protocols.", owasp="A02: Cryptographic Failures", category="encryption_tls"))
        return findings

class PermissionsPolicyModule(ScannerModule):
    module_name = "PermissionsPolicy"
    description = "Checks Permissions-Policy header."

    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=Config.REQUEST_TIMEOUT)
            headers = get_all_headers(resp)
            if "Permissions-Policy" not in headers:
                findings.append(self.make_finding(
                    "Missing Permissions-Policy",
                    "Low",
                    "Missing Permissions-Policy header allows web pages to access browser feature APIs unconditionally.",
                    "Header absent.",
                    remediation="Add Permissions-Policy: camera=(), microphone=(), geolocation=().",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
            else:
                findings.append(self.make_finding(
                    "Permissions-Policy Configured",
                    "Passed",
                    "Permissions-Policy header is active.",
                    headers["Permissions-Policy"][:100],
                    category="http_headers"
                ))
        except Exception:
            pass
        return findings

class SecurityHeadersModule(ScannerModule):
    module_name = "SecurityHeaders"
    description = "Checks HSTS, CSP, XFO, etc."
    
    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=Config.REQUEST_TIMEOUT)
            headers = get_all_headers(resp)
        except requests.exceptions.Timeout as e:
            findings.append(self.make_finding("HTTP Request Failed (Timeout)", "High", "Connection timed out while fetching HTTP headers.", str(e), category="http_headers"))
            return findings
        except requests.exceptions.ConnectionError as e:
            findings.append(self.make_finding("HTTP Request Failed (Connection Error)", "High", "Connection refused or DNS failure while fetching HTTP headers.", str(e), category="http_headers"))
            return findings
        except Exception as e:
            findings.append(self.make_finding("HTTP Request Failed", "High", "Failed to fetch HTTP headers.", str(e), category="http_headers"))
            return findings

        if "Strict-Transport-Security" not in headers:
            findings.append(self.make_finding("Missing Strict-Transport-Security (HSTS)", "High", "Missing HSTS allows SSL-stripping.", "Header absent.", remediation="Add Strict-Transport-Security header.", owasp="A05: Security Misconfiguration", category="encryption_tls"))
        else:
            findings.append(self.make_finding("Strict-Transport-Security Configured", "Passed", "HSTS is present.", headers["Strict-Transport-Security"], category="encryption_tls"))

        if "Content-Security-Policy" not in headers:
            findings.append(self.make_finding("Missing Content-Security-Policy (CSP)", "High", "Missing CSP allows XSS.", "Header absent.", remediation="Implement CSP.", owasp="A05: Security Misconfiguration", category="http_headers"))
        else:
            csp = headers.get("Content-Security-Policy", "")
            if "unsafe-inline" in csp or "unsafe-eval" in csp:
                findings.append(self.make_finding("Weak Content-Security-Policy (CSP)", "Medium", "CSP contains 'unsafe-inline' or 'unsafe-eval'.", csp, remediation="Remove unsafe-inline and unsafe-eval from CSP.", owasp="A05: Security Misconfiguration", category="http_headers"))
            else:
                findings.append(self.make_finding("Content-Security-Policy Configured", "Passed", "CSP is present and strict.", csp, category="http_headers"))

        if "X-Frame-Options" not in headers:
            findings.append(self.make_finding("Missing X-Frame-Options", "Medium", "Missing XFO allows clickjacking.", "Header absent.", remediation="Add X-Frame-Options: DENY.", owasp="A05: Security Misconfiguration", category="http_headers"))

        if "X-Content-Type-Options" not in headers:
            findings.append(self.make_finding("Missing X-Content-Type-Options", "Low", "Missing this allows MIME-sniffing.", "Header absent.", remediation="Add X-Content-Type-Options: nosniff.", owasp="A05: Security Misconfiguration", category="http_headers"))
            
        if "Referrer-Policy" not in headers:
            findings.append(self.make_finding("Missing Referrer-Policy", "Low", "Missing Referrer-Policy allows leaking the referring URL.", "Header absent.", remediation="Add Referrer-Policy: strict-origin-when-cross-origin.", owasp="A05: Security Misconfiguration", category="http_headers"))
        else:
            findings.append(self.make_finding("Referrer-Policy Configured", "Passed", "Referrer-Policy is present.", headers["Referrer-Policy"], category="http_headers"))
            
        return findings

class AdvancedSecurityHeadersModule(ScannerModule):
    module_name = "AdvancedSecurityHeaders"
    description = "Checks COOP, COEP, CORP."
    
    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=Config.REQUEST_TIMEOUT)
            headers = get_all_headers(resp)
            
            if "Cross-Origin-Opener-Policy" not in headers:
                findings.append(self.make_finding("Missing COOP Header", "Informational", "COOP is missing.", "Header absent.", remediation="Add Cross-Origin-Opener-Policy.", owasp="A05: Security Misconfiguration", category="http_headers"))
            if "Cross-Origin-Embedder-Policy" not in headers:
                findings.append(self.make_finding("Missing COEP Header", "Informational", "COEP is missing.", "Header absent.", remediation="Add Cross-Origin-Embedder-Policy.", owasp="A05: Security Misconfiguration", category="http_headers"))
            if "Cross-Origin-Resource-Policy" not in headers:
                findings.append(self.make_finding("Missing CORP Header", "Informational", "CORP is missing.", "Header absent.", remediation="Add Cross-Origin-Resource-Policy.", owasp="A05: Security Misconfiguration", category="http_headers"))
        except Exception:
            pass
        return findings

class SubdomainProbingModule(ScannerModule):
    module_name = "SubdomainProbing"
    description = "Probes common subdomains for the target."
    
    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        domain = hostname[4:] if hostname.startswith("www.") else hostname
            
        for sub in Config.COMMON_SUBDOMAINS:
            sub_url = f"https://{sub}.{domain}"
            try:
                resp = safe_request("HEAD", sub_url, session=session, timeout=3.0)
                findings.append(self.make_finding(
                    f"Active Subdomain Found: {sub}.{domain}",
                    "Informational",
                    f"Probed subdomain responded with status {resp.status_code}.",
                    sub_url,
                    category="information_exposure"
                ))
            except Exception:
                pass
        return findings

# Engine Registry
REGISTERED_MODULES = [
    ExposedFilesModule(),
    DNSCAAModule(),
    DNSEmailSecurityModule(),
    PermissionsPolicyModule(),
    TechFingerprintModule(),
    InformationDisclosureModule(),
    RobotsTxtModule(),
    SitemapModule(),
    SecurityTxtModule(),
    CORSModule(),
    AdvancedCookieModule(),
    HTTPSRedirectModule(),
    EnhancedTLSModule(),
    SecurityHeadersModule(),
    AdvancedSecurityHeadersModule()
]

def get_ip_location(ip):
    try:
        # Free instant GeoIP lookup (no API key needed)
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if res.get("status") == "success":
            country = res.get("country", "Global")
            org = res.get("org") or res.get("isp") or "Cloud"
            return f"{country} ({org})"
    except Exception:
        pass
    return "Global / Cloud"

def get_metadata(domain: str, response: requests.Response, original_url: str = None):
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

    # 3. HTTP Status
    if response:
        rtt_ms = int(response.elapsed.total_seconds() * 1000) if hasattr(response, 'elapsed') else 0
        status = f"{response.status_code} {response.reason} ({rtt_ms}ms)"
    else:
        timeout_ms = int(Config.REQUEST_TIMEOUT * 1000)
        status = f"Timeout (>{timeout_ms}ms)"

    # 4. SSL Cert Info
    ssl_issuer = "Unknown"
    ssl_days_left = "N/A"
    ssl_days_left_int = None
    tls_version = "TLS"
    ssl_success = False
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ver = ssock.version()
                ssl_success = True
                if ver:
                    tls_version = ver
                # Expiry calculation
                not_after_str = cert.get('notAfter')
                if not_after_str:
                    expiry_date = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry_date - datetime.datetime.utcnow()).days
                    ssl_days_left_int = days_left
                    ssl_days_left = f"{days_left} Days Left"
                
                # Issuer calculation
                issuer_tuple = cert.get('issuer', ())
                for item in issuer_tuple:
                    for key, val in item:
                        if key == 'commonName' or key == 'organizationName':
                            ssl_issuer = val
                            break
    except Exception:
        pass

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
    is_timeout = response is None
    is_403 = response and response.status_code == 403
    rtt_val = getattr(response, 'elapsed', None)
    
    if is_timeout:
        status = "Timeout / Failed to Connect"
        waf_cdn_detection = "PROTECTED BY WAF" if ssl_success else "Timeout"
    elif is_403:
        status = f"403 Forbidden ({int(rtt_val.total_seconds() * 1000)}ms)"
        waf_cdn_detection = "PROTECTED BY WAF" if ssl_success else waf_cdn_detection

    # Performance Rating
    if rtt_val and not is_timeout:
        rtt_ms_val = int(rtt_val.total_seconds() * 1000)
        if rtt_ms_val > 1500 or is_403:
            performance_rating = "TIMEOUT" if is_403 else "High Latency"
        else:
            performance_rating = "Optimal Latency" if rtt_ms_val < 150 else "Average Latency" if rtt_ms_val < 500 else "High Latency"
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
        # TIMEOUT FALLBACK FOR HTTPS
        if original_url and original_url.startswith("https") and ssl_success:
            https_enforced = "HTTPS Enforced"
            clean_redirect = "HTTPS ACTIVE (PROBE TIMED OUT)"

    return {
        "ip_address": ip,
        "location_or_cdn": location_or_cdn,
        "server_header": server,
        "http_status": status,
        "ssl_issuer": ssl_issuer if ssl_issuer != "Unknown" else "Valid SSL" if ssl_success else "Unknown",
        "ssl_days_left": ssl_days_left,
        "ssl_days_left_int": ssl_days_left_int,
        "tls_version": tls_version,
        "waf_cdn_detection": waf_cdn_detection,
        "performance_rating": performance_rating,
        "ipv6_supported": ipv6_supported,
        "http_protocol": http_protocol,
        "https_enforced": https_enforced,
        "clean_redirect": clean_redirect
    }


def scan_url(url: str, probe_subdomains: bool = False) -> dict:
    hostname = urlparse(url).hostname
    if not hostname:
        return {"url": url, "error": "Could not parse a hostname from that URL."}
    if not is_public_hostname(hostname):
        return {"url": url, "error": "That host resolves to a private/internal address and can't be scanned."}
    
    metadata = {}
    all_findings = []
    
    active_modules = [mod for mod in REGISTERED_MODULES if mod.enabled]
    if probe_subdomains:
        active_modules.append(SubdomainProbingModule())
        
    with get_http_session() as session:
        try:
            initial_resp = safe_request("GET", url, session=session, timeout=Config.REQUEST_TIMEOUT)
            metadata = get_metadata(hostname, initial_resp, url)
        except Exception as e:
            metadata = get_metadata(hostname, None, url)

        with ThreadPoolExecutor(max_workers=Config.THREAD_POOL_SIZE) as pool:
            futures = {pool.submit(mod.run, url, hostname, session): mod for mod in active_modules}
            for future in as_completed(futures):
                mod = futures[future]
                try:
                    mod_findings = future.result(timeout=mod.timeout)
                    all_findings.extend(mod_findings)
                except Exception as e:
                    logger.error(f"Module {mod.module_name} failed: {e}")
                    all_findings.append({
                        "name": f"Module Crash: {mod.module_name}",
                        "severity": "Informational",
                        "category": "information_exposure",
                        "description": "The scanner module crashed or timed out.",
                        "evidence": str(e),
                        "confidence": "High",
                        "remediation": "N/A",
                        "remediation_snippets": {},
                        "owasp": "N/A",
                        "compliance": {"pci_dss": "N/A", "nist": "N/A", "iso27001": "N/A"}
                    })

    # --- SCORING & CATEGORY ENGINE ---
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Passed": 0}
    penalties = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    max_penalties = {"Critical": 100, "High": 30, "Medium": 20, "Low": 10, "Informational": 0}
    
    category_penalties = {
        "encryption_tls": 0,
        "http_headers": 0,
        "domain_email": 0,
        "session_cookies": 0,
        "information_exposure": 0
    }
    
    owasp_categories = set()
    failed_pci, passed_pci = set(), set()
    failed_nist, passed_nist = set(), set()
    failed_iso, passed_iso = set(), set()
    
    high_critical_failed_pci = set()
    high_critical_failed_nist = set()
    high_critical_failed_iso = set()
    
    cat_weights = {"Critical": 25, "High": 15, "Medium": 10, "Low": 5, "Informational": 0, "Passed": 0}

    for f in all_findings:
        sev = f.get("severity", "Informational")
        cat = f.get("category", "information_exposure")
        
        if sev in severity_counts:
            severity_counts[sev] += 1
            
        weight = abs(Config.SEVERITY_WEIGHTS.get(sev, 0))
        if sev in penalties:
            penalties[sev] = min(penalties[sev] + weight, max_penalties[sev])
        
        # Category sub-scores deduction
        if cat in category_penalties:
            category_penalties[cat] += cat_weights.get(sev, 0)
        
        owasp = f.get("owasp")
        if owasp and owasp != "N/A":
            owasp_categories.add(owasp)
            
        comp = f.get("compliance", {})
        p_c = comp.get("pci_dss")
        n_c = comp.get("nist")
        i_c = comp.get("iso27001")
        
        if sev in ["Critical", "High", "Medium", "Low"]:
            if p_c and p_c != "N/A": 
                failed_pci.add(p_c)
                if sev in ["Critical", "High"]: high_critical_failed_pci.add(p_c)
            if n_c and n_c != "N/A": 
                failed_nist.add(n_c)
                if sev in ["Critical", "High"]: high_critical_failed_nist.add(n_c)
            if i_c and i_c != "N/A": 
                failed_iso.add(i_c)
                if sev in ["Critical", "High"]: high_critical_failed_iso.add(i_c)
        elif sev == "Passed":
            if p_c and p_c != "N/A": passed_pci.add(p_c)
            if n_c and n_c != "N/A": passed_nist.add(n_c)
            if i_c and i_c != "N/A": passed_iso.add(i_c)

    def process_compliance(failed_set, passed_set):
        # 1. Deduplicate failed
        failed_dedup = {}
        for c in failed_set:
            code = c.split(" ")[0]
            if code not in failed_dedup:
                failed_dedup[code] = c
                
        # 2. Deduplicate passed, excluding ANY code that is in failed_dedup
        passed_dedup = {}
        for c in passed_set:
            code = c.split(" ")[0]
            if code not in failed_dedup and code not in passed_dedup:
                passed_dedup[code] = c
                
        return sorted(list(failed_dedup.values())), sorted(list(passed_dedup.values()))

    failed_pci_list, passed_pci_list = process_compliance(failed_pci, passed_pci)
    failed_nist_list, passed_nist_list = process_compliance(failed_nist, passed_nist)
    failed_iso_list, passed_iso_list = process_compliance(failed_iso, passed_iso)

    def get_status(failed_high_crit, passed_list):
        if len(failed_high_crit) == 0 and len(passed_list) >= 2:
            return "Compliant"
        return "Action Required"

    score = max(0, 100 - sum(penalties.values()))
    
    # Calculate Radar Sub-scores out of 100
    category_scores = {
        cat: max(0, 100 - pen) for cat, pen in category_penalties.items()
    }

    grade = "F"
    for letter, threshold in sorted(Config.SCORE_THRESHOLDS.items(), key=lambda x: x[1], reverse=True):
        if score >= threshold:
            grade = letter
            break

    return {
        "url": url,
        "score": score,
        "grade": grade,
        "severity_counts": severity_counts,
        "category_scores": category_scores,
        "owasp_coverage": list(owasp_categories),
        "technical_compliance": {
            "pci_dss_4_0": {
                "status": get_status(high_critical_failed_pci, passed_pci_list),
                "failed_controls": failed_pci_list,
                "passed_controls": passed_pci_list
            },
            "nist_sp_800_53": {
                "status": get_status(high_critical_failed_nist, passed_nist_list),
                "failed_controls": failed_nist_list,
                "passed_controls": passed_nist_list
            },
            "iso_27001": {
                "status": get_status(high_critical_failed_iso, passed_iso_list),
                "failed_controls": failed_iso_list,
                "passed_controls": passed_iso_list
            }
        },
        "findings": all_findings,
        "metadata": metadata,
        "potential_issues_count": sum(c for k, c in severity_counts.items() if k in ["Critical", "High", "Medium", "Low"]),
        "executive_summary": f"Scan completed. Detected {severity_counts['High'] + severity_counts['Critical']} high-priority issues resulting in a score of {score}/100.",
        "disclaimer": "Passive scan only. Modular engine execution."
    }

@app.post("/api/scan")
@app.post("/scan")
async def scan_single(req: ScanRequest):
    try:
        return await asyncio.wait_for(asyncio.to_thread(scan_url, req.url, req.probe_subdomains), timeout=9.0)
    except asyncio.TimeoutError:
        return JSONResponse(status_code=408, content={"error": "Scan timed out. Target may be unresponsive or WAF blocked."})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/api/scan/batch")
@app.post("/scan/batch")
async def scan_batch(req: BatchScanRequest):
    workers = min(10, len(req.urls)) or 1
    
    def process_batch():
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(scan_url, req.urls))
            
    try:
        results = await asyncio.wait_for(asyncio.to_thread(process_batch), timeout=9.0)
        return {"results": results}
    except asyncio.TimeoutError:
        return JSONResponse(status_code=408, content={"error": "Batch scan timed out."})

# --- PDF EXPORT ENGINE ---
@app.post("/api/export/pdf")
def export_pdf(req: ScanRequest):
    """
    Generates a print-ready executive PDF / HTML report for white-label client presentation.
    """
    data = scan_url(req.url, req.probe_subdomains)
    hostname = urlparse(data["url"]).hostname or "report"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Security Posture Report - {hostname}</title>
        <style>
            body {{ font-family: 'Helvetica Neue', Arial, sans-serif; background: #0b0f19; color: #f3f4f6; margin: 0; padding: 40px; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #1f293d; padding-bottom: 20px; }}
            .logo {{ font-size: 24px; font-weight: bold; color: #3b82f6; letter-spacing: 1px; }}
            .score-badge {{ font-size: 36px; font-weight: bold; color: #10b981; background: #064e3b; padding: 10px 25px; border-radius: 12px; border: 1px solid #059669; }}
            .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 24px; margin-top: 24px; }}
            h2 {{ color: #93c5fd; border-bottom: 1px solid #1e3a8a; padding-bottom: 8px; font-size: 18px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #1f2937; font-size: 14px; }}
            th {{ background: #1e293b; color: #94a3b8; }}
            .sev-High {{ color: #ef4444; font-weight: bold; }}
            .sev-Medium {{ color: #f59e0b; font-weight: bold; }}
            .sev-Low {{ color: #eab308; }}
            .sev-Passed {{ color: #10b981; font-weight: bold; }}
            .snippet {{ background: #030712; padding: 8px; font-family: monospace; font-size: 12px; border-radius: 4px; color: #a7f3d0; border: 1px solid #1f2937; white-space: pre-wrap; }}
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <div class="logo">URLScanOnline Security Report</div>
                <div style="color: #94a3b8; margin-top: 5px;">Target: {data['url']} | Date: {datetime.datetime.now().strftime("%B %d, %Y")}</div>
            </div>
            <div class="score-badge">{data['score']}/100 ({data['grade']})</div>
        </div>

        <div class="card">
            <h2>Executive Summary</h2>
            <p>{data['executive_summary']}</p>
            <p><strong>Total Potential Issues Found:</strong> {data['potential_issues_count']}</p>
        </div>

        <div class="card">
            <h2>Category Posture Scores</h2>
            <table>
                <tr><th>Security Domain</th><th>Score</th></tr>
                <tr><td>Encryption & TLS</td><td>{data['category_scores']['encryption_tls']}/100</td></tr>
                <tr><td>HTTP Security Headers</td><td>{data['category_scores']['http_headers']}/100</td></tr>
                <tr><td>Domain & Email Protection (SPF/DMARC)</td><td>{data['category_scores']['domain_email']}/100</td></tr>
                <tr><td>Session & Cookie Hardening</td><td>{data['category_scores']['session_cookies']}/100</td></tr>
                <tr><td>Information Exposure Defenses</td><td>{data['category_scores']['information_exposure']}/100</td></tr>
            </table>
        </div>

        <div class="card">
            <h2>Vulnerability & Finding Matrix</h2>
            <table>
                <tr><th>Severity</th><th>Check Name</th><th>OWASP Category</th><th>Evidence</th></tr>
                {''.join([f"<tr><td class='sev-{f['severity']}'>{f['severity']}</td><td>{f['name']}</td><td>{f['owasp']}</td><td><div class='snippet'>{f['evidence']}</div></td></tr>" for f in data['findings']])}
            </table>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)
