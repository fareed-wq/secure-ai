import asyncio
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
from http.cookiejar import DefaultCookiePolicy
import html
from html.parser import HTMLParser
import ipaddress
import logging
import re
import socket
import ssl
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, field_validator
import requests
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict
import urllib3
import whois

# Disable insecure request warnings for passive SSL probing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Pre-compiled regular expressions for performance
CANONICAL_URL_REGEX = re.compile(r'(https?://[^\s\]\)\>\"\']+)')
WHITESPACE_REGEX = re.compile(r'\s+')


def canonicalize_url(raw_input: str) -> str:
    """Sanitizes raw user input into a clean, canonical HTTP/HTTPS URL."""
    clean_url = raw_input.strip()
    if not clean_url.startswith("http://") and not clean_url.startswith("https://"):
        clean_url = "https://" + clean_url
    match = CANONICAL_URL_REGEX.match(clean_url)
    if match:
        clean_url = match.group(1)
    return clean_url


# --- CENTRAL CONFIGURATION ---
class Config:
    REQUEST_TIMEOUT = 6.0
    MAX_REDIRECTS = 5
    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
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
def health_check() -> dict:
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
    urls: List[str]

    @field_validator("urls")
    @classmethod
    def _normalize_all(cls, v: List[str]) -> List[str]:
        return [normalize_url(u) for u in v]


def is_public_hostname(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False
        except ValueError:
            return False
    return True


# Custom policy to block all cookies during scanning
class BlockAllCookies(DefaultCookiePolicy):
    def set_ok(self, cookie, request):
        return False

    def return_ok(self, cookie, request):
        return False

    def domain_return_ok(self, cookie, request):
        return False

    def path_return_ok(self, cookie, request):
        return False


def get_http_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": Config.USER_AGENT})
    session.cookies.set_policy(BlockAllCookies())

    adapter = HTTPAdapter(pool_connections=25, pool_maxsize=25)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def get_all_headers(resp: Optional[requests.Response]) -> Dict[str, Any]:
    if not resp:
        return {}
    return getattr(resp, 'all_headers', None) or getattr(resp, 'headers', {})


def get_header(resp: Optional[requests.Response], header_name: str, default: Any = None) -> Any:
    headers = get_all_headers(resp)
    if hasattr(headers, 'get'):
        return headers.get(header_name, default)
    return default


# --- SSRF-SAFE REQUEST WRAPPER ---
def safe_request(
    method: str,
    url: str,
    session: Optional[requests.Session] = None,
    max_redirects: int = Config.MAX_REDIRECTS,
    timeout: float = Config.REQUEST_TIMEOUT,
    **kwargs
) -> Optional[requests.Response]:
    current_url = url
    own_session = False

    if session is None:
        session = get_http_session()
        own_session = True

    kwargs["allow_redirects"] = False
    accumulated_headers = CaseInsensitiveDict()
    resp = None

    try:
        for _ in range(max_redirects + 1):
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
    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        pass

    def make_finding(
        self,
        name: str,
        severity: str,
        description: str,
        evidence: str,
        confidence: str = "High",
        remediation: str = "N/A",
        owasp: str = "N/A",
        compliance: Optional[dict] = None,
        category: str = "information_exposure",
        cvss: Optional[float] = None
    ) -> dict:
        if compliance is None:
            compliance = COMPLIANCE_MAP.get(name, {
                "pci_dss": "6.4.1 (Public Web Application Protection)",
                "iso27001": "A.8.20 (Network Security)"
            })

        impact = IMPACT_MAP.get(
            name,
            "Potential exposure of sensitive information or risk of unauthorized actions."
        )
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

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        scheme = "https" if url.startswith("https") else "http"

        try:
            env_url = f"{scheme}://{hostname}/.env"
            resp = safe_request("GET", env_url, session=session, timeout=4.0)
            if resp and resp.status_code == 200 and any(
                k in resp.text.upper() for k in ["DB_", "SECRET", "PASSWORD", "APP_KEY", "API_KEY"]
            ):
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
            if resp and resp.status_code == 200 and "ref: refs/" in resp.text:
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

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        domain = hostname[4:] if hostname.startswith("www.") else hostname

        try:
            caa_url = f"https://dns.google/resolve?name={domain}&type=CAA"
            resp = safe_request("GET", caa_url, session=session, timeout=4.0)

            if resp and resp.status_code == 200:
                data = resp.json()
                if "Answer" in data and len(data["Answer"]) > 0:
                    caa_issuers = [rec.get("data", "") for rec in data["Answer"]]
                    findings.append(self.make_finding(
                        "CAA Records Configured",
                        "Passed",
                        "Certificate Authority Authorization (CAA) DNS records restrict which CAs can issue certificates.",
                        ", ".join(caa_issuers),
                        owasp="A02: Cryptographic Failures",
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

        # DNSSEC Check
        try:
            dnssec_url = f"https://dns.google/resolve?name={domain}&type=DNSKEY"
            resp = safe_request("GET", dnssec_url, session=session, timeout=4.0)
            if resp and resp.status_code == 200:
                data = resp.json()
                if "Answer" in data and len(data["Answer"]) > 0:
                    findings.append(self.make_finding(
                        "DNSSEC Configured",
                        "Passed",
                        "Domain Name System Security Extensions (DNSSEC) is enabled.",
                        "DNSKEY record found",
                        owasp="A02: Cryptographic Failures",
                        category="domain_email"
                    ))
        except Exception:
            pass

        return findings


class DNSEmailSecurityModule(ScannerModule):
    module_name = "DNSEmailSecurity"
    description = "Probes SPF, DMARC, and MX records via DNS-over-HTTPS."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        domain = hostname[4:] if hostname.startswith("www.") else hostname

        try:
            spf_url = f"https://dns.google/resolve?name={domain}&type=TXT"
            resp = safe_request("GET", spf_url, session=session, timeout=4.0)
            spf_found = False

            if resp and resp.status_code == 200:
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
                                owasp="A05: Security Misconfiguration",
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

            if d_resp and d_resp.status_code == 200:
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
                                owasp="A05: Security Misconfiguration",
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

        # MTA-STS Check
        try:
            mta_url = f"https://dns.google/resolve?name=_mta-sts.{domain}&type=TXT"
            resp = safe_request("GET", mta_url, session=session, timeout=4.0)
            mta_found = False
            if resp and resp.status_code == 200:
                for rec in resp.json().get("Answer", []):
                    if "v=STSv1" in rec.get("data", ""):
                        mta_found = True
                        findings.append(self.make_finding(
                            "MTA-STS Mail Transport Security Configured",
                            "Passed",
                            "MTA-STS policy is configured to enforce TLS for email transport.",
                            rec.get("data", ""),
                            owasp="A05: Security Misconfiguration",
                            category="domain_email"
                        ))
                        break
            if not mta_found:
                findings.append(self.make_finding(
                    "Missing MTA-STS Record",
                    "Informational",
                    "No MTA-STS DNS record found.",
                    "",
                    owasp="A05: Security Misconfiguration",
                    category="domain_email"
                ))
        except Exception:
            pass

        # TLS-RPT Check
        try:
            tlsrpt_url = f"https://dns.google/resolve?name=_smtp._tls.{domain}&type=TXT"
            resp = safe_request("GET", tlsrpt_url, session=session, timeout=4.0)
            if resp and resp.status_code == 200:
                for rec in resp.json().get("Answer", []):
                    if "v=TLSRPTv1" in rec.get("data", ""):
                        findings.append(self.make_finding(
                            "TLS-RPT Email Reporting Configured",
                            "Passed",
                            "TLS Reporting (TLS-RPT) is configured.",
                            rec.get("data", ""),
                            owasp="A05: Security Misconfiguration",
                            category="domain_email"
                        ))
                        break
        except Exception:
            pass

        return findings


class TechFingerprintModule(ScannerModule):
    module_name = "TechFingerprint"
    description = "Identifies technologies via headers."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=Config.REQUEST_TIMEOUT)
            headers = get_all_headers(resp)
            server = headers.get("Server")
            if server:
                findings.append(self.make_finding(
                    "Server Header Exposed",
                    "Informational",
                    "The server software and version might be exposed.",
                    server,
                    remediation="Configure server to return generic names.",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
            x_powered = headers.get("X-Powered-By")
            if x_powered:
                findings.append(self.make_finding(
                    "X-Powered-By Header Exposed",
                    "Low",
                    "Backend technology is explicitly declared.",
                    x_powered,
                    remediation="Remove X-Powered-By header.",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
        except Exception:
            pass
        return findings


class InformationDisclosureModule(ScannerModule):
    module_name = "InformationDisclosure"
    description = "Checks for verbose server banners."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=Config.REQUEST_TIMEOUT)
            headers = get_all_headers(resp)
            server = headers.get("Server", "")
            if any(char.isdigit() for char in server) and ("/" in server or "-" in server):
                findings.append(self.make_finding(
                    "Verbose Server Banner",
                    "Low",
                    "Server header leaks exact version numbers.",
                    server,
                    remediation="Configure server to only return generic names (e.g., 'nginx').",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
        except Exception:
            pass
        return findings


class RobotsTxtModule(ScannerModule):
    module_name = "RobotsTxt"
    description = "Fetches and analyzes robots.txt."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            target = f"https://{hostname}/robots.txt" if url.startswith("https") else f"http://{hostname}/robots.txt"
            resp = safe_request("GET", target, session=session, timeout=Config.REQUEST_TIMEOUT)
            if resp and resp.status_code == 200 and "user-agent" in resp.text.lower():
                lines = len(resp.text.splitlines())
                findings.append(self.make_finding(
                    "robots.txt Found",
                    "Informational",
                    f"Found robots.txt with {lines} lines.",
                    target,
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
            else:
                findings.append(self.make_finding(
                    "robots.txt Missing",
                    "Informational",
                    "No robots.txt found.",
                    target,
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
        except Exception:
            pass
        return findings


class SitemapModule(ScannerModule):
    module_name = "SitemapXml"
    description = "Checks for sitemap.xml."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            target = f"https://{hostname}/sitemap.xml" if url.startswith("https") else f"http://{hostname}/sitemap.xml"
            resp = safe_request("GET", target, session=session, timeout=Config.REQUEST_TIMEOUT)
            if resp and resp.status_code == 200 and ("<urlset" in resp.text or "<sitemapindex" in resp.text):
                findings.append(self.make_finding(
                    "sitemap.xml Found",
                    "Informational",
                    "Found XML sitemap.",
                    target,
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
            else:
                findings.append(self.make_finding(
                    "sitemap.xml Missing",
                    "Informational",
                    "No sitemap.xml found.",
                    target,
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
        except Exception:
            pass
        return findings


class SecurityTxtModule(ScannerModule):
    module_name = "SecurityTxt"
    description = "Checks for security.txt."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            target = (
                f"https://{hostname}/.well-known/security.txt"
                if url.startswith("https")
                else f"http://{hostname}/.well-known/security.txt"
            )
            resp = safe_request("GET", target, session=session, timeout=Config.REQUEST_TIMEOUT)
            if resp and resp.status_code == 200 and "contact" in resp.text.lower():
                findings.append(self.make_finding(
                    "security.txt Found",
                    "Passed",
                    "Organization has published security.txt.",
                    target,
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
            else:
                findings.append(self.make_finding(
                    "security.txt Missing",
                    "Informational",
                    "No standard security.txt found.",
                    target,
                    remediation="Publish a security.txt file at /.well-known/security.txt.",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
        except Exception:
            pass
        return findings


class CORSModule(ScannerModule):
    module_name = "CORS"
    description = "Analyzes CORS headers."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=Config.REQUEST_TIMEOUT)
            headers = get_all_headers(resp)
            acao = headers.get("Access-Control-Allow-Origin")
            if acao == "*":
                findings.append(self.make_finding(
                    "Wildcard CORS Policy",
                    "Medium",
                    "The API allows cross-origin requests from any domain.",
                    "Access-Control-Allow-Origin: *",
                    remediation="Restrict CORS to specific trusted origins.",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
            elif acao:
                findings.append(self.make_finding(
                    "CORS Enabled",
                    "Informational",
                    "Cross-Origin Resource Sharing is enabled.",
                    f"Access-Control-Allow-Origin: {acao}",
                    category="http_headers"
                ))
        except Exception:
            pass
        return findings


class AdvancedCookieModule(ScannerModule):
    module_name = "AdvancedCookie"
    description = "Evaluates HttpOnly, Secure, SameSite, and Max-Age."
    NON_SENSITIVE_COOKIES = {"SEARCH_SAMESITE", "1P_JAR", "NID", "AEC", "OGPC"}

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=Config.REQUEST_TIMEOUT)
            if not resp:
                return findings

            raw_cookies = (
                resp.raw.headers.getlist("Set-Cookie")
                if hasattr(resp, "raw") and hasattr(resp.raw, "headers")
                else []
            )
            headers = get_all_headers(resp)
            if not raw_cookies and "Set-Cookie" in headers:
                raw_cookies = [headers["Set-Cookie"]]

            seen_cookies = set()
            missing_httponly = []
            missing_secure = []
            missing_samesite = []
            invalid_prefixes = []

            for cookie_str in raw_cookies:
                parts = [p.strip() for p in cookie_str.split(";") if p.strip()]
                if not parts:
                    continue

                cookie_name = parts[0].split("=")[0].strip()
                if cookie_name in seen_cookies:
                    continue
                seen_cookies.add(cookie_name)

                directives = [p.lower() for p in parts[1:]]

                if "httponly" not in directives:
                    missing_httponly.append(cookie_name)

                if url.startswith("https") and "secure" not in directives:
                    missing_secure.append(cookie_name)

                samesite_found = any(p.startswith("samesite") for p in directives)
                if not samesite_found:
                    missing_samesite.append(cookie_name)

                if cookie_name.startswith("__Host-"):
                    path_is_root = any(p == "path=/" for p in directives)
                    has_domain = any(p.startswith("domain=") for p in directives)
                    if "secure" not in directives or not path_is_root or has_domain:
                        invalid_prefixes.append(cookie_name)
                elif cookie_name.startswith("__Secure-"):
                    if "secure" not in directives:
                        invalid_prefixes.append(cookie_name)

            all_unsecured = set(missing_httponly + missing_secure + missing_samesite + invalid_prefixes)
            if all_unsecured:
                problems = []
                if missing_httponly:
                    problems.append(
                        f"The following cookies are missing the HttpOnly flag: {', '.join(missing_httponly)}."
                    )
                if missing_secure:
                    problems.append(
                        f"The following cookies are missing the Secure flag: {', '.join(missing_secure)}."
                    )
                if missing_samesite:
                    problems.append(
                        f"The following cookies are missing the SameSite attribute: {', '.join(missing_samesite)}."
                    )
                if invalid_prefixes:
                    problems.append(
                        f"The following cookies have invalid __Host- or __Secure- prefixes: {', '.join(invalid_prefixes)}."
                    )

                overall_sev = "Medium"
                if all(c.upper() in self.NON_SENSITIVE_COOKIES for c in all_unsecured):
                    overall_sev = "Informational"

                count_len = len(all_unsecured)
                title = f"Unsecured Cookie{'s' if count_len > 1 else ''} Detected ({count_len} Cookie{'s' if count_len > 1 else ''})"

                findings.append(self.make_finding(
                    title,
                    overall_sev,
                    " ".join(problems),
                    f"Cookies affected: {', '.join(all_unsecured)}",
                    remediation="Add HttpOnly, Secure, and SameSite=Lax/Strict flags to all session cookies.",
                    owasp="A05: Security Misconfiguration",
                    category="session_cookies"
                ))

        except Exception:
            pass
        return findings


class HTTPSRedirectModule(ScannerModule):
    module_name = "HTTPSRedirect"
    description = "Validates HTTP to HTTPS redirection across multi-hop chains safely."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        target = f"http://{hostname}"
        try:
            resp = safe_request("GET", target, session=session, timeout=Config.REQUEST_TIMEOUT)
            if resp and resp.url.startswith("https://"):
                findings.append(self.make_finding(
                    "HTTPS Redirection Configured",
                    "Passed",
                    "HTTP traffic is correctly redirected to HTTPS.",
                    f"Final Target: {resp.url}",
                    owasp="A02: Cryptographic Failures",
                    category="encryption_tls"
                ))
            elif resp:
                findings.append(self.make_finding(
                    "Missing HTTPS Redirection",
                    "High",
                    "The server accepts cleartext HTTP connections without redirecting to HTTPS.",
                    f"Final URL: {resp.url}",
                    remediation="Configure the server to redirect all port 80 traffic to 443 (HTTPS).",
                    owasp="A02: Cryptographic Failures",
                    category="encryption_tls"
                ))
        except requests.exceptions.RequestException:
            pass
        return findings


class EnhancedTLSModule(ScannerModule):
    module_name = "EnhancedTLS"
    description = "Parses SANs, signature algorithms, and expiration."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443), timeout=Config.REQUEST_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()

                    findings.append(self.make_finding(
                        "Valid SSL/TLS Certificate",
                        "Passed",
                        "The server presents a valid TLS certificate.",
                        f"Version: {version}",
                        owasp="A02: Cryptographic Failures",
                        category="encryption_tls"
                    ))

                    subject = dict(x[0] for x in cert.get("subject", []))
                    cn = subject.get("commonName", "")
                    if cn.startswith("*"):
                        findings.append(self.make_finding(
                            "Wildcard Certificate in Use",
                            "Informational",
                            "Wildcard certificates carry broader risk if compromised.",
                            f"CN: {cn}",
                            remediation="Consider using specific SANs instead of wildcards.",
                            owasp="A02: Cryptographic Failures",
                            category="encryption_tls"
                        ))

                    not_after = cert.get("notAfter")
                    if not_after:
                        clean_date = WHITESPACE_REGEX.sub(' ', not_after)
                        expire_date = datetime.datetime.strptime(
                            clean_date, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=datetime.timezone.utc)
                        now = datetime.datetime.now(datetime.timezone.utc)
                        days_left = (expire_date - now).days

                        if days_left < 30:
                            findings.append(self.make_finding(
                                "Certificate Expiring Soon",
                                "Medium",
                                f"Certificate expires in {days_left} days.",
                                not_after,
                                remediation="Renew the TLS certificate immediately.",
                                owasp="A02: Cryptographic Failures",
                                category="encryption_tls"
                            ))
        except Exception as e:
            findings.append(self.make_finding(
                "SSL/TLS Connection Failure",
                "High",
                "Failed to establish a secure TLS connection.",
                str(e),
                remediation="Ensure the server supports standard TLS protocols.",
                owasp="A02: Cryptographic Failures",
                category="encryption_tls"
            ))

        # Legacy TLS Probe
        legacy_supported = False
        try:
            legacy_context = ssl.create_default_context()
            legacy_context.options &= ~ssl.OP_NO_TLSv1
            legacy_context.options &= ~ssl.OP_NO_TLSv1_1
            legacy_context.maximum_version = ssl.TLSVersion.TLSv1_1

            with socket.create_connection((hostname, 443), timeout=3.0) as sock:
                with legacy_context.wrap_socket(sock, server_hostname=hostname):
                    legacy_supported = True
        except Exception:
            pass

        if legacy_supported:
            findings.append(self.make_finding(
                "Deprecated TLS 1.0/1.1 Supported",
                "Medium",
                "The server allows connections using deprecated TLS 1.0 or 1.1 protocols.",
                "",
                remediation="Disable TLS 1.0 and TLS 1.1 on the server.",
                owasp="A05: Security Misconfiguration",
                category="encryption_tls"
            ))
        else:
            findings.append(self.make_finding(
                "Legacy TLS Protocols Disabled",
                "Passed",
                "Server correctly rejects TLS 1.0/1.1 connections.",
                "TLS 1.2+ Only",
                owasp="A02: Cryptographic Failures",
                category="encryption_tls"
            ))

        return findings


class PermissionsPolicyModule(ScannerModule):
    module_name = "PermissionsPolicy"
    description = "Checks Permissions-Policy header."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=Config.REQUEST_TIMEOUT)
            headers = get_all_headers(resp)
            if "Permissions-Policy" not in headers:
                findings.append(self.make_finding(
                    "Missing Permissions-Policy",
                    "Low",
                    "The Permissions-Policy header is missing, allowing web pages to access browser feature APIs unconditionally.",
                    "",
                    remediation="Apply recommended server configuration headers and verify compliance against baseline security standards.",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
            else:
                findings.append(self.make_finding(
                    "Permissions-Policy Configured",
                    "Passed",
                    "Permissions-Policy header is active.",
                    headers["Permissions-Policy"][:100],
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
        except Exception:
            pass
        return findings


class SecurityHeadersModule(ScannerModule):
    module_name = "SecurityHeaders"
    description = "Checks HSTS, CSP, XFO, etc."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=Config.REQUEST_TIMEOUT)
            headers = get_all_headers(resp)
        except requests.exceptions.Timeout as e:
            findings.append(self.make_finding(
                "HTTP Request Failed (Timeout)",
                "High",
                "Connection timed out while fetching HTTP headers.",
                str(e),
                category="http_headers"
            ))
            return findings
        except requests.exceptions.ConnectionError as e:
            findings.append(self.make_finding(
                "HTTP Request Failed (Connection Error)",
                "High",
                "Connection refused or DNS failure while fetching HTTP headers.",
                str(e),
                category="http_headers"
            ))
            return findings
        except Exception as e:
            findings.append(self.make_finding(
                "HTTP Request Failed",
                "High",
                "Failed to fetch HTTP headers.",
                str(e),
                category="http_headers"
            ))
            return findings

        if "Strict-Transport-Security" not in headers:
            findings.append(self.make_finding(
                "Missing Strict-Transport-Security (HSTS)",
                "High",
                "The HTTP Strict-Transport-Security response header is missing, leaving the application vulnerable to SSL-stripping attacks.",
                "",
                remediation="Enable HTTP Strict Transport Security (HSTS) with a long max-age directive and includeSubDomains flag.",
                owasp="A05: Security Misconfiguration",
                category="encryption_tls"
            ))
        else:
            findings.append(self.make_finding(
                "Strict-Transport-Security Configured",
                "Passed",
                "HSTS is present.",
                headers["Strict-Transport-Security"],
                owasp="A02: Cryptographic Failures",
                category="encryption_tls"
            ))

        if "Content-Security-Policy" not in headers:
            findings.append(self.make_finding(
                "Missing Content-Security-Policy (CSP)",
                "High",
                "The HTTP Content-Security-Policy (CSP) response header is missing, leaving the application vulnerable to Cross-Site Scripting (XSS) and data injection attacks.",
                "",
                remediation="Configure your web server to issue strict Content-Security-Policy HTTP headers to restrict script execution sources to trusted domains.",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))
        else:
            csp = headers.get("Content-Security-Policy", "")
            is_strict = True
            weak_reasons = []

            if "unsafe-eval" in csp:
                is_strict = False
                weak_reasons.append("'unsafe-eval'")

            if "unsafe-inline" in csp:
                if "object-src 'none'" in csp and "base-uri 'self'" in csp:
                    pass  # Accepted as strict due to framework limitations
                else:
                    is_strict = False
                    weak_reasons.append("'unsafe-inline' without 'object-src \\'none\\'' and 'base-uri \\'self\\''")

            missing_granular = "object-src" not in csp or "base-uri" not in csp

            if not is_strict or missing_granular:
                problems = []
                if not is_strict:
                    problems.append(f"unsafe directives: {', '.join(weak_reasons)}")
                if missing_granular:
                    problems.append("missing granular directives like object-src or base-uri")

                problem_desc = f"CSP contains flaws: {'; '.join(problems)}."
                sev = "Medium" if not is_strict else "Low"

                findings.append(self.make_finding(
                    "Weak Content-Security-Policy (CSP)",
                    sev,
                    problem_desc,
                    csp,
                    remediation="Remove unsafe-inline/unsafe-eval or strictly define object-src 'none' and base-uri 'self'.",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
            else:
                findings.append(self.make_finding(
                    "Content-Security-Policy Configured",
                    "Passed",
                    "CSP is present and strict.",
                    csp,
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))

        if "X-Permitted-Cross-Domain-Policies" not in headers:
            findings.append(self.make_finding(
                "Missing X-Permitted-Cross-Domain-Policies",
                "Informational",
                "The X-Permitted-Cross-Domain-Policies header is missing.",
                "",
                remediation="Apply recommended server configuration headers and verify compliance against baseline security standards.",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))

        if "X-DNS-Prefetch-Control" not in headers:
            findings.append(self.make_finding(
                "Missing X-DNS-Prefetch-Control",
                "Informational",
                "The X-DNS-Prefetch-Control header is missing.",
                "",
                remediation="Apply recommended server configuration headers and verify compliance against baseline security standards.",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))

        if "X-Frame-Options" not in headers:
            findings.append(self.make_finding(
                "Missing X-Frame-Options",
                "Medium",
                "The X-Frame-Options header is missing, leaving the application vulnerable to clickjacking attacks.",
                "",
                remediation="Apply recommended server configuration headers and verify compliance against baseline security standards.",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))

        if "X-Content-Type-Options" not in headers:
            findings.append(self.make_finding(
                "Missing X-Content-Type-Options",
                "Low",
                "The X-Content-Type-Options header is missing, which allows browsers to perform MIME-sniffing.",
                "",
                remediation="Apply recommended server configuration headers and verify compliance against baseline security standards.",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))

        if "Referrer-Policy" not in headers:
            findings.append(self.make_finding(
                "Missing Referrer-Policy",
                "Low",
                "The Referrer-Policy header is missing, which allows leaking the referring URL.",
                "",
                remediation="Apply recommended server configuration headers and verify compliance against baseline security standards.",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))
        else:
            findings.append(self.make_finding(
                "Referrer-Policy Configured",
                "Passed",
                "Referrer-Policy is present.",
                headers["Referrer-Policy"],
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))

        return findings


class AdvancedSecurityHeadersModule(ScannerModule):
    module_name = "AdvancedSecurityHeaders"
    description = "Checks COOP, COEP, CORP."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=Config.REQUEST_TIMEOUT)
            headers = get_all_headers(resp)

            if "Cross-Origin-Opener-Policy" not in headers:
                findings.append(self.make_finding(
                    "Missing COOP Header",
                    "Informational",
                    "The Cross-Origin-Opener-Policy header is missing.",
                    "",
                    remediation="Apply recommended server configuration headers and verify compliance against baseline security standards.",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
            if "Cross-Origin-Embedder-Policy" not in headers:
                findings.append(self.make_finding(
                    "Missing COEP Header",
                    "Informational",
                    "The Cross-Origin-Embedder-Policy header is missing.",
                    "",
                    remediation="Apply recommended server configuration headers and verify compliance against baseline security standards.",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
            if "Cross-Origin-Resource-Policy" not in headers:
                findings.append(self.make_finding(
                    "Missing CORP Header",
                    "Informational",
                    "The Cross-Origin-Resource-Policy header is missing.",
                    "",
                    remediation="Apply recommended server configuration headers and verify compliance against baseline security standards.",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
        except Exception:
            pass
        return findings


class SubdomainProbingModule(ScannerModule):
    module_name = "SubdomainProbing"
    description = "Probes common subdomains for the target."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        domain = hostname[4:] if hostname.startswith("www.") else hostname

        for sub in Config.COMMON_SUBDOMAINS:
            sub_url = f"https://{sub}.{domain}"
            try:
                resp = safe_request("HEAD", sub_url, session=session, timeout=3.0)
                if resp:
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


class SimpleHTMLResourceParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.insecure_resources = []
        self.insecure_forms = []

    def handle_starttag(self, tag, attrs):
        attr_dict = {k.lower(): v for k, v in attrs if k and v}
        
        # Check subresource URLs
        target_attr = None
        if tag in ["script", "img", "iframe", "embed", "audio", "video", "source"]:
            target_attr = attr_dict.get("src")
        elif tag == "link" and "stylesheet" in attr_dict.get("rel", "").lower():
            target_attr = attr_dict.get("href")

        if target_attr and target_attr.strip().lower().startswith("http://"):
            self.insecure_resources.append((tag, target_attr.strip()))

        # Check HTML Form submissions
        if tag == "form":
            action = attr_dict.get("action", "").strip()
            if action.lower().startswith("http://"):
                self.insecure_forms.append(action)


class MixedContentModule(ScannerModule):
    module_name = "MixedContent"
    description = "Checks for active/passive mixed content and insecure HTTP forms on HTTPS pages."

    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        if not url.startswith("https"):
            return findings

        try:
            resp = safe_request("GET", url, session=session, timeout=Config.REQUEST_TIMEOUT)
            if not resp or not resp.text:
                return findings

            parser = SimpleHTMLResourceParser()
            parser.feed(resp.text[:500000])  # Limit parsing to first 500KB for speed

            if parser.insecure_resources:
                sample_count = len(parser.insecure_resources)
                samples = ", ".join([f"<{tag} src='{src}'>" for tag, src in parser.insecure_resources[:3]])
                findings.append(self.make_finding(
                    "Mixed Content Detected",
                    "Medium",
                    f"Found {sample_count} resource(s) loaded over insecure HTTP on an HTTPS page.",
                    f"Examples: {samples}",
                    remediation="Update all resource links (scripts, styles, images) to use relative paths or HTTPS URLs.",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))

            if parser.insecure_forms:
                findings.append(self.make_finding(
                    "Insecure Form Action (HTTP)",
                    "High",
                    "An HTML form on this HTTPS page submits data to an unencrypted HTTP endpoint.",
                    f"Form action: {', '.join(parser.insecure_forms[:2])}",
                    remediation="Ensure all form 'action' attributes use relative paths or explicit 'https://' URLs.",
                    owasp="A02: Cryptographic Failures",
                    category="encryption_tls"
                ))

            if not parser.insecure_resources and not parser.insecure_forms:
                findings.append(self.make_finding(
                    "No Mixed Content Detected",
                    "Passed",
                    "All front-end resources and form actions are safely served over HTTPS.",
                    "Clean HTML subresources",
                    owasp="A05: Security Misconfiguration",
                    category="encryption_tls"
                ))

        except Exception as e:
            logger.error(f"MixedContentModule error: {e}")

        return findings


class SubdomainTakeoverModule(ScannerModule):
    module_name = "SubdomainTakeover"
    description = "Checks CNAME DNS records for dangling cloud provider targets."

    # Cloud service fingerprints indicative of unclaimed resources
    TAKEOVER_FINGERPRINTS = {
        "s3.amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
        "github.io": ["There isn't a GitHub Pages site here"],
        "herokuapp.com": ["No such app", "There's nothing here, yet."],
        "azurewebsites.net": ["Web App not found", "404 Web Site Not Found"],
        "vercel-dns.com": ["The deployment could not be found on Vercel"],
        "netlify.app": ["Not Found - Request ID:"],
        "myshopify.com": ["Sorry, this shop is currently unavailable"]
    }

    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        domain = hostname[4:] if hostname.startswith("www.") else hostname

        try:
            cname_url = f"https://dns.google/resolve?name={domain}&type=CNAME"
            resp = safe_request("GET", cname_url, session=session, timeout=4.0)

            if not resp or resp.status_code != 200:
                return findings

            data = resp.json()
            answers = data.get("Answer", [])
            if not answers:
                return findings

            cname_target = answers[0].get("data", "").rstrip(".").lower()

            # Check if CNAME points to a known cloud provider
            vulnerable_provider = None
            for provider_domain in self.TAKEOVER_FINGERPRINTS:
                if provider_domain in cname_target:
                    vulnerable_provider = provider_domain
                    break

            if vulnerable_provider:
                # Issue a fast probe to verify if the resource returns an unclaimed error
                probe_resp = safe_request("GET", f"http://{domain}", session=session, timeout=3.0)
                page_text = probe_resp.text if probe_resp else ""

                expected_errors = self.TAKEOVER_FINGERPRINTS[vulnerable_provider]
                if any(err in page_text for err in expected_errors):
                    findings.append(self.make_finding(
                        "Subdomain Takeover Vulnerability (Dangling CNAME)",
                        "High",
                        f"Domain points via CNAME to an abandoned '{vulnerable_provider}' resource that can be claimed by an attacker.",
                        f"CNAME Target: {cname_target}",
                        remediation="Remove the stale DNS CNAME record immediately or reclaim the resource on the third-party service.",
                        owasp="A05: Security Misconfiguration",
                        category="domain_email"
                    ))
                else:
                    findings.append(self.make_finding(
                        "CNAME Alias Configured",
                        "Passed",
                        f"Domain uses a valid CNAME target pointing to {vulnerable_provider}.",
                        f"Target: {cname_target}",
                        owasp="A05: Security Misconfiguration",
                        category="domain_email"
                    ))

        except Exception as e:
            logger.error(f"SubdomainTakeoverModule error: {e}")

        return findings


class TLSCipherStrengthModule(ScannerModule):
    module_name = "TLSCipherStrength"
    description = "Tests SSL/TLS cipher suites for weak algorithms (RC4, 3DES, EXPORT)."

    WEAK_CIPHER_KEYWORDS = ["RC4", "3DES", "DES", "MD5", "EXPORT", "NULL", "ANON"]

    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []

        # Pass 1: Check active negotiated cipher suite
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=Config.REQUEST_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        cipher_name, tls_ver, bit_len = cipher_info[0], cipher_info[1], cipher_info[2]
                        
                        is_weak = any(kw in cipher_name.upper() for kw in self.WEAK_CIPHER_KEYWORDS) or bit_len < 128
                        if is_weak:
                            findings.append(self.make_finding(
                                "Weak TLS Cipher Negotiated",
                                "Medium",
                                f"The server negotiated a weak cipher suite ({cipher_name}) with {bit_len}-bit encryption.",
                                f"Cipher: {cipher_name} ({tls_ver})",
                                remediation="Disable weak ciphers (3DES, RC4) in server configuration and enforce AES-GCM or CHACHA20.",
                                owasp="A02: Cryptographic Failures",
                                category="encryption_tls"
                            ))
                        else:
                            findings.append(self.make_finding(
                                "Strong TLS Cipher Suite Enforced",
                                "Passed",
                                f"Server negotiated a secure cipher ({cipher_name}) with {bit_len}-bit encryption.",
                                f"Cipher: {cipher_name} ({tls_ver})",
                                owasp="A02: Cryptographic Failures",
                                category="encryption_tls"
                            ))
        except Exception:
            pass

        # Pass 2: Probe explicitly for legacy weak ciphers
        try:
            weak_ctx = ssl.create_default_context()
            weak_ctx.check_hostname = False
            weak_ctx.verify_mode = ssl.CERT_NONE
            weak_ctx.set_ciphers("3DES:RC4:DES:MD5:EXPORT")

            weak_supported = False
            with socket.create_connection((hostname, 443), timeout=3.0) as sock:
                with weak_ctx.wrap_socket(sock, server_hostname=hostname):
                    weak_supported = True

            if weak_supported:
                findings.append(self.make_finding(
                    "Legacy Weak TLS Ciphers Supported",
                    "Medium",
                    "Server accepts connections configured with deprecated weak ciphers (e.g. 3DES / RC4).",
                    "Handshake accepted weak cipher list",
                    remediation="Reconfigure server TLS cipher order to forbid 3DES, RC4, and EXPORT suites.",
                    owasp="A02: Cryptographic Failures",
                    category="encryption_tls"
                ))
        except Exception:
            pass  # Handshake rejection means weak ciphers are disabled (Good)

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
    AdvancedSecurityHeadersModule(),
    # --- Category A New Additions ---
    MixedContentModule(),
    SubdomainTakeoverModule(),
    TLSCipherStrengthModule()
]


def get_ip_location(ip: str) -> str:
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if res.get("status") == "success":
            country = res.get("country", "Global")
            org = res.get("org") or res.get("isp") or "Cloud"
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
    try:
        w = whois.whois(domain)
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
        with socket.create_connection((domain, 443), timeout=3) as sock:
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
            with socket.create_connection((domain, 443), timeout=3) as sock:
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


def scan_url(url: str, probe_subdomains: bool = False) -> dict:
    url = canonicalize_url(url)
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
            initial_resp = safe_request("GET", url, session=session, timeout=5, verify=False)
        except Exception:
            initial_resp = None

        metadata = get_metadata(hostname, initial_resp, url)

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

    if metadata.get("ipv6_supported"):
        all_findings.append({
            "name": "IPv6 Dual-Stack Supported",
            "severity": "Passed",
            "category": "encryption_tls",
            "description": "The server supports IPv6 connectivity.",
            "evidence": "IPv6 Address Reachable",
            "confidence": "High",
            "remediation": "N/A",
            "remediation_snippets": {},
            "owasp": "A05: Security Misconfiguration",
            "compliance": {"pci_dss": "N/A", "nist": "N/A", "iso27001": "N/A"},
            "module": "Network",
            "impact": "N/A",
            "cvss": None
        })

    if metadata.get("http2_supported") or metadata.get("http3_supported"):
        all_findings.append({
            "name": "Modern Protocol Supported (HTTP/2 or HTTP/3)",
            "severity": "Passed",
            "category": "encryption_tls",
            "description": "The server uses modern, performant HTTP protocols.",
            "evidence": "HTTP/2 or HTTP/3 detected",
            "confidence": "High",
            "remediation": "N/A",
            "remediation_snippets": {},
            "owasp": "A05: Security Misconfiguration",
            "compliance": {"pci_dss": "N/A", "nist": "N/A", "iso27001": "N/A"},
            "module": "Network",
            "impact": "N/A",
            "cvss": None
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
                if sev in ["Critical", "High"]:
                    high_critical_failed_pci.add(p_c)
            if n_c and n_c != "N/A":
                failed_nist.add(n_c)
                if sev in ["Critical", "High"]:
                    high_critical_failed_nist.add(n_c)
            if i_c and i_c != "N/A":
                failed_iso.add(i_c)
                if sev in ["Critical", "High"]:
                    high_critical_failed_iso.add(i_c)
        elif sev == "Passed":
            if p_c and p_c != "N/A":
                passed_pci.add(p_c)
            if n_c and n_c != "N/A":
                passed_nist.add(n_c)
            if i_c and i_c != "N/A":
                passed_iso.add(i_c)

    def process_compliance(failed_set: set, passed_set: set):
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

    def get_status(failed_high_crit: set, passed_list: list) -> str:
        if len(failed_high_crit) == 0 and len(passed_list) >= 2:
            return "Compliant"
        return "Action Required"

    score = max(0, 100 - sum(penalties.values()))

    # Calculate Radar Sub-scores out of 100
    category_scores = {
        cat: max(0, 100 - pen) for cat, pen in category_penalties.items()
    }

    return {
        "url": url,
        "score": score,
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

    # Safely escape all dynamic strings inserted into HTML
    escaped_url = html.escape(str(data['url']))
    escaped_summary = html.escape(str(data['executive_summary']))
    report_date = datetime.datetime.now().strftime("%B %d, %Y")

    table_rows = []
    for f in data['findings']:
        sev = html.escape(str(f['severity']))
        name = html.escape(str(f['name']))
        owasp = html.escape(str(f['owasp']))
        evidence = html.escape(str(f['evidence']))
        table_rows.append(
            f"<tr><td class='sev-{sev}'>{sev}</td><td>{name}</td><td>{owasp}</td>"
            f"<td><div class='snippet'>{evidence}</div></td></tr>"
        )
    findings_rows = "".join(table_rows)

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Security Posture Report - {html.escape(hostname)}</title>
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
            <div style="color: #94a3b8; margin-top: 5px;">Target: {escaped_url} | Date: {report_date}</div>
        </div>
        <div class="score-badge">{data['score']}/100</div>
    </div>

    <div class="card">
        <h2>Executive Summary</h2>
        <p>{escaped_summary}</p>
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
            {findings_rows}
        </table>
    </div>
</body>
</html>"""
    return HTMLResponse(content=html_content, status_code=200)
