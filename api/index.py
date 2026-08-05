import ipaddress
import socket
import ssl
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
import logging
import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from abc import ABC, abstractmethod
import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- CENTRAL CONFIGURATION ---
class Config:
    REQUEST_TIMEOUT = 6.0
    MAX_REDIRECTS = 5
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    THREAD_POOL_SIZE = 10
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
        "A+": 100,
        "A": 95,
        "B": 85,
        "C": 70,
        "D": 50,
        "F": 0
    }

app = FastAPI(title="Website Security Posture Checker (Advanced Modular)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

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

def get_http_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": Config.USER_AGENT})
    return session

# --- SSRF-SAFE REQUEST WRAPPER ---
def safe_request(method: str, url: str, session: requests.Session = None, max_redirects: int = Config.MAX_REDIRECTS, timeout: float = Config.REQUEST_TIMEOUT, **kwargs) -> requests.Response:
    """
    Executes HTTP requests while explicitly validating the IP address 
    of every hostname in a redirect chain to prevent SSRF attacks.
    """
    current_url = url
    own_session = False
    
    if session is None:
        session = get_http_session()
        own_session = True

    # Disable automatic redirects so we can manually inspect each hop
    kwargs["allow_redirects"] = False

    try:
        for hop in range(max_redirects + 1):
            parsed = urlparse(current_url)
            hostname = parsed.hostname

            if not is_public_hostname(hostname):
                raise requests.exceptions.RequestException(
                    f"SSRF Protection blocked request to non-public host: {hostname}"
                )

            resp = session.request(method, current_url, timeout=timeout, **kwargs)

            # Check if response is a redirect
            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    break
                # Resolve relative redirect URLs
                current_url = urljoin(current_url, location)
            else:
                return resp

        raise requests.exceptions.TooManyRedirects(f"Exceeded maximum redirects ({max_redirects})")
    finally:
        if own_session:
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
    def run(self, url: str, hostname: str) -> list[dict]:
        pass

    def make_finding(self, name, severity, description, evidence, confidence="High", remediation="N/A", owasp="N/A"):
        return {
            "name": name,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "confidence": confidence,
            "remediation": remediation,
            "owasp": owasp
        }

# --- MODULES ---

class TechFingerprintModule(ScannerModule):
    module_name = "TechFingerprint"
    description = "Identifies technologies via headers."
    
    def run(self, url: str, hostname: str) -> list[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, timeout=Config.REQUEST_TIMEOUT)
            server = resp.headers.get("Server")
            if server:
                findings.append(self.make_finding("Server Header Exposed", "Informational", "The server software and version might be exposed.", server))
            x_powered = resp.headers.get("X-Powered-By")
            if x_powered:
                findings.append(self.make_finding("X-Powered-By Header Exposed", "Low", "Backend technology is explicitly declared.", x_powered, remediation="Remove X-Powered-By header.", owasp="A05: Security Misconfiguration"))
        except Exception:
            pass
        return findings

class InformationDisclosureModule(ScannerModule):
    module_name = "InformationDisclosure"
    description = "Checks for verbose server banners."
    
    def run(self, url: str, hostname: str) -> list[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, timeout=Config.REQUEST_TIMEOUT)
            server = resp.headers.get("Server", "")
            if any(char.isdigit() for char in server) and ("/" in server or "-" in server):
                findings.append(self.make_finding("Verbose Server Banner", "Low", "Server header leaks exact version numbers.", server, remediation="Configure server to only return generic names (e.g., 'nginx').", owasp="A05: Security Misconfiguration"))
        except Exception:
            pass
        return findings

class RobotsTxtModule(ScannerModule):
    module_name = "RobotsTxt"
    description = "Fetches and analyzes robots.txt."
    
    def run(self, url: str, hostname: str) -> list[dict]:
        findings = []
        try:
            target = f"https://{hostname}/robots.txt" if url.startswith("https") else f"http://{hostname}/robots.txt"
            resp = safe_request("GET", target, timeout=Config.REQUEST_TIMEOUT)
            if resp.status_code == 200 and "user-agent" in resp.text.lower():
                lines = len(resp.text.splitlines())
                findings.append(self.make_finding("robots.txt Found", "Informational", f"Found robots.txt with {lines} lines.", target))
        except Exception:
            pass
        return findings

class SitemapModule(ScannerModule):
    module_name = "SitemapXml"
    description = "Checks for sitemap.xml."
    
    def run(self, url: str, hostname: str) -> list[dict]:
        findings = []
        try:
            target = f"https://{hostname}/sitemap.xml" if url.startswith("https") else f"http://{hostname}/sitemap.xml"
            resp = safe_request("GET", target, timeout=Config.REQUEST_TIMEOUT)
            if resp.status_code == 200 and ("<urlset" in resp.text or "<sitemapindex" in resp.text):
                findings.append(self.make_finding("sitemap.xml Found", "Informational", "Found XML sitemap.", target))
        except Exception:
            pass
        return findings

class SecurityTxtModule(ScannerModule):
    module_name = "SecurityTxt"
    description = "Checks for security.txt."
    
    def run(self, url: str, hostname: str) -> list[dict]:
        findings = []
        try:
            target = f"https://{hostname}/.well-known/security.txt" if url.startswith("https") else f"http://{hostname}/.well-known/security.txt"
            resp = safe_request("GET", target, timeout=Config.REQUEST_TIMEOUT)
            if resp.status_code == 200 and "contact" in resp.text.lower():
                findings.append(self.make_finding("security.txt Found", "Passed", "Organization has published security.txt.", target))
            else:
                findings.append(self.make_finding("security.txt Missing", "Informational", "No standard security.txt found.", target, remediation="Publish a security.txt file at /.well-known/security.txt."))
        except Exception:
            pass
        return findings

class CORSModule(ScannerModule):
    module_name = "CORS"
    description = "Analyzes CORS headers."
    
    def run(self, url: str, hostname: str) -> list[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, timeout=Config.REQUEST_TIMEOUT)
            acao = resp.headers.get("Access-Control-Allow-Origin")
            if acao == "*":
                findings.append(self.make_finding("Wildcard CORS Policy", "Medium", "The API allows cross-origin requests from any domain.", "Access-Control-Allow-Origin: *", remediation="Restrict CORS to specific trusted origins.", owasp="A05: Security Misconfiguration"))
            elif acao:
                findings.append(self.make_finding("CORS Enabled", "Informational", "Cross-Origin Resource Sharing is enabled.", f"Access-Control-Allow-Origin: {acao}"))
        except Exception:
            pass
        return findings

class AdvancedCookieModule(ScannerModule):
    module_name = "AdvancedCookie"
    description = "Evaluates HttpOnly, Secure, SameSite, and Max-Age."
    
    # List of non-sensitive tracking/preference cookies to ignore for harsh penalty
    NON_SENSITIVE_COOKIES = {"SEARCH_SAMESITE", "1P_JAR", "NID", "AEC", "OGPC"}

    def run(self, url: str, hostname: str) -> list[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, timeout=Config.REQUEST_TIMEOUT)
            
            raw_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp, "raw") and hasattr(resp.raw, "headers") else []
            if not raw_cookies and "Set-Cookie" in resp.headers:
                raw_cookies = [resp.headers["Set-Cookie"]]

            for cookie_str in raw_cookies:
                parts = [p.strip() for p in cookie_str.split(";") if p.strip()]
                if not parts:
                    continue
                
                cookie_name = parts[0].split("=")[0].strip()
                directives = [p.lower() for p in parts[1:]]
                
                # Determine severity based on cookie sensitivity
                cookie_sev = "Informational" if cookie_name.upper() in self.NON_SENSITIVE_COOKIES else "Medium"
                
                if "httponly" not in directives:
                    findings.append(self.make_finding(
                        f"Missing HttpOnly Flag on Cookie: {cookie_name}", 
                        cookie_sev, 
                        "Cookie can be accessed via client-side scripts.", 
                        f"Cookie: {cookie_name}", 
                        remediation="Add HttpOnly flag to cookies.", 
                        owasp="A05: Security Misconfiguration"
                    ))
                
                if url.startswith("https") and "secure" not in directives:
                    findings.append(self.make_finding(
                        f"Missing Secure Flag on Cookie: {cookie_name}", 
                        cookie_sev, 
                        "Cookie transmitted in cleartext if sent over HTTP.", 
                        f"Cookie: {cookie_name}", 
                        remediation="Add Secure flag to cookies.", 
                        owasp="A02: Cryptographic Failures"
                    ))
                
                samesite_found = any(p.startswith("samesite") for p in directives)
                if not samesite_found:
                    findings.append(self.make_finding(
                        f"Missing SameSite Attribute on Cookie: {cookie_name}", 
                        "Low", 
                        "Cookie lacks SameSite attribute, increasing CSRF risk.", 
                        f"Cookie: {cookie_name}", 
                        remediation="Add SameSite=Lax or SameSite=Strict.", 
                        owasp="A01: Broken Access Control"
                    ))
        except Exception:
            pass
        return findings

class HTTPSRedirectModule(ScannerModule):
    module_name = "HTTPSRedirect"
    description = "Validates HTTP to HTTPS redirection across multi-hop chains safely."
    
    def run(self, url: str, hostname: str) -> list[dict]:
        findings = []
        target = f"http://{hostname}"
        try:
            resp = safe_request("GET", target, timeout=Config.REQUEST_TIMEOUT)
            if resp.url.startswith("https://"):
                findings.append(self.make_finding("HTTPS Redirection Configured", "Passed", "HTTP traffic is correctly redirected to HTTPS.", f"Final Target: {resp.url}"))
            else:
                findings.append(self.make_finding("Missing HTTPS Redirection", "High", "The server accepts cleartext HTTP connections without redirecting to HTTPS.", f"Final URL: {resp.url}", remediation="Configure the server to redirect all port 80 traffic to 443 (HTTPS).", owasp="A02: Cryptographic Failures"))
        except requests.exceptions.RequestException:
            pass
        return findings

class EnhancedTLSModule(ScannerModule):
    module_name = "EnhancedTLS"
    description = "Parses SANs, signature algorithms, and expiration."
    
    def run(self, url: str, hostname: str) -> list[dict]:
        findings = []
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443), timeout=Config.REQUEST_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    
                    findings.append(self.make_finding("Valid SSL/TLS Certificate", "Passed", "The server presents a valid TLS certificate.", f"Version: {version}", owasp="A02: Cryptographic Failures"))
                    
                    subject = dict(x[0] for x in cert.get("subject", []))
                    cn = subject.get("commonName", "")
                    if cn.startswith("*"):
                        findings.append(self.make_finding("Wildcard Certificate in Use", "Informational", "Wildcard certificates carry broader risk if compromised.", f"CN: {cn}", remediation="Consider using specific SANs instead of wildcards.", owasp="A02: Cryptographic Failures"))
                    
                    not_after = cert.get("notAfter")
                    if not_after:
                        clean_date = re.sub(r'\s+', ' ', not_after)
                        expire_date = datetime.datetime.strptime(clean_date, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                        now = datetime.datetime.now(datetime.timezone.utc)
                        days_left = (expire_date - now).days
                        
                        if days_left < 30:
                            findings.append(self.make_finding("Certificate Expiring Soon", "Medium", f"Certificate expires in {days_left} days.", not_after, remediation="Renew the TLS certificate immediately.", owasp="A02: Cryptographic Failures"))
        except Exception as e:
            findings.append(self.make_finding("SSL/TLS Connection Failure", "High", "Failed to establish a secure TLS connection.", str(e), remediation="Ensure the server supports standard TLS protocols.", owasp="A02: Cryptographic Failures"))
        return findings

class SecurityHeadersModule(ScannerModule):
    module_name = "SecurityHeaders"
    description = "Checks HSTS, CSP, XFO, etc."
    
    def run(self, url: str, hostname: str) -> list[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, timeout=Config.REQUEST_TIMEOUT)
            headers = resp.headers
        except requests.exceptions.Timeout as e:
            findings.append(self.make_finding("HTTP Request Failed (Timeout)", "High", "Connection timed out while fetching HTTP headers.", str(e)))
            return findings
        except requests.exceptions.ConnectionError as e:
            findings.append(self.make_finding("HTTP Request Failed (Connection Error)", "High", "Connection refused or DNS failure while fetching HTTP headers.", str(e)))
            return findings
        except Exception as e:
            findings.append(self.make_finding("HTTP Request Failed", "High", "Failed to fetch HTTP headers.", str(e)))
            return findings

        # HSTS
        if "Strict-Transport-Security" not in headers:
            findings.append(self.make_finding("Missing Strict-Transport-Security (HSTS)", "High", "Missing HSTS allows SSL-stripping.", "Header absent.", remediation="Add Strict-Transport-Security header.", owasp="A05: Security Misconfiguration"))
        else:
            findings.append(self.make_finding("Strict-Transport-Security Configured", "Passed", "HSTS is present.", headers["Strict-Transport-Security"]))

        # CSP
        if "Content-Security-Policy" not in headers:
            findings.append(self.make_finding("Missing Content-Security-Policy (CSP)", "High", "Missing CSP allows XSS.", "Header absent.", remediation="Implement CSP.", owasp="A05: Security Misconfiguration"))
        else:
            csp = headers.get("Content-Security-Policy", "")
            if "unsafe-inline" in csp or "unsafe-eval" in csp:
                findings.append(self.make_finding("Weak Content-Security-Policy (CSP)", "Medium", "CSP contains 'unsafe-inline' or 'unsafe-eval'.", csp[:100], remediation="Remove unsafe-inline and unsafe-eval from CSP.", owasp="A05: Security Misconfiguration"))
            else:
                findings.append(self.make_finding("Content-Security-Policy Configured", "Passed", "CSP is present and strict.", csp[:100]))

        # X-Frame-Options
        if "X-Frame-Options" not in headers:
            findings.append(self.make_finding("Missing X-Frame-Options", "Medium", "Missing XFO allows clickjacking.", "Header absent.", remediation="Add X-Frame-Options: DENY.", owasp="A05: Security Misconfiguration"))

        # X-Content-Type-Options
        if "X-Content-Type-Options" not in headers:
            findings.append(self.make_finding("Missing X-Content-Type-Options", "Low", "Missing this allows MIME-sniffing.", "Header absent.", remediation="Add X-Content-Type-Options: nosniff.", owasp="A05: Security Misconfiguration"))
            
        # Referrer-Policy
        if "Referrer-Policy" not in headers:
            findings.append(self.make_finding("Missing Referrer-Policy", "Low", "Missing Referrer-Policy allows leaking the referring URL.", "Header absent.", remediation="Add Referrer-Policy: strict-origin-when-cross-origin.", owasp="A05: Security Misconfiguration"))
        else:
            findings.append(self.make_finding("Referrer-Policy Configured", "Passed", "Referrer-Policy is present.", headers["Referrer-Policy"]))
            
        return findings

class AdvancedSecurityHeadersModule(ScannerModule):
    module_name = "AdvancedSecurityHeaders"
    description = "Checks COOP, COEP, CORP."
    
    def run(self, url: str, hostname: str) -> list[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, timeout=Config.REQUEST_TIMEOUT)
            headers = resp.headers
            
            if "Cross-Origin-Opener-Policy" not in headers:
                findings.append(self.make_finding("Missing COOP Header", "Informational", "COOP is missing.", "Header absent.", remediation="Add Cross-Origin-Opener-Policy.", owasp="A05: Security Misconfiguration"))
            if "Cross-Origin-Embedder-Policy" not in headers:
                findings.append(self.make_finding("Missing COEP Header", "Informational", "COEP is missing.", "Header absent.", remediation="Add Cross-Origin-Embedder-Policy.", owasp="A05: Security Misconfiguration"))
            if "Cross-Origin-Resource-Policy" not in headers:
                findings.append(self.make_finding("Missing CORP Header", "Informational", "CORP is missing.", "Header absent.", remediation="Add Cross-Origin-Resource-Policy.", owasp="A05: Security Misconfiguration"))
        except Exception:
            pass
        return findings

class SubdomainProbingModule(ScannerModule):
    module_name = "SubdomainProbing"
    description = "Probes common subdomains for the target."
    
    def run(self, url: str, hostname: str) -> list[dict]:
        findings = []
        domain = hostname
        if domain.startswith("www."):
            domain = domain[4:]
            
        for sub in Config.COMMON_SUBDOMAINS:
            sub_url = f"https://{sub}.{domain}"
            try:
                resp = safe_request("HEAD", sub_url, timeout=3.0)
                findings.append(self.make_finding(
                    f"Active Subdomain Found: {sub}.{domain}",
                    "Informational",
                    f"Probed subdomain responded with status {resp.status_code}.",
                    sub_url
                ))
            except Exception:
                pass
        return findings

# Engine Registry
REGISTERED_MODULES = [
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

def scan_url(url: str, probe_subdomains: bool = False) -> dict:
    hostname = urlparse(url).hostname
    if not hostname:
        return {"url": url, "error": "Could not parse a hostname from that URL."}
    if not is_public_hostname(hostname):
        return {"url": url, "error": "That host resolves to a private/internal address and can't be scanned."}

    all_findings = []
    
    active_modules = [mod for mod in REGISTERED_MODULES if mod.enabled]
    if probe_subdomains:
        active_modules.append(SubdomainProbingModule())
        
    with ThreadPoolExecutor(max_workers=Config.THREAD_POOL_SIZE) as pool:
        futures = {pool.submit(mod.run, url, hostname): mod for mod in active_modules}
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
                    "description": "The scanner module crashed or timed out.",
                    "evidence": str(e),
                    "confidence": "High",
                    "remediation": "N/A",
                    "owasp": "N/A"
                })

    # --- SCORING ENGINE ---
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Passed": 0}
    penalties = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    max_penalties = {"Critical": 100, "High": 30, "Medium": 20, "Low": 10, "Informational": 0}
    owasp_categories = set()
    
    for f in all_findings:
        sev = f.get("severity", "Informational")
        if sev in severity_counts:
            severity_counts[sev] += 1
            
        weight = abs(Config.SEVERITY_WEIGHTS.get(sev, 0))
        if sev in penalties:
            penalties[sev] = min(penalties[sev] + weight, max_penalties[sev])
        
        owasp = f.get("owasp")
        if owasp and owasp != "N/A":
            owasp_categories.add(owasp)
            
    score = max(0, 100 - sum(penalties.values()))
    
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
        "owasp_coverage": list(owasp_categories),
        "findings": all_findings,
        "potential_issues_count": sum(c for k, c in severity_counts.items() if k in ["Critical", "High", "Medium", "Low"]),
        "executive_summary": f"Scan completed. Detected {severity_counts['High'] + severity_counts['Critical']} high-priority issues resulting in a score of {score}/100.",
        "disclaimer": "Passive scan only. Modular engine execution."
    }

@app.post("/api/scan")
def scan_single(req: ScanRequest):
    return scan_url(req.url, req.probe_subdomains)

@app.post("/api/scan/batch")
def scan_batch(req: BatchScanRequest):
    workers = min(10, len(req.urls)) or 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(scan_url, req.urls))
    return {"results": results}
