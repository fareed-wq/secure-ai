import re
import logging
from typing import List
import requests

from api.scanner.base import ScannerModule
from api.scanner.transport import safe_request

logger = logging.getLogger(__name__)


class AdvancedCookieModule(ScannerModule):
    module_name = "AdvancedCookie"
    description = "Evaluates HttpOnly, Secure, SameSite, and scopes with session-awareness."
    NON_SENSITIVE_COOKIES = {"SEARCH_SAMESITE", "1P_JAR", "NID", "AEC", "OGPC"}

    def is_session_cookie(self, name: str) -> bool:
        nl = name.lower()
        session_keywords = {
            "session", "sessionid", "sess", "sid", "auth", "token", 
            "access_token", "refresh_token", "jwt", "connect.sid", 
            "phpsessid", "jsessionid", "asp.net_sessionid"
        }
        return any(k in nl for k in session_keywords)

    def mask_cookie_value(self, cookie_str: str) -> str:
        parts = cookie_str.split(";")
        if not parts:
            return cookie_str
        first_part = parts[0]
        if "=" in first_part:
            name, _ = first_part.split("=", 1)
            parts[0] = f"{name}=[REDACTED]"
        return ";".join(parts)

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=(1.5, 2.5))
            if not resp:
                return findings

            raw_cookies = (
                resp.raw.headers.getlist("Set-Cookie")
                if hasattr(resp, "raw") and hasattr(resp.raw, "headers")
                else []
            )
            set_cookie_header = self.get_header_safe(resp, "Set-Cookie")
            if not raw_cookies and set_cookie_header:
                raw_cookies = [set_cookie_header]

            seen_cookies = set()
            missing_httponly = []
            missing_secure = []
            missing_samesite = []

            for cookie_str in raw_cookies:
                parts = [p.strip() for p in cookie_str.split(";") if p.strip()]
                if not parts:
                    continue

                cookie_name_part = parts[0]
                if "=" not in cookie_name_part:
                    continue
                cookie_name = cookie_name_part.split("=")[0].strip()
                
                if cookie_name in seen_cookies:
                    continue
                seen_cookies.add(cookie_name)

                directives = [p.lower() for p in parts[1:]]
                
                is_secure = "secure" in directives
                is_httponly = "httponly" in directives
                
                samesite_val = None
                domain_val = None
                path_val = None
                for d in directives:
                    if d.startswith("samesite="):
                        samesite_val = d.split("=")[1].strip()
                    elif d == "samesite":
                        samesite_val = "unknown"
                    elif d.startswith("domain="):
                        domain_val = d.split("=", 1)[1].strip()
                    elif d.startswith("path="):
                        path_val = d.split("=", 1)[1].strip()

                is_session = self.is_session_cookie(cookie_name)
                masked_cookie = self.mask_cookie_value(cookie_str)
                
                # Smart Session Cookie Checks
                if is_session:
                    if not is_secure and url.startswith("https"):
                        findings.append(self.make_finding(
                            "Session Cookie Missing Secure Flag",
                            "Medium",
                            "A likely session/authentication cookie lacks the 'Secure' flag.",
                            masked_cookie,
                            remediation="Add the 'Secure' attribute to ensure the cookie is only transmitted over HTTPS.",
                            owasp="A05: Security Misconfiguration",
                            category="session_cookies",
                            confidence="High"
                        ))
                    if not is_httponly:
                        findings.append(self.make_finding(
                            "Session Cookie Missing HttpOnly Flag",
                            "Medium",
                            "A likely session/authentication cookie lacks the 'HttpOnly' flag.",
                            masked_cookie,
                            remediation="Add the 'HttpOnly' attribute to prevent client-side script access.",
                            owasp="A05: Security Misconfiguration",
                            category="session_cookies",
                            confidence="High"
                        ))
                    
                    if not samesite_val:
                        findings.append(self.make_finding(
                            "Session Cookie Missing SameSite Attribute",
                            "Low",
                            "A likely session cookie has no SameSite attribute, relying on default browser behavior.",
                            masked_cookie,
                            remediation="Explicitly set SameSite=Lax or SameSite=Strict.",
                            owasp="A05: Security Misconfiguration",
                            category="session_cookies",
                            confidence="High"
                        ))
                    elif samesite_val == "none" and not is_secure:
                        findings.append(self.make_finding(
                            "Session Cookie Uses SameSite=None Without Secure",
                            "Medium",
                            "A likely session cookie specifies SameSite=None but lacks the Secure flag, which is invalid in modern browsers.",
                            masked_cookie,
                            remediation="Add the Secure flag when using SameSite=None.",
                            owasp="A05: Security Misconfiguration",
                            category="session_cookies",
                            confidence="High"
                        ))
                    
                    if domain_val and domain_val.startswith(".") and domain_val != f".{hostname}":
                        # Basic broad domain check
                        findings.append(self.make_finding(
                            "Broad Session Cookie Domain Scope",
                            "Low",
                            "A likely session cookie has a broad Domain attribute scope, potentially exposing it to subdomains.",
                            f"Domain={domain_val} on cookie {cookie_name}",
                            remediation="Scope session cookies tightly to the exact host.",
                            owasp="A05: Security Misconfiguration",
                            category="session_cookies",
                            confidence="Medium"
                        ))
                else:
                    # Collect non-session cookie issues for bulk reporting
                    if not is_httponly:
                        missing_httponly.append(cookie_name)
                    if not is_secure and url.startswith("https"):
                        missing_secure.append(cookie_name)
                    if not samesite_val:
                        missing_samesite.append(cookie_name)

                # Prefix Checks
                if cookie_name.startswith("__Host-"):
                    path_is_root = path_val == "/"
                    if not is_secure or not path_is_root or domain_val is not None:
                        findings.append(self.make_finding(
                            "Invalid __Host- Cookie Prefix Configuration",
                            "Medium",
                            "A cookie using the __Host- prefix does not meet security requirements (must have Secure, Path=/, and no Domain).",
                            masked_cookie,
                            remediation="Ensure the cookie sets Secure, Path=/, and omits the Domain attribute.",
                            owasp="A05: Security Misconfiguration",
                            category="session_cookies"
                        ))
                elif cookie_name.startswith("__Secure-"):
                    if not is_secure:
                        findings.append(self.make_finding(
                            "Invalid __Secure- Cookie Prefix Configuration",
                            "Medium",
                            "A cookie using the __Secure- prefix lacks the Secure flag.",
                            masked_cookie,
                            remediation="Ensure the cookie sets the Secure attribute.",
                            owasp="A05: Security Misconfiguration",
                            category="session_cookies"
                        ))

            all_unsecured = set(missing_httponly + missing_secure + missing_samesite)
            if all_unsecured:
                problems = []
                if missing_httponly:
                    problems.append(f"Missing HttpOnly: {', '.join(missing_httponly)}.")
                if missing_secure:
                    problems.append(f"Missing Secure: {', '.join(missing_secure)}.")
                if missing_samesite:
                    problems.append(f"Missing SameSite: {', '.join(missing_samesite)}.")

                overall_sev = "Low"
                if all(c.upper() in self.NON_SENSITIVE_COOKIES for c in all_unsecured):
                    overall_sev = "Informational"

                count_len = len(all_unsecured)
                title = f"Unsecured Non-Session Cookie{'s' if count_len > 1 else ''} Detected ({count_len})"
                findings.append(self.make_finding(
                    title,
                    overall_sev,
                    " ".join(problems),
                    f"Cookies affected: {', '.join(all_unsecured)}",
                    remediation="Consider adding HttpOnly, Secure, and SameSite flags to all cookies.",
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
            resp = safe_request("GET", target, session=session, timeout=(1.5, 2.5))
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


class SecurityHeadersModule(ScannerModule):
    module_name = "SecurityHeaders"
    description = "Checks HSTS, CSP, XFO, etc."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=(1.5, 2.5))
        except requests.exceptions.Timeout as e:
            findings.append(self.make_finding(
                "HTTP Request Failed (Timeout)",
                "High",
                "Connection timed out while fetching HTTP headers.",
                str(e),
                owasp="A05: Security Misconfiguration",
                                category="http_headers"
            ))
            return findings
        except requests.exceptions.ConnectionError as e:
            findings.append(self.make_finding(
                "HTTP Request Failed (Connection Error)",
                "High",
                "Connection refused or DNS failure while fetching HTTP headers.",
                str(e),
                owasp="A05: Security Misconfiguration",
                                category="http_headers"
            ))
            return findings
        except Exception as e:
            findings.append(self.make_finding(
                "HTTP Request Failed",
                "High",
                "Failed to fetch HTTP headers.",
                str(e),
                owasp="A05: Security Misconfiguration",
                                category="http_headers"
            ))
            return findings

        content_type = self.get_header_safe(resp, "Content-Type", "").lower()
        is_api_response = "application/json" in content_type


        hsts = self.get_header_safe(resp, "Strict-Transport-Security")
        if not hsts:
            findings.append(self.make_finding(
                "Missing Strict-Transport-Security (HSTS)",
                "High",
                "The HTTP Strict-Transport-Security response header is missing, leaving the application vulnerable to SSL-stripping attacks.",
                "Header not found in response",
                remediation="Enable HTTP Strict Transport Security (HSTS) with a long max-age directive and includeSubDomains flag.",
                owasp="A05: Security Misconfiguration",
                category="encryption_tls"
            ))
        else:
            if "max-age=0" in hsts.replace(" ", ""):
                findings.append(self.make_finding(
                    "HSTS Policy Disabled",
                    "High",
                    "The HTTP Strict-Transport-Security (HSTS) header is present but explicitly sets max-age=0, disabling HSTS protection.",
                    hsts,
                    remediation="Increase the max-age directive to at least 15552000 (180 days).",
                    owasp="A05: Security Misconfiguration",
                    category="encryption_tls",
                    confidence="High"
                ))
            else:
                try:
                    match = re.search(r"max-age=(\d+)", hsts)
                    if match and int(match.group(1)) < 15552000:
                        findings.append(self.make_finding(
                            "Weak HSTS max-age Configuration",
                            "Low",
                            "The HSTS max-age is set to less than 180 days.",
                            hsts,
                            remediation="Increase the max-age directive to at least 15552000 (180 days).",
                            owasp="A05: Security Misconfiguration",
                            category="encryption_tls",
                            confidence="High"
                        ))
                    else:
                        findings.append(self.make_finding(
                            "Strict-Transport-Security Configured",
                            "Passed",
                            "HSTS is present and appropriately configured.",
                            hsts,
                            owasp="A02: Cryptographic Failures",
                            category="encryption_tls"
                        ))
                except Exception:
                    pass

        csp = self.get_header_safe(resp, "Content-Security-Policy", "")
        if not is_api_response:
            if not csp:
                findings.append(self.make_finding(
                    "Missing Content-Security-Policy (CSP)",
                    "High",
                    "The HTTP Content-Security-Policy (CSP) response header is missing, leaving the application vulnerable to Cross-Site Scripting (XSS) and data injection attacks.",
                    "Header not found in response",
                    remediation="Configure your web server to issue strict Content-Security-Policy HTTP headers to restrict script execution sources to trusted domains.",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
            else:
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
                        
                if re.search(r"script-src[^;]*\s\*\s", csp + " ") or re.search(r"script-src\s+\*", csp):
                    is_strict = False
                    weak_reasons.append("wildcard '*' script source")

                if re.search(r"script-src[^;]*\sdata:", csp) or re.search(r"script-src[^;]*\sblob:", csp):
                    is_strict = False
                    weak_reasons.append("data: or blob: script source")
                    
                if re.search(r"frame-ancestors[^;]*\s\*\s", csp + " ") or re.search(r"frame-ancestors\s+\*", csp):
                    is_strict = False
                    weak_reasons.append("unrestricted frame-ancestors '*'")

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
                        remediation="Remove unsafe-inline/unsafe-eval, avoid wildcard/data/blob script sources, and strictly define object-src 'none' and base-uri 'self'.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers",
                        confidence="High"
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

        if not self.get_header_safe(resp, "X-Permitted-Cross-Domain-Policies"):
            findings.append(self.make_finding(
                "Missing X-Permitted-Cross-Domain-Policies",
                "Informational",
                "The X-Permitted-Cross-Domain-Policies header is missing.",
                "Header not found in response",
                remediation="Set the X-Permitted-Cross-Domain-Policies header to 'none' to prevent Flash/PDF cross-domain data loading.",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))

        if not self.get_header_safe(resp, "X-DNS-Prefetch-Control"):
            findings.append(self.make_finding(
                "Missing X-DNS-Prefetch-Control",
                "Informational",
                "The X-DNS-Prefetch-Control header is missing.",
                "Header not found in response",
                remediation="Set X-DNS-Prefetch-Control: off to prevent browsers from performing DNS lookups for external links on the page.",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))

        if not is_api_response and not self.get_header_safe(resp, "X-Frame-Options"):
            findings.append(self.make_finding(
                "Missing X-Frame-Options",
                "Medium",
                "The X-Frame-Options header is missing, leaving the application vulnerable to clickjacking attacks.",
                "Header not found in response",
                remediation="Apply the specific header to your web server (e.g., X-Frame-Options: DENY) to defend against client-side attacks.",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))

        if not self.get_header_safe(resp, "X-Content-Type-Options"):
            findings.append(self.make_finding(
                "Missing X-Content-Type-Options",
                "Low",
                "The X-Content-Type-Options header is missing, which allows browsers to perform MIME-sniffing.",
                "Header not found in response",
                remediation="Set X-Content-Type-Options: nosniff to prevent browsers from MIME-sniffing the response.",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))

        referrer = self.get_header_safe(resp, "Referrer-Policy")
        if not referrer:
            findings.append(self.make_finding(
                "Missing Referrer-Policy",
                "Low",
                "The Referrer-Policy header is missing, which allows leaking the referring URL.",
                "Header not found in response",
                remediation="Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer' to control URL leakage.",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))
        else:
            if "unsafe-url" in referrer.lower():
                findings.append(self.make_finding(
                    "Unsafe Referrer Policy Configured",
                    "Low",
                    "The Referrer-Policy is set to 'unsafe-url', which forces the browser to leak the full URL (including query parameters) to all destinations.",
                    referrer,
                    remediation="Change the Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers",
                    confidence="High"
                ))
            else:
                findings.append(self.make_finding(
                    "Referrer-Policy Configured",
                    "Passed",
                    "Referrer-Policy is present.",
                    referrer,
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))

        # SRI Check
        if resp and resp.text:
            sri_regex = re.compile(r'<(?:script|link)[^>]*(?:src|href)=[\'"](https?://(?:cdnjs|jsdelivr|unpkg|stackpath|maxcdn)[^\'"]+)[\'"][^>]*>', re.IGNORECASE)
            matches = sri_regex.finditer(resp.text)
            missing_sri = []
            for match in matches:
                tag = match.group(0)
                url_attr = match.group(1)
                if 'integrity=' not in tag.lower():
                    missing_sri.append(url_attr)
            
            if missing_sri:
                findings.append(self.make_finding(
                    "Missing Subresource Integrity (SRI) on CDN Assets",
                    "Low",
                    "Third-party JavaScript or CSS resources are loaded from external CDNs without cryptographic integrity hashes.",
                    "\n".join(missing_sri),
                    impact="If an external CDN is compromised, attackers can tamper with the hosted script files to inject malicious code into your website.",
                    remediation="Add integrity='sha384-...' and crossorigin='anonymous' attributes to all external CDN script tags.",
                    owasp="A05: Security Misconfiguration",
                                category="http_headers"
                ))

        # WAF & Rate-Limiting Detection
        waf_headers = ['server', 'x-cdn', 'cf-ray', 'x-succinct', 'x-istart-waf', 'awsalb']
        rl_headers = ['x-ratelimit-limit', 'x-ratelimit-remaining', 'retry-after']
        
        waf_found = False
        rl_found = False
        evidence_headers = []
        
        headers = resp.headers if resp else {}
        for k, v in headers.items():
            kl = k.lower()
            if kl in waf_headers or (kl == 'server' and 'cloudflare' in v.lower()):
                waf_found = True
                evidence_headers.append(f"{k}: {v}")
            if kl in rl_headers:
                rl_found = True
                evidence_headers.append(f"{k}: {v}")
                
        if not waf_found and not rl_found:
            findings.append(self.make_finding(
                "No Web Application Firewall (WAF) / Rate-Limiting Headers Detected",
                "Informational",
                "The target application does not expose active WAF or rate-limiting response headers.",
                "WAF/CDN headers absent",
                impact="Leaves public endpoints and login portals more susceptible to automated brute-force, credential stuffing, or Layer 7 DoS attacks.",
                owasp="A05: Security Misconfiguration",
                                category="http_headers"
            ))
        elif waf_found:
            findings.append(self.make_finding(
                "Web Application Firewall (WAF) Active",
                "Passed",
                "WAF or CDN headers were detected.",
                "\n".join(evidence_headers),
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
            resp = safe_request("GET", url, session=session, timeout=(1.5, 2.5))
            
            content_type = self.get_header_safe(resp, "Content-Type", "").lower()
            is_api_response = "application/json" in content_type

            if not is_api_response and not self.get_header_safe(resp, "Cross-Origin-Opener-Policy"):
                findings.append(self.make_finding(
                    "Missing COOP Header",
                    "Informational",
                    "The Cross-Origin-Opener-Policy header is missing.",
                    "Header not found in response",
                    remediation="Set Cross-Origin-Opener-Policy: same-origin to isolate your browsing context from cross-origin popups.",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
            if not is_api_response and not self.get_header_safe(resp, "Cross-Origin-Embedder-Policy"):
                findings.append(self.make_finding(
                    "Missing COEP Header",
                    "Informational",
                    "The Cross-Origin-Embedder-Policy header is missing.",
                    "Header not found in response",
                    remediation="Set Cross-Origin-Embedder-Policy: require-corp to prevent loading cross-origin resources without explicit permission.",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
            if not is_api_response and not self.get_header_safe(resp, "Cross-Origin-Resource-Policy"):
                findings.append(self.make_finding(
                    "Missing CORP Header",
                    "Informational",
                    "The Cross-Origin-Resource-Policy header is missing.",
                    "Header not found in response",
                    remediation="Set Cross-Origin-Resource-Policy: same-origin to prevent other sites from embedding your resources.",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
        except Exception:
            pass
        return findings
