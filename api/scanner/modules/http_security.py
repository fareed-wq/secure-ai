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
                            "A cookie used to keep users logged in is missing the 'Secure' setting.",
                            masked_cookie,
                            impact="Hackers intercepting network traffic on public Wi-Fi could steal this cookie and hijack user accounts.",
                            remediation="Add the 'Secure' attribute to ensure the cookie is only transmitted over HTTPS.",
                            owasp="A05: Security Misconfiguration",
                            category="session_cookies",
                            confidence="High"
                        ))
                    if not is_httponly:
                        findings.append(self.make_finding(
                            "Session Cookie Missing HttpOnly Flag",
                            "Medium",
                            "A cookie used to keep users logged in is missing the 'HttpOnly' setting.",
                            masked_cookie,
                            impact="Malicious scripts on your website could easily steal this cookie and take over user accounts.",
                            remediation="Add the 'HttpOnly' attribute to prevent client-side script access.",
                            owasp="A05: Security Misconfiguration",
                            category="session_cookies",
                            confidence="High"
                        ))
                    
                    if not samesite_val:
                        findings.append(self.make_finding(
                            "Session Cookie Missing SameSite Attribute",
                            "Low",
                            "A login cookie is missing the 'SameSite' rule, which tells the browser when to send it.",
                            masked_cookie,
                            impact="Attackers could trick your users into performing unwanted actions on your website from another malicious site.",
                            remediation="Explicitly set SameSite=Lax or SameSite=Strict.",
                            owasp="A05: Security Misconfiguration",
                            category="session_cookies",
                            confidence="High"
                        ))
                    elif samesite_val == "none" and not is_secure:
                        findings.append(self.make_finding(
                            "Session Cookie Uses SameSite=None Without Secure",
                            "Medium",
                            "A login cookie is configured to be sent everywhere but is missing the required 'Secure' safety rule.",
                            masked_cookie,
                            impact="Modern browsers will reject this cookie, which may break your login system, and it leaves the cookie vulnerable to theft.",
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
                            "A login cookie is allowed to be sent to all subdomains of your website.",
                            f"Domain={domain_val} on cookie {cookie_name}",
                            impact="If one of your subdomains is hacked, the attacker could steal this cookie and gain access to the main website.",
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
                            "A cookie trying to use the secure '__Host-' naming rule is missing required safety settings.",
                            masked_cookie,
                            impact="The browser will reject this cookie because it doesn't follow strict security rules, potentially breaking parts of your website.",
                            remediation="Ensure the cookie sets Secure, Path=/, and omits the Domain attribute.",
                            owasp="A05: Security Misconfiguration",
                            category="session_cookies"
                        ))
                elif cookie_name.startswith("__Secure-"):
                    if not is_secure:
                        findings.append(self.make_finding(
                            "Invalid __Secure- Cookie Prefix Configuration",
                            "Medium",
                            "A cookie trying to use the secure '__Secure-' naming rule is missing the 'Secure' flag.",
                            masked_cookie,
                            impact="The browser will reject this cookie because it is not securely encrypted, which could break features on your site.",
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
                    impact="While not used for logins, these unsecured cookies could still be stolen to track users or steal less sensitive information.",
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
                    "Your website correctly forces visitors to use a secure HTTPS connection.",
                    f"Final Target: {resp.url}",
                    impact="This protects your visitors from having their data intercepted by hackers on public Wi-Fi networks.",
                    owasp="A02: Cryptographic Failures",
                    category="encryption_tls"
                ))
            elif resp:
                findings.append(self.make_finding(
                    "Missing HTTPS Redirection",
                    "High",
                    "Your website allows visitors to connect using an unencrypted connection (HTTP) without forcing them to a secure one (HTTPS).",
                    f"Final URL: {resp.url}",
                    impact="Hackers on the same network as your visitors can easily intercept passwords, personal data, and login sessions.",
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
                "Your website is missing a security rule (HSTS) that forces browsers to only use secure connections.",
                "Header not found in response",
                impact="Attackers can downgrade a visitor's secure connection to an insecure one and steal sensitive information like passwords.",
                remediation="Enable HTTP Strict Transport Security (HSTS) with a long max-age directive and includeSubDomains flag.",
                owasp="A05: Security Misconfiguration",
                category="encryption_tls"
            ))
        else:
            if "max-age=0" in hsts.replace(" ", ""):
                findings.append(self.make_finding(
                    "HSTS Policy Disabled",
                    "High",
                    "Your website has a security rule (HSTS) for forcing secure connections, but it is currently turned off.",
                    hsts,
                    impact="Visitors are not protected from connection downgrade attacks, allowing hackers to potentially steal their sensitive data.",
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
                            "Your website's security rule for forcing secure connections (HSTS) is set to expire too quickly.",
                            hsts,
                            impact="If a user does not visit your site frequently, hackers might still be able to trick them into using an insecure connection and steal data.",
                            remediation="Increase the max-age directive to at least 15552000 (180 days).",
                            owasp="A05: Security Misconfiguration",
                            category="encryption_tls",
                            confidence="High"
                        ))
                    else:
                        findings.append(self.make_finding(
                            "Strict-Transport-Security Configured",
                            "Passed",
                            "Your website is correctly using HSTS to force visitors to use secure connections.",
                            hsts,
                            impact="Your visitors are protected from connection downgrade attacks.",
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
                    "Your website does not have a Content Security Policy (CSP), which acts as a bouncer to block malicious scripts.",
                    "Header not found in response",
                    impact="Hackers could inject malicious code into your website to steal your users' information or take over their accounts.",
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
                        impact="Hackers could bypass your weak security policy and inject malicious code into your website to steal user data.",
                        remediation="Remove unsafe-inline/unsafe-eval, avoid wildcard/data/blob script sources, and strictly define object-src 'none' and base-uri 'self'.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers",
                        confidence="High"
                    ))
                else:
                    findings.append(self.make_finding(
                        "Content-Security-Policy Configured",
                        "Passed",
                        "Your website has a strong Content Security Policy (CSP) in place.",
                        csp,
                        impact="Your website is well-protected against malicious script injection attacks.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))

        if not self.get_header_safe(resp, "X-Permitted-Cross-Domain-Policies"):
            findings.append(self.make_finding(
                "Missing X-Permitted-Cross-Domain-Policies",
                "Informational",
                "Your website is missing a rule that tells old technologies like Flash or PDF readers what they are allowed to load.",
                "Header not found in response",
                impact="Although rare today, outdated plugins could be tricked into stealing data from your website.",
                remediation="Set the X-Permitted-Cross-Domain-Policies header to 'none' to prevent Flash/PDF cross-domain data loading.",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))

        if not self.get_header_safe(resp, "X-DNS-Prefetch-Control"):
            findings.append(self.make_finding(
                "Missing X-DNS-Prefetch-Control",
                "Informational",
                "Your website is missing a rule that stops browsers from guessing what external links your visitors might click on.",
                "Header not found in response",
                impact="This could slightly leak visitors' browsing habits to external network monitors, though the risk is very low.",
                remediation="Set X-DNS-Prefetch-Control: off to prevent browsers from performing DNS lookups for external links on the page.",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))

        if not is_api_response and not self.get_header_safe(resp, "X-Frame-Options"):
            findings.append(self.make_finding(
                "Missing X-Frame-Options",
                "Medium",
                "Your website is missing a rule that prevents it from being embedded inside a hidden frame on another website.",
                "Header not found in response",
                impact="Attackers could trick your visitors into clicking hidden buttons on your website, like accidentally deleting their account or making a purchase.",
                remediation="Apply the specific header to your web server (e.g., X-Frame-Options: DENY) to defend against client-side attacks.",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))

        if not self.get_header_safe(resp, "X-Content-Type-Options"):
            findings.append(self.make_finding(
                "Missing X-Content-Type-Options",
                "Low",
                "Your website is missing a rule that stops browsers from guessing what kind of file they are downloading.",
                "Header not found in response",
                impact="Hackers could upload a malicious script disguised as an image, and the browser might run it, compromising the user's computer.",
                remediation="Set X-Content-Type-Options: nosniff to prevent browsers from MIME-sniffing the response.",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))

        referrer = self.get_header_safe(resp, "Referrer-Policy")
        if not referrer:
            findings.append(self.make_finding(
                "Missing Referrer-Policy",
                "Low",
                "Your website is missing a rule that controls how much of your web addresses are shared when visitors click on external links.",
                "Header not found in response",
                impact="Sensitive information hidden in your website's web addresses (like secret password reset tokens) could be accidentally leaked to other websites.",
                remediation="Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer' to control URL leakage.",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))
        else:
            if "unsafe-url" in referrer.lower():
                findings.append(self.make_finding(
                    "Unsafe Referrer Policy Configured",
                    "Low",
                    "Your website is explicitly configured to share your full web addresses whenever visitors click external links.",
                    referrer,
                    impact="Sensitive information hidden in your website's web addresses (like secret password reset tokens) will be leaked to other websites.",
                    remediation="Change the Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers",
                    confidence="High"
                ))
            else:
                findings.append(self.make_finding(
                    "Referrer-Policy Configured",
                    "Passed",
                    "Your website correctly controls what web address information is shared when visitors click external links.",
                    referrer,
                    impact="Sensitive information in your web addresses is protected from being leaked to other websites.",
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
                    "Your website loads files from other services without checking if they have been secretly altered.",
                    "\n".join(missing_sri),
                    impact="If the external service gets hacked, attackers could alter the files to secretly inject malicious code directly into your website.",
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
                "We could not detect a Web Application Firewall (WAF) or speed limit (rate-limiting) protecting your website.",
                "WAF/CDN headers absent",
                impact="Your website is more vulnerable to automated attacks, such as hackers guessing passwords very quickly or crashing your site by flooding it with traffic.",
                owasp="A05: Security Misconfiguration",
                                category="http_headers"
            ))
        elif waf_found:
            findings.append(self.make_finding(
                "Web Application Firewall (WAF) Active",
                "Passed",
                "A Web Application Firewall (WAF) or protective network layer was detected on your website.",
                "\n".join(evidence_headers),
                impact="Your website has an active layer of defense against automated hacker tools and floods of bad traffic.",
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
                    "Your website is missing the Cross-Origin-Opener-Policy (COOP) security rule.",
                    "Header not found in response",
                    impact="Malicious websites that open your site in a pop-up might be able to spy on what your users are doing.",
                    remediation="Set Cross-Origin-Opener-Policy: same-origin to isolate your browsing context from cross-origin popups.",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
            if not is_api_response and not self.get_header_safe(resp, "Cross-Origin-Embedder-Policy"):
                findings.append(self.make_finding(
                    "Missing COEP Header",
                    "Informational",
                    "Your website is missing the Cross-Origin-Embedder-Policy (COEP) security rule.",
                    "Header not found in response",
                    impact="Your website might accidentally load malicious files from other sites, putting your visitors at risk.",
                    remediation="Set Cross-Origin-Embedder-Policy: require-corp to prevent loading cross-origin resources without explicit permission.",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
            if not is_api_response and not self.get_header_safe(resp, "Cross-Origin-Resource-Policy"):
                findings.append(self.make_finding(
                    "Missing CORP Header",
                    "Informational",
                    "Your website is missing the Cross-Origin-Resource-Policy (CORP) security rule.",
                    "Header not found in response",
                    impact="Other malicious websites could embed your private images or resources and try to steal information from your logged-in users.",
                    remediation="Set Cross-Origin-Resource-Policy: same-origin to prevent other sites from embedding your resources.",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
        except Exception:
            pass
        return findings
