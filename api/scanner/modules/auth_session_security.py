import re
from typing import List
import requests
from urllib.parse import urlparse
from api.scanner.base import ScannerModule
from api.scanner.transport import safe_request

class AuthenticationSessionSecurityModule(ScannerModule):
    module_name = "AuthenticationSessionSecurity"
    description = "Passively analyzes authentication forms, session technologies, CSRF posture, and cache controls."

    AUTH_KEYWORDS = ['login', 'signin', 'account', 'profile', 'dashboard', 'user', 'session', 'auth']
    RECOVERY_KEYWORDS = [r'/forgot-password', r'/reset-password', r'/password/reset', r'forgot password', r'reset password', r'account recovery']
    CSRF_KEYWORDS = ['csrf', 'csrf_token', 'authenticity_token', 'xsrf', '__requestverificationtoken']
    PRIVILEGED_HTML_KEYWORDS = ['/admin', '/administrator', '/staff', '/management', '/control-panel', '/dashboard', '/internal', '/backend']
    SESSION_TECHS = ['PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId', 'connect.sid', 'laravel_session', 'sessionid']
    AUTH_TECHS = ['OAuth', 'OAuth2', 'OpenID Connect', 'SAML', 'Auth0', 'Okta', 'Keycloak', 'Microsoft identity', 'Entra', 'Google Identity', 'Firebase Authentication']

    FORM_PATTERN = re.compile(r'<form[^>]*>.*?</form>', re.IGNORECASE | re.DOTALL)
    INPUT_PATTERN = re.compile(r'<input[^>]+>', re.IGNORECASE)
    HREF_PATTERN = re.compile(r'href=[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
    ACTION_PATTERN = re.compile(r'action=[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
    METHOD_PATTERN = re.compile(r'method=[\'"]([^\'"]+)[\'"]', re.IGNORECASE)

    def is_auth_related(self, text: str) -> bool:
        lower_text = text.lower()
        return any(re.search(r'\b' + re.escape(k) + r'\b', lower_text) for k in self.AUTH_KEYWORDS)

    def extract_forms(self, html: str) -> List[str]:
        return self.FORM_PATTERN.findall(html)

    def extract_inputs(self, form_html: str) -> List[str]:
        return self.INPUT_PATTERN.findall(form_html)

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=(1.5, 3.5))
            if not resp:
                return findings

            headers = resp.headers if resp else {}

            # WWW-Authenticate Intelligence
            www_auth = self.get_header_safe(resp, "WWW-Authenticate")
            if www_auth:
                findings.append(self.make_finding(
                    "HTTP Authentication Scheme Disclosed",
                    "Informational",
                    description="Your server publicly announces the exact method it uses to verify user logins.",
                    evidence=www_auth,
                    owasp="Not Mapped",
                    category="authentication",
                    impact="Exposed authentication logic assists external reconnaissance of the security model."
                ))
                if "basic" in www_auth.lower() and url.startswith("http://"):
                    findings.append(self.make_finding(
                        "Basic Authentication Advertised Over HTTP",
                        "High",
                        description="Your website asks for user logins over an insecure, unencrypted connection.",
                        evidence=www_auth,
                        remediation="Enforce HTTPS for all authentication portals.",
                        owasp="A02: Cryptographic Failures",
                        category="authentication",
                        confidence="High",
                        impact="Anyone on the same network can easily steal user passwords as they are being sent to your website."
                    ))

            # Cache & Auth Response Posture
            cache_control = self.get_header_safe(resp, "Cache-Control", "")
            cache_lower = cache_control.lower()
            is_highly_sensitive = self.is_auth_related(url) or self.is_auth_related(resp.text)

            if is_highly_sensitive:
                is_vuln = False
                severity = "Medium"

                if not cache_control:
                    is_vuln = True
                elif "no-store" in cache_lower or "private" in cache_lower:
                    is_vuln = False
                elif "public" in cache_lower:
                    if "max-age=0" in cache_lower and "must-revalidate" in cache_lower:
                        # Effectively forces revalidation, lower risk but still not strict no-store
                        is_vuln = True
                        severity = "Low"
                    else:
                        # Positive max-age or s-maxage with public is risky for auth
                        is_vuln = True
                        severity = "Medium"

                if is_vuln:
                    findings.append(self.make_finding(
                        "Authentication Response May Be Publicly Cacheable",
                        severity,
                        description="Your website allows sensitive login pages to be saved and stored on public networks.",
                        evidence=f"Cache-Control: {cache_control}" if cache_control else "No Cache-Control header",
                        remediation="Set Cache-Control: no-store, max-age=0 on sensitive pages.",
                        owasp="A05: Security Misconfiguration",
                        category="authentication",
                        confidence="Medium",
                        impact="Other people using the same computer or network might be able to view your users' personal accounts or login details."
                    ))

                # Deep Cache Analysis
                if cache_control and ("no-store" in cache_lower or "no-cache" in cache_lower) and ("max-age=" in cache_lower or "s-maxage=" in cache_lower):
                    findings.append(self.make_finding(
                        "Contradictory Cache-Control Directives",
                        "Low",
                        description="The response contains conflicting instructions about whether the data can be cached.",
                        evidence=f"Cache-Control: {cache_control}",
                        remediation="Ensure Cache-Control headers consistently enforce a single caching policy (e.g., 'no-store' without 'max-age').",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers",
                        impact="Different network proxies may interpret these conflicting rules differently, potentially caching sensitive data unexpectedly."
                    ))

                is_publicly_cacheable = is_vuln or (cache_lower and "max-age" in cache_lower and "max-age=0" not in cache_lower and "no-store" not in cache_lower and "private" not in cache_lower)

                cdn_headers = ["CDN-Cache-Control", "Cloudflare-CDN-Cache-Control"]
                for ch in cdn_headers:
                    val = self.get_header_safe(resp, ch).lower()
                    if val:
                        if "public" in val or ("max-age" in val and "max-age=0" not in val and "no-store" not in val and "private" not in val):
                            is_publicly_cacheable = True
                            findings.append(self.make_finding(
                                "Permissive CDN Caching on Sensitive Content",
                                "Medium",
                                description="A Content Delivery Network (CDN) is explicitly instructed to cache this sensitive response.",
                                evidence=f"{ch}: {val}",
                                remediation="Configure CDN-specific cache headers to 'no-store' for sensitive endpoints.",
                                owasp="A05: Security Misconfiguration",
                                category="http_headers",
                                impact="The CDN may serve this sensitive data to unauthorized users or store it on public edge servers."
                            ))

                if is_publicly_cacheable:
                    vary = self.get_header_safe(resp, "Vary", "").lower()
                    if "cookie" not in vary and "authorization" not in vary:
                        findings.append(self.make_finding(
                            "Cache Variation Header Not Observed",
                            "Informational",
                            description="The JSON response permits shared caching but fails to instruct caches to separate responses per user.",
                            evidence=f"Cache-Control: {cache_control} | Vary: {vary}",
                            remediation="If caching is required, ensure 'Vary: Cookie' or 'Vary: Authorization' is present.",
                            owasp="Not Mapped",
                            category="http_headers",
                            impact="If caching is required for sensitive data, ensure 'Vary: Cookie' or 'Vary: Authorization' is present."
                        ))

                if cache_control and "no-store" in cache_lower:
                    etag = self.get_header_safe(resp, "ETag", "")
                    last_mod = self.get_header_safe(resp, "Last-Modified", "")
                    if etag or last_mod:
                        evidence = f"ETag: {etag}" if etag else f"Last-Modified: {last_mod}"
                        findings.append(self.make_finding(
                            "Sensitive Response Tracking Indicator (ETag/Last-Modified)",
                            "Informational",
                            description="A sensitive response restricts caching but exposes revalidation headers which could be used to track authenticated sessions.",
                            evidence=evidence,
                            remediation="Remove ETag and Last-Modified headers from highly sensitive, non-cacheable API or auth endpoints.",
                            owasp="Not Mapped",
                            category="http_headers",
                            impact="Even without caching the content, browsers may send these values back, potentially allowing cross-session tracking."
                        ))

            # Session Management Technology
            set_cookie = self.get_header_safe(resp, "Set-Cookie", "")
            found_session_techs = []
            for tech in self.SESSION_TECHS:
                if tech.lower() in set_cookie.lower():
                    found_session_techs.append(tech)
            if found_session_techs:
                findings.append(self.make_finding(
                    "Session Technology Fingerprinted",
                    "Informational",
                    description="Your website publicly reveals the specific software it uses to keep users logged in.",
                    evidence=f"Technologies: {', '.join(found_session_techs)}",
                    owasp="Not Mapped",
                    category="session_cookies",
                    confidence="High",
                    impact="Exposing technology details provides reconnaissance information to external observers."
                ))

            # HTML Parsing
            if resp.text:
                html_lower = resp.text.lower()

                # Password Reset / Account Recovery
                for rec in self.RECOVERY_KEYWORDS:
                    if rec in html_lower:
                        findings.append(self.make_finding(
                            "Password Recovery Interface Detected",
                            "Informational",
                            description="We found a password reset or account recovery page on your website.",
                            evidence=f"Matched reference: {rec}",
                            owasp="Not Mapped",
                            category="authentication",
                            confidence="High",
                            impact="Publicly accessible authentication interfaces are common targets for credential attacks and should be protected with appropriate authentication controls, rate limiting, and monitoring."
                        ))
                        break # One finding is enough

                # PHASE 31: Privileged / Administrative Surface Discovery (HTML Links)
                privileged_surface_links = set()
                hrefs = self.HREF_PATTERN.findall(resp.text)
                for href in hrefs:
                    href_lower = href.lower()
                    if any(href_lower.startswith(kw) or href_lower.startswith(f"http://{hostname}{kw}") or href_lower.startswith(f"https://{hostname}{kw}") for kw in self.PRIVILEGED_HTML_KEYWORDS):
                        privileged_surface_links.add(href)

                # Authentication Technology
                found_auth_techs = []
                for atech in self.AUTH_TECHS:
                    if atech.lower() in html_lower or atech.lower() in str(headers).lower():
                        found_auth_techs.append(atech)
                if found_auth_techs:
                    findings.append(self.make_finding(
                        "Authentication Technology Detected",
                        "Informational",
                        description="Your website shows that it uses external third-party services to handle user logins.",
                        evidence=f"Technologies: {', '.join(found_auth_techs)}",
                        owasp="Not Mapped",
                        category="authentication",
                        confidence="Medium",
                        impact="Integration with vulnerable third-party services may introduce authentication bypass vectors."
                    ))

                # Forms Analysis
                forms = self.extract_forms(resp.text)
                for form in forms:
                    inputs = self.extract_inputs(form)

                    is_password_form = any('type="password"' in i.lower() or "type='password'" in i.lower() for i in inputs)
                    action_match = self.ACTION_PATTERN.search(form)
                    method_match = self.METHOD_PATTERN.search(form)

                    action = action_match.group(1) if action_match else ""
                    method = method_match.group(1).upper() if method_match else "GET"

                    if any(action.lower().startswith(kw) for kw in self.PRIVILEGED_HTML_KEYWORDS):
                        privileged_surface_links.add(action)

                    if is_password_form:
                        # Login Form Detection
                        action_truncated = action[:50] + "..." if len(action) > 50 else action
                        findings.append(self.make_finding(
                            "Authentication Interface Detected",
                            "Informational",
                            description="We found a page where users are asked to enter their passwords.",
                            evidence=f"Action: {action_truncated}, Method: {method}",
                            owasp="Not Mapped",
                            category="authentication",
                            confidence="High",
                            impact="Publicly accessible authentication interfaces are common targets for credential attacks and should be protected with appropriate authentication controls, rate limiting, and monitoring."
                        ))

                        # Password Form Over HTTP
                        if action.lower().startswith("http://"):
                            findings.append(self.make_finding(
                                "Password Form Submits Over HTTP",
                                "High",
                                description="Your website sends user passwords across the internet without any encryption.",
                                evidence=f"Target Action: {action}",
                                remediation="Ensure all authentication forms submit strictly to HTTPS origins.",
                                owasp="A02: Cryptographic Failures",
                                category="authentication",
                                confidence="High",
                                impact="Unencrypted authentication endpoints expose credentials to network interception."
                            ))

                        # External Authentication Action
                        if action.startswith("http"):
                            action_domain = urlparse(action).netloc
                            if action_domain and action_domain != hostname:
                                findings.append(self.make_finding(
                                    "Authentication Form Uses External Origin",
                                    "Informational",
                                    description="Your website's login form sends user passwords to a completely different website.",
                                    evidence=f"External Target: {action_domain}",
                                    owasp="Not Mapped",
                                    category="authentication",
                                    confidence="High",
                                    impact="Sending credentials to third-party domains increases the risk of credential interception if those domains are compromised."
                                ))

                        # Password Autocomplete Policy
                        for inp in inputs:
                            if 'type="password"' in inp.lower() or "type='password'" in inp.lower():
                                if 'autocomplete="off"' in inp.lower() or "autocomplete='off'" in inp.lower():
                                    findings.append(self.make_finding(
                                        "Password Autocomplete Policy Detected",
                                        "Informational",
                                        description="Your website explicitly prevents web browsers from saving user passwords.",
                                        evidence="autocomplete='off' present on password field.",
                                        owasp="Not Mapped",
                                        category="authentication",
                                        impact="Disabling autocomplete can interfere with password managers, inadvertently encouraging weaker user-memorized passwords."
                                    ))

                    # CSRF Posture (Passive Only)
                    is_state_changing = method in ['POST', 'PUT', 'PATCH', 'DELETE']
                    if is_state_changing:
                        has_csrf = False
                        for inp in inputs:
                            inp_lower = inp.lower()
                            if 'type="hidden"' in inp_lower or "type='hidden'" in inp_lower:
                                if any(csrf_kw in inp_lower for csrf_kw in self.CSRF_KEYWORDS):
                                    has_csrf = True
                                    break
                        if not has_csrf:
                            findings.append(self.make_finding(
                                "Potential Missing CSRF Protection",
                                "Medium",
                                description="Your website has forms that change account settings but appear to lack hidden security tokens.",
                                evidence="No apparent CSRF token was observed in the analyzed form.",
                                remediation="Ensure all state-changing endpoints are protected by anti-CSRF tokens.",
                                owasp="A01: Broken Access Control",
                                category="authentication",
                                confidence="Low",
                                impact="Without Anti-CSRF tokens, authenticated sessions may be susceptible to Cross-Site Request Forgery (CSRF)."
                            ))

                if privileged_surface_links:
                    findings.append(self.make_finding(
                        "Privileged / Administrative Surface Discovered",
                        "Informational",
                        description="We found hidden links to administrator or restricted areas of your website.",
                        evidence="\\n".join(list(privileged_surface_links)[:10]),
                        confidence="Medium",
                        owasp="Not Mapped",
                        category="api_surface",
                        impact="Exposed administrative interfaces provide targets for unauthorized access attempts."
                    ))

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
            # Safely skip on network failures to avoid false positives and noise
            pass
        except Exception as e:
            logger.error(f"AuthSessionSecurityModule global error: {e}")
            findings.append(self.make_finding(
                "Authentication/Session Security Check Inconclusive",
                "Inconclusive",
                f"The scanner could not complete this check because the target connection failed: {e}",
                "Network request failed",
                confidence="High",
                owasp="Not Mapped",
                category="authentication",
                impact="Unable to assess due to connection failure."
            ))

        return findings
