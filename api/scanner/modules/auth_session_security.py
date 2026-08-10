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
        return any(k in lower_text for k in self.AUTH_KEYWORDS)
        
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
                    "The server disclosed an explicit HTTP authentication scheme.",
                    www_auth,
                    owasp="A07: Identification and Authentication Failures",
                    category="authentication"
                ))
                if "basic" in www_auth.lower() and url.startswith("http://"):
                    findings.append(self.make_finding(
                        "Basic Authentication Advertised Over HTTP",
                        "High",
                        "The server advertises Basic authentication over an unencrypted HTTP connection.",
                        www_auth,
                        remediation="Enforce HTTPS for all authentication portals.",
                        owasp="A02: Cryptographic Failures",
                        category="authentication",
                        confidence="High"
                    ))

            # Cache & Auth Response Posture
            cache_control = self.get_header_safe(resp, "Cache-Control", "").lower()
            if self.is_auth_related(url) or self.is_auth_related(resp.text):
                if "public" in cache_control or not cache_control:
                    findings.append(self.make_finding(
                        "Authentication Response May Be Publicly Cacheable",
                        "Medium",
                        "A page containing authentication or session indicators lacks strict cache prevention directives.",
                        f"Cache-Control: {cache_control}" if cache_control else "No Cache-Control header",
                        remediation="Set Cache-Control: no-store, max-age=0 on sensitive pages.",
                        owasp="A05: Security Misconfiguration",
                        category="authentication",
                        confidence="Medium"
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
                    "A specific session management framework was identified via cookies.",
                    f"Technologies: {', '.join(found_session_techs)}",
                    owasp="A05: Security Misconfiguration",
                    category="session_cookies",
                    confidence="High"
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
                            "References to password reset or account recovery were identified.",
                            f"Matched reference: {rec}",
                            owasp="A07: Identification and Authentication Failures",
                            category="authentication",
                            confidence="High"
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
                        "Third-party authentication or identity provider technologies were detected.",
                        f"Technologies: {', '.join(found_auth_techs)}",
                        owasp="A07: Identification and Authentication Failures",
                        category="authentication",
                        confidence="Medium"
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
                            "A password authentication form was detected.",
                            f"Action: {action_truncated}, Method: {method}",
                            owasp="A07: Identification and Authentication Failures",
                            category="authentication",
                            confidence="High"
                        ))
                        
                        # Password Form Over HTTP
                        if action.lower().startswith("http://"):
                            findings.append(self.make_finding(
                                "Password Form Submits Over HTTP",
                                "High",
                                "The password form explicitly submits credentials over an unencrypted HTTP connection.",
                                f"Target Action: {action}",
                                remediation="Ensure all authentication forms submit strictly to HTTPS origins.",
                                owasp="A02: Cryptographic Failures",
                                category="authentication",
                                confidence="High"
                            ))
                            
                        # External Authentication Action
                        if action.startswith("http"):
                            action_domain = urlparse(action).netloc
                            if action_domain and action_domain != hostname:
                                findings.append(self.make_finding(
                                    "Authentication Form Uses External Origin",
                                    "Informational",
                                    "The authentication form submits data to a different domain origin.",
                                    f"External Target: {action_domain}",
                                    owasp="A07: Identification and Authentication Failures",
                                    category="authentication",
                                    confidence="High"
                                ))
                                
                        # Password Autocomplete Policy
                        for inp in inputs:
                            if 'type="password"' in inp.lower() or "type='password'" in inp.lower():
                                if 'autocomplete="off"' in inp.lower() or "autocomplete='off'" in inp.lower():
                                    findings.append(self.make_finding(
                                        "Password Autocomplete Policy Detected",
                                        "Informational",
                                        "A password input explicitly disables autocomplete.",
                                        "autocomplete='off' present on password field.",
                                        owasp="A05: Security Misconfiguration",
                                        category="authentication"
                                    ))

                    # CSRF Posture (Passive Only)
                    is_state_changing = method in ['POST', 'PUT', 'DELETE'] or is_password_form or self.is_auth_related(form)
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
                                "A state-changing form was detected without obvious hidden CSRF protection tokens. (Passive inference only)",
                                "No apparent CSRF token was observed in the analyzed form.",
                                remediation="Ensure all state-changing endpoints are protected by anti-CSRF tokens.",
                                owasp="A01: Broken Access Control",
                                category="authentication",
                                confidence="Low"
                            ))

                if privileged_surface_links:
                    findings.append(self.make_finding(
                        "Privileged / Administrative Surface Discovered",
                        "Informational",
                        "Administrative or privileged application paths were discovered via HTML links or form actions.",
                        "\\n".join(list(privileged_surface_links)[:10]),
                        confidence="Medium",
                        owasp="A01: Broken Access Control",
                        category="api_surface"
                    ))

        except Exception:
            pass
        return findings
