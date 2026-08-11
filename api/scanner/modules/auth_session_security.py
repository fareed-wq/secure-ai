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
                    owasp="A07: Identification and Authentication Failures",
                    category="authentication",
                    impact="This information helps hackers understand how to target your login systems more effectively."
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
            cache_control = self.get_header_safe(resp, "Cache-Control", "").lower()
            if self.is_auth_related(url) or self.is_auth_related(resp.text):
                is_vuln = False
                severity = "Medium"
                
                if not cache_control:
                    is_vuln = True
                elif "no-store" in cache_control or "private" in cache_control:
                    is_vuln = False
                elif "public" in cache_control:
                    if "max-age=0" in cache_control and "must-revalidate" in cache_control:
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
                    owasp="A05: Security Misconfiguration",
                    category="session_cookies",
                    confidence="High",
                    impact="Hackers can use this information to search for specific flaws in that software and launch targeted attacks."
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
                            owasp="A07: Identification and Authentication Failures",
                            category="authentication",
                            confidence="High",
                            impact="These pages are frequent targets for hackers trying to break into user accounts, so they must be heavily protected."
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
                        owasp="A07: Identification and Authentication Failures",
                        category="authentication",
                        confidence="Medium",
                        impact="If these external services have security flaws or are misconfigured, hackers might be able to bypass your login process."
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
                            owasp="A07: Identification and Authentication Failures",
                            category="authentication",
                            confidence="High",
                            impact="This is the front door to your users' accounts and is a primary target for hackers trying to break in."
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
                                impact="Anyone watching the network can read the passwords in plain text and steal user accounts."
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
                                    owasp="A07: Identification and Authentication Failures",
                                    category="authentication",
                                    confidence="High",
                                    impact="If this other website is compromised or untrusted, hackers could easily steal all of your users' passwords."
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
                                        owasp="A05: Security Misconfiguration",
                                        category="authentication",
                                        impact="This makes it harder for users to use strong, complex passwords saved in password managers, leading them to choose weaker passwords."
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
                                impact="Hackers could trick your users into clicking a malicious link that changes their account settings or password without their permission."
                            ))

                if privileged_surface_links:
                    findings.append(self.make_finding(
                        "Privileged / Administrative Surface Discovered",
                        "Informational",
                        description="We found hidden links to administrator or restricted areas of your website.",
                        evidence="\\n".join(list(privileged_surface_links)[:10]),
                        confidence="Medium",
                        owasp="A01: Broken Access Control",
                        category="api_surface",
                        impact="Hackers look for these hidden areas to find ways to take complete control over your website."
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
                owasp="A00: N/A",
                category="authentication",
                impact="Unable to assess due to connection failure."
            ))
            
        return findings
