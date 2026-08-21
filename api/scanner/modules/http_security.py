import re
import logging
from html.parser import HTMLParser
from urllib.parse import urlparse
import base64
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
                max_age_val = None
                expires_val = None
                for d in directives:
                    if d.startswith("samesite="):
                        samesite_val = d.split("=")[1].strip()
                    elif d == "samesite":
                        samesite_val = "unknown"
                    elif d.startswith("domain="):
                        domain_val = d.split("=", 1)[1].strip()
                    elif d.startswith("path="):
                        path_val = d.split("=", 1)[1].strip()
                    elif d.startswith("max-age="):
                        max_age_val = d.split("=", 1)[1].strip()
                    elif d.startswith("expires="):
                        expires_val = d.split("=", 1)[1].strip()

                is_session = self.is_session_cookie(cookie_name)
                masked_cookie = self.mask_cookie_value(cookie_str)

                # Lifetime calculation
                effective_lifetime = None
                is_expired_for_deletion = False

                if max_age_val is not None:
                    try:
                        max_age_sec = int(max_age_val)
                        if max_age_sec <= 0:
                            is_expired_for_deletion = True
                        else:
                            effective_lifetime = max_age_sec
                    except ValueError:
                        pass
                elif expires_val is not None:
                    import datetime
                    import email.utils
                    try:
                        parsed_tuple = email.utils.parsedate_tz(expires_val)
                        if parsed_tuple:
                            exp_timestamp = email.utils.mktime_tz(parsed_tuple)
                            now_timestamp = datetime.datetime.now(datetime.timezone.utc).timestamp()
                            diff = exp_timestamp - now_timestamp
                            if diff <= 0:
                                is_expired_for_deletion = True
                            else:
                                effective_lifetime = diff
                    except Exception:
                        pass

                if effective_lifetime is not None and effective_lifetime > 400 * 24 * 3600:
                    if is_session:
                        findings.append(self.make_finding(
                            "Persistent Authentication Cookie",
                            "Low",
                            "A cookie used for authentication or sessions is configured to persist for an unusually long time.",
                            masked_cookie,
                            impact="If a user's device is compromised, long-lived session cookies provide a larger window for attackers to hijack accounts.",
                            remediation="Limit session cookie lifetimes to a reasonable duration (e.g., 400 days or less).",
                            owasp="A05: Security Misconfiguration",
                            category="session_cookies",
                            confidence="High"
                        ))
                    else:
                        findings.append(self.make_finding(
                            "Excessive Cookie Lifetime",
                            "Informational",
                            "A cookie is configured to persist for an unusually long time (over 400 days).",
                            masked_cookie,
                            impact="Excessively long-lived cookies can pose privacy risks by tracking users indefinitely.",
                            remediation="Limit cookie lifetimes to 400 days, aligning with modern browser limits.",
                            owasp="A05: Security Misconfiguration",
                            category="session_cookies"
                        ))

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



class SRIScriptParser(HTMLParser):
    def __init__(self, target_url):
        super().__init__()
        self.target_url = target_url
        self.target_netloc = urlparse(target_url).netloc.lower()
        if self.target_netloc.startswith("www."):
            self.base_domain = self.target_netloc[4:]
        else:
            self.base_domain = self.target_netloc

        self.third_party_scripts = []

    def _is_third_party(self, src: str) -> bool:
        if not src.startswith("http://") and not src.startswith("https://") and not src.startswith("//"):
            return False

        if src.startswith("//"):
            src = "https:" + src

        parsed = urlparse(src)
        netloc = parsed.netloc.lower()

        if not netloc or netloc == self.target_netloc:
            return False

        # Check if it's a subdomain of the target (e.g., assets.example.com vs example.com)
        if netloc.endswith("." + self.base_domain) or netloc == self.base_domain:
            return False

        return True

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            attr_dict = {k.lower(): v for k, v in attrs if k and v}
            src = attr_dict.get("src", "").strip()

            if src and self._is_third_party(src):
                self.third_party_scripts.append({
                    "src": src,
                    "integrity": attr_dict.get("integrity", "").strip(),
                    "crossorigin": attr_dict.get("crossorigin", "").strip()
                })

class SecurityHeadersModule(ScannerModule):
    module_name = "SecurityHeaders"
    description = "Checks HSTS, CSP, XFO, etc."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=(1.5, 2.5))
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
            # Safely skip on network failures to avoid false positives and noise
            # (as requested: Request failed -> safely skipped -> 0 penalty)
            return findings
        except Exception as e:
            logger.error("SecurityHeadersModule unexpected error: %s", e, exc_info=True)
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
        csp_ro = self.get_header_safe(resp, "Content-Security-Policy-Report-Only", "")

        if not is_api_response:
            if not csp:
                if csp_ro:
                    findings.append(self.make_finding(
                        "Content-Security-Policy in Report-Only Mode",
                        "Informational",
                        "Your website has a Content Security Policy (CSP) configured, but it is in 'Report-Only' mode and does not actively block threats.",
                        csp_ro,
                        impact="Because the policy is not enforced, hackers can still exploit vulnerabilities. Report-Only should be used for testing before enabling full enforcement.",
                        remediation="Once testing is complete, change the header to 'Content-Security-Policy' to enforce the rules.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))

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
                low_reasons = []

                if "unsafe-eval" in csp:
                    is_strict = False
                    weak_reasons.append("'unsafe-eval'")

                if "unsafe-inline" in csp:
                    if "object-src 'none'" in csp and "base-uri 'self'" in csp:
                        pass  # Accepted as strict due to framework limitations
                    else:
                        is_strict = False
                        weak_reasons.append("'unsafe-inline' without 'object-src \\'none\\'' and 'base-uri \\'self\\''")

                has_script_src = bool(re.search(r"script-src(?:$|[\s;])", csp))

                if re.search(r"script-src[^;]*\s\*\s", csp + " ") or re.search(r"script-src\s+\*(?:$|;)", csp):
                    is_strict = False
                    weak_reasons.append("wildcard '*' script source")
                elif not has_script_src and (re.search(r"default-src[^;]*\s\*\s", csp + " ") or re.search(r"default-src\s+\*(?:$|;)", csp)):
                    is_strict = False
                    weak_reasons.append("wildcard '*' default source (effective script source)")

                if re.search(r"script-src[^;]*\shttp:", csp) or (not has_script_src and re.search(r"default-src[^;]*\shttp:", csp)):
                    low_reasons.append("insecure 'http:' sources permitted for scripts")

                if re.search(r"script-src[^;]*\sdata:", csp) or re.search(r"script-src[^;]*\sblob:", csp):
                    is_strict = False
                    weak_reasons.append("data: or blob: script source")

                if re.search(r"frame-ancestors[^;]*\s\*\s", csp + " ") or re.search(r"frame-ancestors\s+\*(?:$|;)", csp):
                    is_strict = False
                    weak_reasons.append("unrestricted frame-ancestors '*'")

                missing_granular = "object-src" not in csp or "base-uri" not in csp

                if csp_ro:
                    findings.append(self.make_finding(
                        "Content-Security-Policy-Report-Only Also Present",
                        "Informational",
                        "Your website enforces a CSP but also uses a Report-Only CSP, likely for testing new rules.",
                        csp_ro,
                        owasp="Not Mapped",
                        category="http_headers"
                    ))

                if not is_strict or missing_granular or low_reasons:
                    problems = []
                    if not is_strict:
                        problems.append(f"unsafe directives: {', '.join(weak_reasons)}")
                    if low_reasons:
                        problems.append(f"weak configurations: {', '.join(low_reasons)}")
                    if missing_granular:
                        problems.append("missing granular directives like object-src or base-uri")

                    problem_desc = f"CSP contains flaws: {'; '.join(problems)}."
                    sev = "Low"
                    if not is_strict:
                        sev = "Medium"

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

                positive_indicators = []
                if "upgrade-insecure-requests" in csp:
                    positive_indicators.append("upgrade-insecure-requests")
                if "strict-dynamic" in csp:
                    positive_indicators.append("strict-dynamic")
                if "nonce-" in csp:
                    positive_indicators.append("nonce")
                if re.search(r"sha(?:256|384|512)-", csp):
                    positive_indicators.append("hashes")

                if positive_indicators:
                    findings.append(self.make_finding(
                        "Advanced CSP Hardening Detected",
                        "Informational",
                        "Your CSP includes advanced hardening techniques.",
                        f"Features detected: {', '.join(positive_indicators)}",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))

                if resp and resp.text and re.search(r"<form\b", resp.text, re.IGNORECASE):
                    if not re.search(r"form-action(?:$|[\s;])", csp):
                        findings.append(self.make_finding(
                            "CSP Missing form-action Directive",
                            "Informational",
                            "Your HTML contains forms, but your CSP does not restrict where those forms can submit data using the 'form-action' directive.",
                            "Missing 'form-action'",
                            impact="Hackers could potentially inject a form that sends data to an attacker-controlled server.",
                            remediation="Add the 'form-action' directive to restrict form submissions to trusted origins.",
                            owasp="A05: Security Misconfiguration",
                            category="http_headers"
                        ))
                    else:
                        findings.append(self.make_finding(
                            "CSP form-action Configured",
                            "Informational",
                            "Your CSP correctly restricts form submissions.",
                            "form-action present",
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
                owasp="Not Mapped",
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
                owasp="Not Mapped",
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
                "Informational",
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
                "Informational",
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

        # SRI & Third-Party JavaScript Check
        if resp and resp.text:
            parser = SRIScriptParser(url)
            parser.feed(resp.text[:2000000])  # limit size

            if parser.third_party_scripts:
                # 1. Third-Party Script Inventory
                tp_domains = set()
                for script in parser.third_party_scripts:
                    parsed = urlparse(script["src"] if not script["src"].startswith("//") else "https:" + script["src"])
                    if parsed.netloc:
                        tp_domains.add(parsed.netloc)

                if tp_domains:
                    findings.append(self.make_finding(
                        "Third-Party Script Execution Detected",
                        "Informational",
                        description="Your website allows external organizations to execute JavaScript code in your visitors' browsers.",
                        evidence="\\n".join(sorted(list(tp_domains))),
                        impact="If any of these third parties are compromised, they can execute malicious code on your website.",
                        remediation="Regularly audit third-party dependencies and remove unused external scripts.",
                        owasp="Not Mapped",
                        category="technology_detection",
                        confidence="High"
                    ))

                missing_sri = []
                malformed_sri = []
                missing_co = []

                for script in parser.third_party_scripts:
                    src = script["src"]
                    integrity = script["integrity"]
                    crossorigin = script["crossorigin"].lower()

                    if not integrity:
                        missing_sri.append(src)
                    else:
                        # 3. Malformed SRI Attribute
                        # Can have multiple tokens separated by whitespace
                        tokens = integrity.split()
                        valid_tokens = 0
                        for token in tokens:
                            if re.match(r'^sha(256|384|512)-[a-zA-Z0-9+/]+={0,2}$', token):
                                valid_tokens += 1
                        if valid_tokens == 0:
                            malformed_sri.append(f"{src} (integrity: {integrity})")

                        # 4. Cross-Origin Indicator
                        if crossorigin not in ("anonymous", "use-credentials"):
                            missing_co.append(src)

                # 2. Missing SRI
                if missing_sri:
                    findings.append(self.make_finding(
                        "Missing Subresource Integrity (SRI) on Third-Party Asset",
                        "Low",
                        description="Your website loads external JavaScript files without using SRI hashes to verify they haven't been tampered with.",
                        evidence="\\n".join(missing_sri[:5]) + ("\\n... and others" if len(missing_sri) > 5 else ""),
                        impact="If the external service gets hacked, attackers could alter the files to secretly inject malicious code directly into your website.",
                        remediation="Add integrity='sha384-...' and crossorigin='anonymous' attributes to all external script tags.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers",
                        confidence="High"
                    ))

                if malformed_sri:
                    findings.append(self.make_finding(
                        "Malformed Subresource Integrity (SRI) Attribute",
                        "Low",
                        description="A third-party script specifies an integrity attribute, but the hash format is invalid and won't work correctly.",
                        evidence="\\n".join(malformed_sri[:5]),
                        impact="The browser cannot verify the script, which means tampering will go undetected, or the script may fail to load.",
                        remediation="Ensure the integrity attribute contains a valid base64-encoded hash starting with sha256-, sha384-, or sha512-.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers",
                        confidence="High"
                    ))

                if missing_co:
                    findings.append(self.make_finding(
                        "Missing Cross-Origin Attribute for SRI Verification",
                        "Low",
                        description="A third-party script uses SRI but is missing the required crossorigin attribute.",
                        evidence="\\n".join(missing_co[:5]),
                        impact="The browser requires Cross-Origin Resource Sharing (CORS) to verify SRI hashes for third-party scripts. Without this attribute, verification may fail or the script might not load properly.",
                        remediation="Add crossorigin='anonymous' to the script tag.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers",
                        confidence="High"
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
                owasp="Not Mapped",
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

            coop = self.get_header_safe(resp, "Cross-Origin-Opener-Policy")
            coep = self.get_header_safe(resp, "Cross-Origin-Embedder-Policy")
            corp = self.get_header_safe(resp, "Cross-Origin-Resource-Policy")

            if not is_api_response:
                weak = []
                missing = []

                if not coop:
                    missing.append("Cross-Origin-Opener-Policy")
                elif coop.lower() == "unsafe-none":
                    weak.append(f"COOP: {coop}")

                if not coep:
                    missing.append("Cross-Origin-Embedder-Policy")
                elif coep.lower() == "unsafe-none":
                    weak.append(f"COEP: {coep}")

                if not corp:
                    missing.append("Cross-Origin-Resource-Policy")
                elif corp.lower() == "unsafe-none":
                    weak.append(f"CORP: {corp}")

                if weak:
                    findings.append(self.make_finding(
                        "Weak Cross-Origin Isolation",
                        "Low",
                        "Your website is explicitly configured with weak cross-origin isolation policies.",
                        ", ".join(weak),
                        remediation="Configure COOP and COEP to restrict cross-origin interactions.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))

                if "Cross-Origin-Opener-Policy" in missing:
                    findings.append(self.make_finding(
                        "Missing COOP Header",
                        "Informational",
                        "Your website is missing the Cross-Origin-Opener-Policy (COOP) security rule.",
                        "Header not found in response",
                        impact="Malicious websites that open your site in a pop-up might be able to spy on what your users are doing.",
                        remediation="Set Cross-Origin-Opener-Policy: same-origin to isolate your browsing context from cross-origin popups.",
                        owasp="Not Mapped",
                        category="http_headers"
                    ))
                if "Cross-Origin-Embedder-Policy" in missing:
                    findings.append(self.make_finding(
                        "Missing COEP Header",
                        "Informational",
                        "Your website is missing the Cross-Origin-Embedder-Policy (COEP) security rule.",
                        "Header not found in response",
                        impact="Your website might accidentally load malicious files from other sites, putting your visitors at risk.",
                        remediation="Set Cross-Origin-Embedder-Policy: require-corp to prevent loading cross-origin resources without explicit permission.",
                        owasp="Not Mapped",
                        category="http_headers"
                    ))
                if "Cross-Origin-Resource-Policy" in missing:
                    findings.append(self.make_finding(
                        "Missing CORP Header",
                        "Informational",
                        "Your website is missing the Cross-Origin-Resource-Policy (CORP) security rule.",
                        "Header not found in response",
                        impact="Other malicious websites could embed your private images or resources and try to steal information from your logged-in users.",
                        remediation="Set Cross-Origin-Resource-Policy: same-origin to prevent other sites from embedding your resources.",
                        owasp="Not Mapped",
                        category="http_headers"
                    ))

                if not missing and not weak:
                    findings.append(self.make_finding(
                        "Cross-Origin Isolation Configured",
                        "Passed",
                        "Your website has implemented modern cross-origin isolation headers.",
                        f"COOP: {coop}, COEP: {coep}, CORP: {corp}",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
            # Safely skip on network failures to avoid false positives and noise
            pass
        except Exception as e:
            findings.append(self.make_finding(
                "HTTP Security Check Inconclusive",
                "Inconclusive",
                f"The scanner could not complete this check because the target connection failed: {e}",
                "Network request failed",
                confidence="High",
                owasp="Not Mapped",
                category="http_headers",
                impact="Unable to assess due to connection failure."
            ))

        return findings
