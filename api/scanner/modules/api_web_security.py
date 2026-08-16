import logging
import re
from typing import List
from urllib.parse import urlparse, urljoin
import json
import requests

from api.scanner.base import ScannerModule
from api.scanner.transport import safe_request, get_all_headers

logger = logging.getLogger(__name__)

class ApiWebSecurityModule(ScannerModule):
    module_name = "ApiWebSecurity"
    description = "Passive API and Web Security intelligence."

    ERROR_SIGNATURES = [
        (re.compile(r'(?i)Traceback \(most recent call last\):'), 'Python Traceback'),
        (re.compile(r'(?i)java\.lang\.[A-Za-z]+Exception'), 'Java Exception'),
        (re.compile(r'(?i)System\.NullReferenceException'), '.NET Exception'),
        (re.compile(r'(?i)SQL syntax.*MySQL'), 'MySQL Error'),
        (re.compile(r'(?i)PostgreSQL query failed:'), 'PostgreSQL Error'),
        (re.compile(r'(?i)PDOException'), 'PHP PDO Exception')
    ]

    WS_PATTERN = re.compile(r'(wss?://[a-zA-Z0-9\-\.]+)')
    VER_PATTERN = re.compile(r'(/api/v\d+/|/v\d+/|/rest/v\d+/|/graphql/v\d+/)')
    AUTH_PATTERN = re.compile(r'(/login|/signin|/admin|/api/auth|/auth/login)')
    GQL_PATTERN = re.compile(r'(/graphql/?|/api/graphql)')
    DOC_PATTERN = re.compile(r'(/swagger/?|/swagger-ui/?|/openapi/?|/openapi\.json|/api-docs|/redoc/?|/docs/?)')

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            # 1. Base URL fetch
            resp = safe_request("GET", url, session=session, timeout=(1.8, 2.5), allow_redirects=True)
            if not resp:
                return findings

            # 2. Redirect Chain Security
            if len(resp.history) > 0:
                first_url = resp.history[0].url
                final_url = resp.url
                
                # Check HTTP -> HTTP vs HTTPS -> HTTP
                if first_url.startswith("https://") and final_url.startswith("http://"):
                    findings.append(self.make_finding(
                        "HTTP to HTTPS Redirect Security Issue",
                        "Medium",
                        description="Your website sends visitors from a secure connection (HTTPS) back to an unencrypted one (HTTP).",
                        evidence=f"From: {first_url} To: {final_url}",
                        confidence="High",
                        remediation="Ensure all redirects maintain or upgrade to HTTPS.",
                        category="encryption_tls",
                        owasp="A02: Cryptographic Failures",
                        impact="Hackers can intercept this unencrypted traffic to steal sensitive user data like passwords or personal information."
                    ))
                
                # Excessive redirect chain
                if len(resp.history) > 5:
                    chain = " -> ".join([h.url for h in resp.history] + [final_url])
                    findings.append(self.make_finding(
                        "Excessive HTTP Redirect Chain Detected",
                        "Low",
                        description="Your website sends visitors through too many redirects before they reach their destination.",
                        evidence=chain[:180],
                        confidence="High",
                        remediation="Minimize redirect hops to a single redirect where possible.",
                        category="misconfiguration",
                        owasp="A05: Security Misconfiguration",
                        impact="This makes your website load slowly and can make it easier for attackers to hide malicious links from your users."
                    ))
                    
                # Cross-domain redirect
                first_domain = urlparse(first_url).hostname
                final_domain = urlparse(final_url).hostname
                if first_domain and final_domain:
                    # simplistic registrable domain check (last two parts)
                    first_parts = first_domain.split('.')
                    final_parts = final_domain.split('.')
                    if len(first_parts) >= 2 and len(final_parts) >= 2:
                        first_reg = ".".join(first_parts[-2:])
                        final_reg = ".".join(final_parts[-2:])
                        if first_reg != final_reg:
                            # Avoid known safe CDNs or login providers if we had a list, but we'll flag any cross-domain
                            # that isn't obviously related. To minimize FP, we just flag it as Medium/Medium.
                            findings.append(self.make_finding(
                                "Unexpected Cross-Domain Redirect Detected",
                                "Medium",
                                description="Your website redirects users to a completely different and potentially untrusted website.",
                                evidence=f"Redirected to: {final_domain}",
                                confidence="Medium",
                                remediation="Ensure cross-domain redirects only point to trusted external services.",
                                category="misconfiguration",
                                owasp="A05: Security Misconfiguration",
                                impact="Attackers could exploit this to trick your users into visiting a fake website to steal their login details."
                            ))

            # 3. HTTP Method Posture
            allow = self.get_header_safe(resp, "Allow", "").upper()
            acam = self.get_header_safe(resp, "Access-Control-Allow-Methods", "").upper()
            if "TRACE" in allow or "TRACE" in acam:
                findings.append(self.make_finding(
                    "TRACE HTTP Method Advertised",
                    "Low",
                    description="Your web server is set up to allow a troubleshooting feature called the TRACE method.",
                    evidence=f"Allow: {allow} | ACAM: {acam}"[:180],
                    confidence="High",
                    remediation="Disable TRACE method to prevent Cross-Site Tracing (XST).",
                    category="misconfiguration",
                    owasp="A05: Security Misconfiguration",
                    impact="Hackers can sometimes use this feature to bypass security controls and steal user session cookies."
                ))

            # 4. API Content-Type Mismatch
            content_type = self.get_header_safe(resp, "Content-Type", "").lower()
            body = resp.text
            is_json = False
            
            if body and len(body) > 1 and len(body) < 100000:
                body_stripped = body.strip()
                if body_stripped.startswith("{") or body_stripped.startswith("["):
                    try:
                        json.loads(body_stripped)
                        is_json = True
                    except Exception:
                        pass
                        
            # Only check mismatch if it's NOT an SPA fallback
            if is_json and not self.is_spa_fallback(resp, 0):
                if "text/html" in content_type or "text/plain" in content_type:
                    findings.append(self.make_finding(
                        "API Content-Type Mismatch Detected",
                        "Low",
                        description="Your website sends data in one format but incorrectly tells the browser it is a different format.",
                        evidence=f"Content-Type: {content_type}",
                        confidence="Medium",
                        remediation="Ensure API endpoints return application/json Content-Type.",
                        category="http_headers",
                        owasp="A05: Security Misconfiguration",
                        impact="This confusion can sometimes be tricked by hackers into running malicious scripts on your website."
                    ))

            # 5. API Cache Security
            path = urlparse(resp.url).path.lower()
            is_sensitive_path = any(x in path for x in ['/api', '/user', '/me', '/account', '/profile'])
            is_highly_sensitive = any(x in path for x in ['/user', '/me', '/account', '/profile'])
            if is_sensitive_path:
                cache_control = self.get_header_safe(resp, "Cache-Control", "")
                cache_lower = cache_control.lower()
                if "public" in cache_lower or "max-age" in cache_lower or "s-maxage" in cache_lower:
                    findings.append(self.make_finding(
                        "Sensitive API Response May Be Publicly Cacheable",
                        "Medium",
                        description="Your website allows sensitive user data to be saved on public servers or shared networks.",
                        evidence=f"Cache-Control: {cache_control}",
                        confidence="Medium",
                        remediation="Set Cache-Control to 'no-store, no-cache, must-revalidate' for sensitive data.",
                        category="http_headers",
                        owasp="A05: Security Misconfiguration",
                        impact="Other people on the same network or public computers could view your users' private information."
                    ))

                # Deep Cache Analysis
                if ("no-store" in cache_lower or "no-cache" in cache_lower) and ("max-age=" in cache_lower or "s-maxage=" in cache_lower):
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

                is_publicly_cacheable = ("public" in cache_lower or (cache_lower and "max-age" in cache_lower and "max-age=0" not in cache_lower and "no-store" not in cache_lower and "private" not in cache_lower))
                
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

                if is_publicly_cacheable and is_highly_sensitive:
                    vary = self.get_header_safe(resp, "Vary", "").lower()
                    if "cookie" not in vary and "authorization" not in vary:
                        findings.append(self.make_finding(
                            "Missing Cache Vary Protection on Sensitive Content",
                            "Medium",
                            description="Sensitive content permits shared caching but fails to instruct caches to separate responses per user.",
                            evidence=f"Cache-Control: {cache_control} | Vary: {vary}",
                            remediation="If caching is required, ensure 'Vary: Cookie' or 'Vary: Authorization' is present.",
                            owasp="A05: Security Misconfiguration",
                            category="http_headers",
                            impact="A shared cache might mistakenly serve one user's private data to a completely different user."
                        ))

                if "no-store" in cache_lower and is_highly_sensitive:
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
                            owasp="A05: Security Misconfiguration",
                            category="http_headers",
                            impact="Even without caching the content, browsers may send these values back, potentially allowing cross-session tracking."
                        ))

            # 6. API Error Information Disclosure
            if body:
                for sig, name in self.ERROR_SIGNATURES:
                    match = sig.search(body)
                    if match:
                        snippet = body[max(0, match.start()-20):match.end()+100].replace('\n', ' ')
                        findings.append(self.make_finding(
                            "API Error Information Disclosure",
                            "Medium",
                            description=f"Your website shows detailed technical error messages ({name}) to regular users.",
                            evidence=snippet[:180],
                            confidence="Medium",
                            remediation="Configure the application to display generic error messages in production.",
                            category="information_exposure",
                            owasp="A05: Security Misconfiguration",
                            impact="Hackers can read these error messages to understand how your website is built and find weak spots to attack."
                        ))
                        break

            # 7. Passive Web Reconnaissance
            if body:
                # WebSockets
                ws_matches = set(self.WS_PATTERN.findall(body))
                if ws_matches:
                    findings.append(self.make_finding(
                        "WebSocket Endpoint Discovered",
                        "Informational",
                        description="We noticed your website uses WebSockets to send data back and forth.",
                        evidence="\\n".join(list(ws_matches)[:3]),
                        confidence="High",
                        category="information_exposure",
                        owasp="A00: Informational",
                        impact="If not properly secured, hackers might be able to intercept or send fake messages through this real-time connection."
                    ))
                elif "new WebSocket(" in body or 'WebSocket("' in body or "WebSocket('" in body:
                    findings.append(self.make_finding(
                        "WebSocket Endpoint Discovered",
                        "Informational",
                        description="We noticed your website uses WebSockets to communicate in real-time.",
                        evidence="new WebSocket(...) observed",
                        confidence="High",
                        category="information_exposure",
                        owasp="A00: Informational",
                        impact="Without proper security checks, hackers could manipulate this connection to steal data or attack your site."
                    ))

                # API Versions
                ver_matches = set(self.VER_PATTERN.findall(body.lower()))
                if ver_matches:
                    findings.append(self.make_finding(
                        "API Version Disclosed",
                        "Informational",
                        description="Your website publicly shows which exact version of its data interface (API) it is using.",
                        evidence="\\n".join(list(ver_matches)[:5]),
                        confidence="High",
                        category="information_exposure",
                        owasp="A00: Informational",
                        impact="Hackers can look up this exact version to find known security flaws and use them against your website."
                    ))

                # Auth Portals
                auth_matches = set(self.AUTH_PATTERN.findall(body.lower()))
                if auth_matches:
                    findings.append(self.make_finding(
                        "Authentication / Administrative Portal Discovered",
                        "Informational",
                        description="We found a login or admin page that is publicly visible on your website.",
                        evidence="\\n".join(list(auth_matches)[:5]),
                        confidence="High",
                        category="information_exposure",
                        owasp="A00: Informational",
                        impact="If left unprotected or hidden weakly, hackers can try to guess passwords and gain control over your website."
                    ))

                # GraphQL refs
                gql_matches = set(self.GQL_PATTERN.findall(body.lower()))
                if gql_matches:
                    findings.append(self.make_finding(
                        "GraphQL Endpoint Reference Discovered",
                        "Informational",
                        description="Your website uses a data system called GraphQL and its access points are publicly visible.",
                        evidence="\\n".join(list(gql_matches)[:3]),
                        confidence="Medium",
                        category="information_exposure",
                        owasp="A00: Informational",
                        impact="Hackers often target these systems to pull large amounts of sensitive data if they aren't fully locked down."
                    ))

                # API Docs
                doc_matches = set(self.DOC_PATTERN.findall(body.lower()))
                if doc_matches:
                    findings.append(self.make_finding(
                        "API Documentation Reference Discovered",
                        "Informational",
                        description="Your website leaves its internal instruction manual (API documentation) out in the open.",
                        evidence="\\n".join(list(doc_matches)[:5]),
                        confidence="High",
                        category="information_exposure",
                        owasp="A00: Informational",
                        impact="This gives hackers a complete map of how your website works, making it much easier for them to plan an attack."
                    ))
                    
        except requests.exceptions.RequestException:
            pass
        except Exception as e:
            logger.debug(f"ApiWebSecurityModule base fetch failed: {e}")

        # 8. OIDC Configuration
        try:
            oidc_url = urljoin(url, "/.well-known/openid-configuration")
            oidc_resp = safe_request("GET", oidc_url, session=session, timeout=(1.5, 2.5))
            if oidc_resp and oidc_resp.status_code == 200:
                ct = self.get_header_safe(oidc_resp, "Content-Type", "").lower()
                if "application/json" in ct:
                    try:
                        data = oidc_resp.json()
                        required_fields = ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"]
                        found_fields = [f for f in required_fields if f in data]
                        if len(found_fields) >= 2:
                            findings.append(self.make_finding(
                                "OpenID Connect Configuration Discovered",
                                "Informational",
                                description="Your website publicly shares its login system configuration file.",
                                evidence=f"Observed fields: {', '.join(found_fields)}",
                                confidence="High",
                                category="information_exposure",
                                owasp="A00: Informational",
                                impact="While normally safe, any misconfiguration here could help hackers figure out how to bypass your login system."
                            ))
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"ApiWebSecurityModule OIDC fetch failed: {e}")

        return findings
