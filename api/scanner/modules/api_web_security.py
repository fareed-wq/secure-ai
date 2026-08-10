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
                        "The application downgraded a secure HTTPS request to an insecure HTTP endpoint.",
                        f"From: {first_url} To: {final_url}",
                        confidence="High",
                        remediation="Ensure all redirects maintain or upgrade to HTTPS.",
                        category="encryption_tls",
                        owasp="A02: Cryptographic Failures"
                    ))
                
                # Excessive redirect chain
                if len(resp.history) > 5:
                    chain = " -> ".join([h.url for h in resp.history] + [final_url])
                    findings.append(self.make_finding(
                        "Excessive HTTP Redirect Chain Detected",
                        "Low",
                        "The application uses an excessive number of redirects, which can impact performance and security.",
                        chain[:180],
                        confidence="High",
                        remediation="Minimize redirect hops to a single redirect where possible.",
                        category="misconfiguration",
                        owasp="A05: Security Misconfiguration"
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
                                "The application redirects users to a completely different domain.",
                                f"Redirected to: {final_domain}",
                                confidence="Medium",
                                remediation="Ensure cross-domain redirects only point to trusted external services.",
                                category="misconfiguration",
                                owasp="A05: Security Misconfiguration"
                            ))

            # 3. HTTP Method Posture
            allow = self.get_header_safe(resp, "Allow", "").upper()
            acam = self.get_header_safe(resp, "Access-Control-Allow-Methods", "").upper()
            if "TRACE" in allow or "TRACE" in acam:
                findings.append(self.make_finding(
                    "TRACE HTTP Method Advertised",
                    "Low",
                    "The TRACE HTTP method is explicitly advertised in the response headers.",
                    f"Allow: {allow} | ACAM: {acam}"[:180],
                    confidence="High",
                    remediation="Disable TRACE method to prevent Cross-Site Tracing (XST).",
                    category="misconfiguration",
                    owasp="A05: Security Misconfiguration"
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
                        "The response body is valid JSON, but the Content-Type header incorrectly advertises text/html or text/plain.",
                        f"Content-Type: {content_type}",
                        confidence="Medium",
                        remediation="Ensure API endpoints return application/json Content-Type.",
                        category="http_headers",
                        owasp="A05: Security Misconfiguration"
                    ))

            # 5. API Cache Security
            path = urlparse(resp.url).path.lower()
            is_sensitive_path = any(x in path for x in ['/api', '/user', '/me', '/account', '/profile'])
            if is_sensitive_path:
                cache_control = self.get_header_safe(resp, "Cache-Control", "").lower()
                if "public" in cache_control or "max-age" in cache_control or "s-maxage" in cache_control:
                    findings.append(self.make_finding(
                        "Sensitive API Response May Be Publicly Cacheable",
                        "Medium",
                        "A potentially sensitive API response explicitly permits public caching.",
                        f"Cache-Control: {cache_control}",
                        confidence="Medium",
                        remediation="Set Cache-Control to 'no-store, no-cache, must-revalidate' for sensitive data.",
                        category="http_headers",
                        owasp="A05: Security Misconfiguration"
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
                            f"The application disclosed verbose error information ({name}).",
                            snippet[:180],
                            confidence="Medium",
                            remediation="Configure the application to display generic error messages in production.",
                            category="information_exposure",
                            owasp="A05: Security Misconfiguration"
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
                        "WebSocket endpoints were discovered passively in the page content.",
                        "\\n".join(list(ws_matches)[:3]),
                        confidence="High",
                        category="information_exposure",
                        owasp="A00: Informational"
                    ))
                elif "new WebSocket(" in body or 'WebSocket("' in body or "WebSocket('" in body:
                    findings.append(self.make_finding(
                        "WebSocket Endpoint Discovered",
                        "Informational",
                        "WebSocket invocation pattern discovered passively in the page content.",
                        "new WebSocket(...) observed",
                        confidence="High",
                        category="information_exposure",
                        owasp="A00: Informational"
                    ))

                # API Versions
                ver_matches = set(self.VER_PATTERN.findall(body.lower()))
                if ver_matches:
                    findings.append(self.make_finding(
                        "API Version Disclosed",
                        "Informational",
                        "API versioning information was passively discovered in the page content.",
                        "\\n".join(list(ver_matches)[:5]),
                        confidence="High",
                        category="information_exposure",
                        owasp="A00: Informational"
                    ))

                # Auth Portals
                auth_matches = set(self.AUTH_PATTERN.findall(body.lower()))
                if auth_matches:
                    findings.append(self.make_finding(
                        "Authentication / Administrative Portal Discovered",
                        "Informational",
                        "Administrative or authentication portals were passively discovered.",
                        "\\n".join(list(auth_matches)[:5]),
                        confidence="High",
                        category="information_exposure",
                        owasp="A00: Informational"
                    ))

                # GraphQL refs
                gql_matches = set(self.GQL_PATTERN.findall(body.lower()))
                if gql_matches:
                    findings.append(self.make_finding(
                        "GraphQL Endpoint Reference Discovered",
                        "Informational",
                        "GraphQL endpoint references were passively discovered.",
                        "\\n".join(list(gql_matches)[:3]),
                        confidence="Medium",
                        category="information_exposure",
                        owasp="A00: Informational"
                    ))

                # API Docs
                doc_matches = set(self.DOC_PATTERN.findall(body.lower()))
                if doc_matches:
                    findings.append(self.make_finding(
                        "API Documentation Reference Discovered",
                        "Informational",
                        "API documentation endpoints were passively discovered.",
                        "\\n".join(list(doc_matches)[:5]),
                        confidence="High",
                        category="information_exposure",
                        owasp="A00: Informational"
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
                                "An OpenID Connect (OIDC) configuration file was safely observed.",
                                f"Observed fields: {', '.join(found_fields)}",
                                confidence="High",
                                category="information_exposure",
                                owasp="A00: Informational"
                            ))
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"ApiWebSecurityModule OIDC fetch failed: {e}")

        return findings
