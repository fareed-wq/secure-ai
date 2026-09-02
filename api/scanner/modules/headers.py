from typing import List
import requests
from api.scanner.base import ScannerModule
from api.scanner.transport import safe_request, get_all_headers

class TechFingerprintModule(ScannerModule):
    module_name = "TechFingerprint"
    description = "Identifies technologies via headers."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=(1.5, 2.5))

            headers_to_check = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"]
            exposed_tech = []
            has_version = False
            import re
            version_regex = re.compile(r'\d')

            for h in headers_to_check:
                val = self.get_header_safe(resp, h)
                if val:
                    exposed_tech.append(f"{h}: {val}")
                    if version_regex.search(val):
                        has_version = True

            if exposed_tech:
                if has_version:
                    findings.append(self.make_finding(
                        "Server Version Information Disclosed",
                        "Low",
                        "Your web server publicly announces its exact software name and version.",
                        "\\n".join(exposed_tech),
                        impact="Exposing detailed server/version information gives external observers additional information that may assist reconnaissance.",
                        confidence="High",
                        remediation="Configure server to return generic names and omit version numbers.",
                        owasp="Not Mapped",
                        category="information_exposure"
                    ))
                else:
                    findings.append(self.make_finding(
                        "Server Header Exposed",
                        "Informational",
                        "Your web server publicly announces the software it is running.",
                        "\\n".join(exposed_tech),
                        impact="Exposing technology details provides reconnaissance information to external observers.",
                        remediation="Configure server to return generic names or remove headers.",
                        owasp="Not Mapped",
                        category="information_exposure"
                    ))

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
            pass
        except Exception as e:
            import logging
            logging.getLogger(__name__).debug("TechFingerprintModule failed: %s", e)
        return findings

class CORSModule(ScannerModule):
    module_name = "CORS"
    description = "Analyzes CORS headers."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        request_successful = False
        try:
            synthetic_origin = "https://cors-test.invalid"
            headers = {"Origin": synthetic_origin}
            resp = safe_request("GET", url, headers=headers, session=session, timeout=(1.5, 2.5))

            if resp is None:
                return findings

            # WAF/Challenge protection check
            # If the response is a known WAF challenge, we should not evaluate CORS
            # because the headers belong to the challenge page, not the application.
            vercel_mitigated = self.get_header_safe(resp, "X-Vercel-Mitigated")
            if vercel_mitigated and vercel_mitigated.strip().lower() == "challenge":
                return findings

            acao_raw = self.get_header_safe(resp, "Access-Control-Allow-Origin")
            acao = acao_raw.strip() if acao_raw else ""

            acac_raw = self.get_header_safe(resp, "Access-Control-Allow-Credentials")
            acac = acac_raw.strip().lower() == "true" if acac_raw else False

            evidence_str = "Origin sent: " + synthetic_origin + chr(10) + "Access-Control-Allow-Origin: " + acao_raw + chr(10) + "Access-Control-Allow-Credentials: " + str(acac_raw)

            if acao == synthetic_origin:
                if acac:
                    findings.append(self.make_finding(
                        "Insecure CORS Policy (Arbitrary Origin Reflection with Credentials)",
                        "High",
                        "Your website dynamically reflects an arbitrary origin and allows credentials.",
                        evidence_str,
                        impact="This may allow a malicious origin to read credentialed cross-origin responses when the browser sends applicable credentials.",
                        confidence="High",
                        remediation="Never dynamically reflect the Origin header. Statically define a list of trusted domains.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
                else:
                    findings.append(self.make_finding(
                        "Insecure CORS Policy (Arbitrary Origin Reflection)",
                        "Low",
                        "The server reflects an arbitrary Origin value in its CORS response.",
                        evidence_str,
                        impact="This permits cross-origin reading of responses that are accessible without credentialed CORS. Risk depends on whether the endpoint exposes data that should not be readable by arbitrary origins.",
                        confidence="High",
                        remediation="Statically define a list of trusted domains instead of echoing the request Origin.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
            elif acao == "*":
                if acac:
                    findings.append(self.make_finding(
                        "Insecure CORS Policy (Wildcard with Credentials)",
                        "Low",
                        "Your website specifies a wildcard origin and allows credentials, but browsers block this combination.",
                        evidence_str,
                        impact="Modern web browsers strictly reject this invalid configuration, preventing direct exploitation. However, it indicates inconsistent CORS middleware or security configuration.",
                        confidence="High",
                        remediation="Fix the CORS middleware configuration. Access-Control-Allow-Credentials: true must only be used with a specific, statically defined Origin, never a wildcard (*).",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
                else:
                    findings.append(self.make_finding(
                        "CORS Enabled (Wildcard)",
                        "Informational",
                        "Your website allows any other website on the internet to read its public responses.",
                        evidence_str,
                        impact="If this part of your website contains sensitive data, any other website can access it.",
                        confidence="Medium",
                        remediation="Restrict CORS to specific trusted origins if the endpoint handles sensitive data.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
            elif acao == "null":
                if acac:
                    findings.append(self.make_finding(
                        "CORS Null-Origin Configuration Observed",
                        "Low",
                        "The tested response returned Access-Control-Allow-Origin: null while a different synthetic Origin was sent.",
                        evidence_str,
                        impact="This may indicate a null-origin CORS configuration, but acceptance of an actual Origin: null request was not verified.",
                        confidence="High",
                        remediation="Do not trust the 'null' origin. Statically define a list of trusted domains.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
                else:
                    findings.append(self.make_finding(
                        "CORS Null-Origin Configuration Observed",
                        "Informational",
                        "The tested response returned Access-Control-Allow-Origin: null while a different synthetic Origin was sent.",
                        evidence_str,
                        impact="This may indicate a null-origin CORS configuration, but acceptance of an actual Origin: null request was not verified.",
                        confidence="Medium",
                        remediation="Ensure that the 'null' origin is intentionally trusted.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
            elif acao:
                findings.append(self.make_finding(
                    "CORS Configured for Specific Origin",
                    "Informational",
                    "The response allows a specific origin that differs from the test origin.",
                    evidence_str,
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))

            # Reached end of evaluation successfully
            request_successful = True

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException):
            pass
        except Exception as e:
            import logging
            logging.getLogger(__name__).debug("CORSModule failed: %s", e)

        if request_successful and not any("CORS" in f["name"].upper() for f in findings):
            findings.append(self.make_finding(
                "Strict CORS Policy Enforced",
                "Passed",
                "No permissive Access-Control-Allow-Origin policy was observed on the tested response.",
                "Origin sent: " + synthetic_origin + chr(10) + "Access-Control-Allow-Origin: not present",
                owasp="A05: Security Misconfiguration",
                category="http_headers"
            ))

        return findings

class PermissionsPolicyModule(ScannerModule):
    module_name = "PermissionsPolicy"
    description = "Checks Permissions-Policy header."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=(1.5, 2.5))
            headers = get_all_headers(resp)
            content_type = self.get_header_safe(resp, "Content-Type", "").lower()
            is_api_response = "application/json" in content_type

            if "Permissions-Policy" not in headers:
                if not is_api_response:
                    findings.append(self.make_finding(
                        "Missing Permissions-Policy",
                        "Informational",
                        "Your website is missing rules that stop it from using sensitive browser features like the camera, microphone, or location.",
                        "Header not found in response",
                        impact="A missing or overly permissive Permissions-Policy may allow unintended access to sensitive browser features.",
                        remediation="Apply recommended server configuration headers and verify compliance against baseline security standards.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
            else:
                policy_str = headers["Permissions-Policy"]
                sensitive_features = ["geolocation", "camera", "microphone"]
                weak_configs = []

                directives = [d.strip() for d in policy_str.split(",")]
                for d in directives:
                    for feat in sensitive_features:
                        if d.startswith(feat):
                            if "*" in d:
                                weak_configs.append(feat)

                if weak_configs:
                    findings.append(self.make_finding(
                        "Permissive Permissions-Policy",
                        "Low",
                        f"Your website's Permissions-Policy explicitly allows broad access to sensitive features: {', '.join(weak_configs)}.",
                        policy_str[:100],
                        remediation="Restrict sensitive browser features to 'self' or specific trusted origins.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
                else:
                    findings.append(self.make_finding(
                        "Permissions-Policy Configured",
                        "Passed",
                        "Your website has clear rules that restrict the use of sensitive browser features.",
                        policy_str[:100],
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException):
            pass
        except Exception:
            pass
        return findings

class CSPQualityModule(ScannerModule):
    module_name = "CSPQuality"
    description = "Passively analyzes Content-Security-Policy."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=(1.5, 2.5))
            csp = self.get_header_safe(resp, "Content-Security-Policy")

            if csp:
                # 1. Parse CSP into directives preserving original source case
                csp_dict = {}
                for part in csp.split(';'):
                    tokens = part.strip().split(None, 1)
                    if tokens:
                        directive = tokens[0].lower()
                        sources = tokens[1] if len(tokens) > 1 else ""
                        if directive not in csp_dict:
                            csp_dict[directive] = sources

                def get_effective_sources(directive_name):
                    if directive_name in csp_dict:
                        return csp_dict[directive_name]
                    return csp_dict.get('default-src', '')

                weaknesses = []

                # Helper to check nonce/hash token validity
                def has_nonce_or_hash(sources):
                    for token in sources.split():
                        t = token.lower()
                        if t.startswith("'nonce-") and t.endswith("'") and len(t) > 8:
                            return True
                        if (t.startswith("'sha256-") or t.startswith("'sha384-") or t.startswith("'sha512-")) and t.endswith("'") and len(t) > 9:
                            return True
                    return False

                # 2. unsafe-inline evaluation
                script_sources = get_effective_sources('script-src')
                script_sources_lower = script_sources.lower()
                has_nonce_or_hash_script = has_nonce_or_hash(script_sources)

                if "'unsafe-inline'" in script_sources_lower and not has_nonce_or_hash_script:
                    weaknesses.append("unsafe-inline in script-src")

                style_sources = get_effective_sources('style-src')
                if "'unsafe-inline'" in style_sources.lower() and not has_nonce_or_hash(style_sources):
                    weaknesses.append("unsafe-inline in style-src")

                # 2. unsafe-eval evaluation (only in effective script policy)
                if "'unsafe-eval'" in script_sources_lower:
                    weaknesses.append("unsafe-eval")

                # 3. http: sources and strict-dynamic
                script_strict_dynamic = "'strict-dynamic'" in script_sources_lower and has_nonce_or_hash_script

                fetch_and_source_directives = {
                    'default-src', 'script-src', 'style-src', 'img-src', 'connect-src',
                    'font-src', 'object-src', 'media-src', 'frame-src', 'child-src',
                    'worker-src', 'manifest-src', 'prefetch-src', 'base-uri', 'form-action'
                }

                http_found = False
                for directive, sources in csp_dict.items():
                    if directive in fetch_and_source_directives:
                        if "http:" in sources.lower():
                            if directive == 'script-src' and script_strict_dynamic:
                                continue # mitigated by strict-dynamic + nonce/hash
                            http_found = True
                            break

                if http_found:
                    weaknesses.append("http: sources")

                if weaknesses:
                    remediation = []
                    if any("unsafe" in w for w in weaknesses):
                        remediation.append("Remove unsafe-inline and unsafe-eval if possible.")
                    if "http: sources" in weaknesses:
                        remediation.append("Replace insecure HTTP sources with HTTPS.")

                    findings.append(self.make_finding(
                        "Weak Content-Security-Policy",
                        "Medium",
                        "Your website's Content-Security-Policy allows potentially unsafe practices.",
                        f"CSP Weaknesses: {', '.join(weaknesses)}\n\nFull CSP: {csp[:100]}...",
                        impact="A permissive Content Security Policy reduces its effectiveness as a defense-in-depth control against script injection.",
                        confidence="High",
                        remediation=" ".join(remediation),
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))

                # 4. default-src
                has_default_src = "default-src" in csp_dict
                core_fetch_directives = ["script-src", "style-src", "img-src", "connect-src", "font-src", "object-src", "media-src", "frame-src", "worker-src", "manifest-src"]
                unspecified_core = [d for d in core_fetch_directives if d not in csp_dict]

                if not has_default_src and unspecified_core:
                    findings.append(self.make_finding(
                        "CSP Missing Default Source Fallback",
                        "Low",
                        "The Content-Security-Policy lacks a 'default-src' directive and does not explicitly cover common fetch directives.",
                        f"Missing explicitly: {', '.join(unspecified_core)}\n\nFull CSP: {csp[:100]}...",
                        impact="Without a default-src fallback, unspecified resource types default to unrestricted, which may weaken defense-in-depth.",
                        confidence="High",
                        remediation="Add a 'default-src' directive (e.g., default-src 'self' or default-src 'none') to act as a secure fallback.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))

                # 5. object-src
                if "object-src" not in csp_dict:
                    default_sources = csp_dict.get("default-src", "").lower()
                    if "'none'" not in default_sources.split():
                        findings.append(self.make_finding(
                            "CSP Object Sources Not Explicitly Disabled",
                            "Low",
                            "The Content-Security-Policy does not explicitly disable object sources.",
                            f"Full CSP: {csp[:100]}...",
                            impact="Failing to explicitly restrict object-src may leave the application open to legacy plugin risks if a user's browser environment still supports them.",
                            confidence="High",
                            remediation="Add object-src 'none' to your CSP to explicitly disable legacy plugin loading.",
                            owasp="A05: Security Misconfiguration",
                            category="http_headers"
                        ))

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException):
            pass
        except Exception:
            pass
        return findings
