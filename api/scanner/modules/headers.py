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
                        impact="Hackers can easily look up the exact version of your server to find known security flaws and launch a targeted attack against your website.",
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
                        impact="Hackers can use this information to better understand your systems and plan potential attacks.",
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
        try:
            headers = {"Origin": "https://audit-test.local"}
            resp = safe_request("GET", url, headers=headers, session=session, timeout=(1.5, 2.5))
            acao = self.get_header_safe(resp, "Access-Control-Allow-Origin")
            acac = self.get_header_safe(resp, "Access-Control-Allow-Credentials").lower() == "true"

            if acao == "https://audit-test.local" and acac:
                findings.append(self.make_finding(
                    "Insecure CORS Policy (Arbitrary Origin Reflection with Credentials)",
                    "High",
                    "Your website automatically trusts any other website that asks for data, and allows them to access users' private information.",
                    f"Access-Control-Allow-Origin: {acao}\\nAccess-Control-Allow-Credentials: true",
                    impact="Hackers can host a malicious website that silently steals your users' private account information or performs actions on their behalf.",
                    confidence="High",
                    remediation="Never dynamically reflect the Origin header. Statically define a list of trusted domains.",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
            elif acao == "*":
                if acac:
                    findings.append(self.make_finding(
                        "Insecure CORS Policy (Wildcard with Credentials)",
                        "Low",
                        "Your website is set up to allow any other website on the internet to read your users' private data.",
                        f"Access-Control-Allow-Origin: *\\nAccess-Control-Allow-Credentials: true",
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
                        "Access-Control-Allow-Origin: *",
                        impact="If this part of your website contains sensitive data, any other website can access it.",
                        confidence="Medium",
                        remediation="Restrict CORS to specific trusted origins if the endpoint handles sensitive data.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
            elif acao:
                findings.append(self.make_finding(
                    "CORS Enabled",
                    "Informational",
                    "Your website is specifically configured to share data with another trusted website.",
                    f"Access-Control-Allow-Origin: {acao}",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException):
            pass
        except Exception as e:
            import logging
            logging.getLogger(__name__).debug("CORSModule failed: %s", e)

        if not any("CORS" in f["name"].upper() for f in findings):
            findings.append(self.make_finding(
                "Strict CORS Policy Enforced",
                "Passed",
                "Your website safely restricts other websites from reading its data.",
                "No open Access-Control-Allow-Origin header detected.",
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
                        impact="If your website gets hacked, the attackers could secretly turn on the visitors' cameras or track their location.",
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
                csp_lower = csp.lower()
                weaknesses = []

                if "unsafe-inline" in csp_lower:
                    weaknesses.append("unsafe-inline")
                if "unsafe-eval" in csp_lower:
                    weaknesses.append("unsafe-eval")
                if "http:" in csp_lower:
                    weaknesses.append("http: sources")

                if weaknesses:
                    findings.append(self.make_finding(
                        "Weak Content-Security-Policy",
                        "Medium",
                        "Your website's Content-Security-Policy allows potentially unsafe practices.",
                        f"CSP Weaknesses: {', '.join(weaknesses)}\\n\\nFull CSP: {csp[:100]}...",
                        impact="The CSP is too permissive, reducing its effectiveness against Cross-Site Scripting (XSS).",
                        confidence="High",
                        remediation="Remove unsafe-inline and unsafe-eval from your CSP if possible.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException):
            pass
        except Exception:
            pass
        return findings
