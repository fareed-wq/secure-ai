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
                        "Server headers explicitly disclose technology versions.",
                        "\\n".join(exposed_tech),
                        confidence="High",
                        remediation="Configure server to return generic names and omit version numbers.",
                        owasp="A05: Security Misconfiguration",
                        category="information_exposure"
                    ))
                else:
                    findings.append(self.make_finding(
                        "Server Header Exposed",
                        "Informational",
                        "The server software or backend technology is explicitly declared.",
                        "\\n".join(exposed_tech),
                        remediation="Configure server to return generic names or remove headers.",
                        owasp="A05: Security Misconfiguration",
                        category="information_exposure"
                    ))
                    
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
            # Passive scan - inject a test Origin header to check for reflection
            resp = safe_request("GET", url, session=session, timeout=(1.5, 2.5), headers={"Origin": "https://audit-test.local"})
            acao = self.get_header_safe(resp, "Access-Control-Allow-Origin")
            acac = self.get_header_safe(resp, "Access-Control-Allow-Credentials").lower() == "true"
            
            if acao == "*":
                if acac:
                    findings.append(self.make_finding(
                        "Insecure CORS Policy (Wildcard with Credentials)",
                        "High",
                        "The API passively responded with a wildcard CORS policy (*) AND allows credentials. This is a severe misconfiguration (though modern browsers block it, some older clients or misconfigured proxies may not).",
                        f"Access-Control-Allow-Origin: *\\nAccess-Control-Allow-Credentials: true",
                        confidence="High",
                        remediation="Restrict CORS to specific trusted origins and remove credentials flag if not needed.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
                else:
                    findings.append(self.make_finding(
                        "CORS Enabled (Wildcard)",
                        "Informational",
                        "The API passively responded with a wildcard CORS policy (*). This allows any origin to read responses, but blocks credentials.",
                        "Access-Control-Allow-Origin: *",
                        confidence="Medium",
                        remediation="Restrict CORS to specific trusted origins if the endpoint handles sensitive data.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
            elif acao == "https://audit-test.local" or acao == "null":
                if acac:
                    findings.append(self.make_finding(
                        "Insecure CORS Policy (Arbitrary Origin Reflection with Credentials)",
                        "High",
                        "The API reflects arbitrary Origin headers in its Access-Control-Allow-Origin response AND allows credentials. This allows any malicious site to read authenticated API responses.",
                        f"Access-Control-Allow-Origin: {acao}\\nAccess-Control-Allow-Credentials: true",
                        confidence="High",
                        remediation="Validate the Origin header against a strict whitelist of trusted domains before echoing it back.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
                else:
                    findings.append(self.make_finding(
                        "CORS Enabled (Arbitrary Origin Reflection)",
                        "Medium",
                        "The API reflects arbitrary Origin headers. This allows any origin to read responses, but credentials are NOT allowed.",
                        f"Access-Control-Allow-Origin: {acao}",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
            elif acao:
                findings.append(self.make_finding(
                    "CORS Enabled",
                    "Informational",
                    "Cross-Origin Resource Sharing is enabled for a specific origin.",
                    f"Access-Control-Allow-Origin: {acao}",
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
        
        except Exception as e:
            import logging
            logging.getLogger(__name__).debug("CORSModule failed: %s", e)
        
        if not any("CORS" in f["name"].upper() for f in findings):
            findings.append(self.make_finding(
                "Strict CORS Policy Enforced",
                "Passed",
                "CORS headers are omitted or strictly configured.",
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
                        "Low",
                        "The Permissions-Policy header is missing, allowing web pages to access browser feature APIs unconditionally.",
                        "Header not found in response",
                        remediation="Apply recommended server configuration headers and verify compliance against baseline security standards.",
                        owasp="A05: Security Misconfiguration",
                        category="http_headers"
                    ))
            else:
                findings.append(self.make_finding(
                    "Permissions-Policy Configured",
                    "Passed",
                    "Permissions-Policy header is active.",
                    headers["Permissions-Policy"][:100],
                    owasp="A05: Security Misconfiguration",
                    category="http_headers"
                ))
        except Exception:
            pass
        return findings
