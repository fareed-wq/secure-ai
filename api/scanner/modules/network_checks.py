import logging
import ssl
import socket
from typing import List
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from api.scanner.base import ScannerModule
from api.scanner.transport import safe_request
from api.scanner.core import Config
from api.scanner.socket_helper import safe_create_connection

logger = logging.getLogger(__name__)


class SubdomainProbingModule(ScannerModule):
    module_name = "SubdomainProbing"
    description = "Probes common subdomains for the target."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        domain = hostname[4:] if hostname.startswith("www.") else hostname

        for sub in Config.COMMON_SUBDOMAINS:
            sub_url = f"https://{sub}.{domain}"
            try:
                resp = safe_request("HEAD", sub_url, session=session, timeout=(1.5, 2.5))
                if resp:
                    findings.append(self.make_finding(
                        f"Active Subdomain Found: {sub}.{domain}",
                        "Informational",
                        "We discovered an active subdomain related to your website.",
                        sub_url,
                        impact="Unused or forgotten subdomains may increase the attack surface if they lack standard security controls.",
                        owasp="A05: Security Misconfiguration",
                                category="information_exposure"
                    ))
            except Exception:
                pass
        return findings


class SubdomainTakeoverModule(ScannerModule):
    module_name = "SubdomainTakeover"
    description = "Checks CNAME DNS records for dangling cloud provider targets."

    # Cloud service fingerprints indicative of unclaimed resources
    TAKEOVER_FINGERPRINTS = {
        "s3.amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
        "github.io": ["There isn't a GitHub Pages site here"],
        "herokuapp.com": ["No such app", "There's nothing here, yet."],
        "azurewebsites.net": ["Web App not found", "404 Web Site Not Found"],
        "vercel-dns.com": ["The deployment could not be found on Vercel"],
        "netlify.app": ["Not Found - Request ID:"],
        "myshopify.com": ["Sorry, this shop is currently unavailable"]
    }

    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        domain = hostname[4:] if hostname.startswith("www.") else hostname

        try:
            cname_url = f"https://dns.google/resolve?name={domain}&type=CNAME"
            resp = safe_request("GET", cname_url, session=session, timeout=(1.5, 2.5))

            if not resp or resp.status_code != 200:
                return findings

            data = resp.json()
            answers = data.get("Answer", [])
            if not answers:
                findings.append(self.make_finding(
                    "No Subdomain Takeover Risk Detected",
                    "Passed",
                    "We checked your domain records and found no abandoned cloud resources.",
                    f"[-] DNS & CNAME Audit\n[!] Target: {hostname} -> [NO CNAME RECORD FOUND]\n\nValidated CNAME and DNS routing records.",
                    impact="Your domains are properly managed, reducing the risk of subdomain takeover.",
                    owasp="Not Mapped",
                    category="domain_email"
                ))
                return findings

            cname_target = answers[0].get("data", "").rstrip(".").lower()

            # Check if CNAME points to a known cloud provider
            vulnerable_provider = None
            for provider_domain in self.TAKEOVER_FINGERPRINTS:
                if provider_domain in cname_target:
                    vulnerable_provider = provider_domain
                    break

            if vulnerable_provider:
                # Issue a fast probe to verify if the resource returns an unclaimed error
                probe_resp = safe_request("GET", f"http://{domain}", session=session, timeout=(1.5, 2.5))
                page_text = probe_resp.text if probe_resp else ""

                expected_errors = self.TAKEOVER_FINGERPRINTS[vulnerable_provider]
                if any(err in page_text for err in expected_errors):
                    findings.append(self.make_finding(
                        "Subdomain Takeover Vulnerability (Dangling CNAME)",
                        "High",
                        f"Your domain is pointing to a cloud service (like {vulnerable_provider}) that has been abandoned or deleted.",
                        f"CNAME Target: {cname_target}",
                        impact="A hacker can claim this abandoned address and set up a fake website under your official domain to scam your users.",
                        confidence="Medium",
                        remediation="Remove the stale DNS CNAME record immediately or reclaim the resource on the third-party service.",
                        owasp="A05: Security Misconfiguration",
                        category="domain_email"
                    ))
                else:
                    findings.append(self.make_finding(
                        "CNAME Alias Configured",
                        "Passed",
                        f"Your domain correctly points to an active third-party service.",
                        f"Target: {cname_target}",
                        impact="Properly configured domain records ensure visitors are safely directed to the right place without risk of subdomain takeover.",
                        owasp="Not Mapped",
                        category="domain_email"
                    ))
            else:
                findings.append(self.make_finding(
                    "No Subdomain Takeover Risk Detected",
                    "Passed",
                    "We checked your domain records and found no abandoned cloud resources.",
                    f"[-] DNS & CNAME Audit\n[!] Target: {hostname} -> [NO CNAME RECORD FOUND]\n\nValidated CNAME and DNS routing records.",
                    impact="Your domains are properly managed, reducing the risk of subdomain takeover.",
                    owasp="Not Mapped",
                    category="domain_email"
                ))

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
            # Safely skip on network failures to avoid false positives and noise
            pass
        except Exception as e:
            logger.error(f"SubdomainTakeoverModule error: {e}")

        return findings


class GraphQLIntrospectionModule(ScannerModule):
    module_name = "GraphQLIntrospection"
    description = "Checks if public GraphQL schemas can be extracted."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=(1.5, 2.5))
            if resp and resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "").lower()
                if "application/json" in content_type:
                    text = resp.text
                    if '"__typename"' in text or '"__schema"' in text:
                        findings.append(self.make_finding(
                            "Public GraphQL Introspection Enabled",
                            "Informational",
                            "Your database interface (GraphQL) is publicly answering questions about how it is structured.",
                            url,
                            impact="Exposed GraphQL introspection provides a complete schema map, assisting reconnaissance.",
                            owasp="Not Mapped",
                            category="information_exposure"
                        ))
        except Exception:
            pass
        return findings

class VerboseStackTraceModule(ScannerModule):
    module_name = "VerboseStackTrace"
    description = "Checks for backend error trace disclosures."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            base_url = f"http://{hostname}" if url.startswith("http://") else f"https://{hostname}"
            target_url = f"{base_url}/api/v1/debug_probe_404"
            resp = safe_request("GET", target_url, session=session, timeout=(1.5, 2.5))
            if resp and resp.text:
                if "Traceback (most recent call last):" in resp.text:
                    findings.append(self.make_finding(
                        "Verbose Error Messages Disclosed",
                        "Low",
                        "Your website reveals detailed internal programming errors when something goes wrong.",
                        "Traceback (most recent call last):",
                        impact="Verbose error messages expose internal application state and structure.",
                        remediation="Configure your web framework to hide detailed error messages in production and show a generic error page instead.",
                        owasp="A05: Security Misconfiguration",
                        category="information_disclosure",
                        confidence="High"
                    ))
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException):
            pass
        except Exception:
            pass
        return findings

class PassiveSubdomainDiscoveryModule(ScannerModule):
    module_name = "PassiveSubdomainDiscovery"
    description = "Discovers subdomains passively via Certificate Transparency logs."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        domain = hostname[4:] if hostname.startswith("www.") else hostname
        discovered_subdomains = set()

        try:
            ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = safe_request("GET", ct_url, session=session, timeout=(1.5, 3.0), max_attempts=1)

            if resp and resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        if not name_value:
                            continue

                        for raw_name in name_value.splitlines():
                            clean_name = raw_name.lower().strip().strip('.')
                            if clean_name.startswith("*."):
                                clean_name = clean_name[2:]

                            if clean_name == domain or clean_name.endswith(f".{domain}"):
                                discovered_subdomains.add(clean_name)
        except Exception as e:
            logger.debug(f"PassiveSubdomainDiscoveryModule error: {e}")
            findings.append(self.make_finding(
                "Subdomain Discovery Inconclusive",
                "Inconclusive",
                "We could not verify your domain's certificate transparency logs due to a network timeout with an external service.",
                "crt.sh connection timed out or failed.",
                owasp="Not Mapped",
                category="information_exposure"
            ))

        if discovered_subdomains:
            sub_list = sorted(list(discovered_subdomains))
            summary_count = len(sub_list)

            categories = {
                "API": 0,
                "Administrative": 0,
                "Development/Staging": 0,
                "Mail": 0,
                "Other": 0
            }

            for sub in sub_list:
                sub_parts = sub.split('.')
                if len(sub_parts) > 1:
                    prefix = sub_parts[0]
                    if prefix in ["api"]:
                        categories["API"] += 1
                    elif prefix in ["admin", "portal", "internal", "vpn"]:
                        categories["Administrative"] += 1
                    elif prefix in ["dev", "development", "staging", "stage", "test", "qa", "uat", "beta"]:
                        categories["Development/Staging"] += 1
                    elif prefix in ["mail"]:
                        categories["Mail"] += 1
                    else:
                        categories["Other"] += 1
                else:
                    categories["Other"] += 1

            evidence_str = f"{summary_count} unique subdomains discovered\n\nAttack Surface Categories:\n"
            evidence_str += f"  API: {categories['API']}\n"
            evidence_str += f"  Administrative: {categories['Administrative']}\n"
            evidence_str += f"  Development/Staging: {categories['Development/Staging']}\n"
            evidence_str += f"  Mail: {categories['Mail']}\n"
            evidence_str += f"  Other: {categories['Other']}\n\n"

            if summary_count > 20:
                evidence_str += f"... (and {summary_count - 20} more omitted)\n"

            evidence_str += "Examples:\n"
            preview = "\n- ".join(sub_list[:20])
            evidence_str += f"- {preview}"

            finding = self.make_finding(
                "Subdomains Discovered",
                "Informational",
                "We found publicly visible addresses (subdomains) connected to your main website.",
                evidence_str,
                impact="Exposed internal IPs reveal network topology and may assist reconnaissance.",
                owasp="Not Mapped",
                category="information_exposure"
            )
            finding["metadata"] = {
                "total_subdomains": summary_count,
                "attack_surface_categories": categories,
                "source": "Certificate Transparency"
            }
            findings.append(finding)

        return findings

