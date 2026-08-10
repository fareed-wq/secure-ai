import logging
import ssl
import re
from typing import List, Set
from urllib.parse import urlparse
import requests

from api.scanner.base import ScannerModule
from api.scanner.socket_helper import safe_create_connection
from api.scanner.transport import safe_request

logger = logging.getLogger(__name__)


class InfrastructureIntelligenceModule(ScannerModule):
    module_name = "InfrastructureIntelligence"
    description = "Passive infrastructure fingerprinting and attack-surface classification."

    # Cloud Fingerprinting Signatures
    CLOUD_PROVIDERS = {
        "Amazon Web Services (AWS)": [r'\.amazonaws\.com$', r'\.cloudfront\.net$', r'\.elasticbeanstalk\.com$'],
        "Microsoft Azure": [r'\.azurewebsites\.net$', r'\.blob\.core\.windows\.net$', r'\.cloudapp\.azure\.com$'],
        "Google Cloud Platform (GCP)": [r'\.storage\.googleapis\.com$', r'\.appspot\.com$', r'\.cloudfunctions\.net$'],
        "Cloudflare": [r'\.cloudflare\.net$', r'\.cloudflare\.com$'],
        "Vercel": [r'\.vercel\.app$'],
        "Netlify": [r'\.netlify\.app$'],
        "GitHub Pages": [r'\.github\.io$']
    }

    # Dangling Cloud Resource Signatures
    DANGLING_SIGNATURES = {
        "AWS S3": {"status": 404, "body": "<Code>NoSuchBucket</Code>"},
        "Azure Blob": {"status": 404, "body": "ResourceNotFound"},
        "GCP Storage": {"status": 404, "body": "NoSuchBucket"}
    }

    # Mail Providers
    MAIL_PROVIDERS = {
        "Google Workspace": [r'google\.com$', r'googlemail\.com$'],
        "Microsoft 365": [r'outlook\.com$', r'protection\.outlook\.com$'],
        "Proofpoint": [r'pphosted\.com$'],
        "Mimecast": [r'mimecast\.com$'],
        "Amazon SES": [r'amazonses\.com$']
    }

    # DNS Providers
    DNS_PROVIDERS = {
        "Cloudflare": [r'cloudflare\.com$'],
        "AWS Route 53": [r'awsdns'],
        "Google Cloud DNS": [r'googledomains\.com$'],
        "Azure DNS": [r'azure-dns'],
        "GoDaddy": [r'domaincontrol\.com$'],
        "Akamai": [r'akam\.net$']
    }

    def _normalize_hostname(self, hostname: str, base_domain: str) -> str:
        h = hostname.lower().strip().rstrip('.')
        if h.startswith("*."):
            h = h[2:]
        if h == base_domain or h.endswith("." + base_domain):
            return h
        return ""

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        domain = hostname[4:] if hostname.startswith("www.") else hostname
        
        discovered_hostnames = set()

        # 1. Certificate SAN Correlation
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with safe_create_connection((hostname, 443), timeout=2.5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        sans = []
                        for ext in cert.get("subjectAltName", []):
                            if ext[0] == "DNS":
                                norm_h = self._normalize_hostname(ext[1], domain)
                                if norm_h:
                                    sans.append(norm_h)
                                    discovered_hostnames.add(norm_h)
                        
                        sans = list(set(sans))
                        if len(sans) > 0:
                            total = len(sans)
                            examples = "\\n".join(sans[:5])
                            omitted = total - 5 if total > 5 else 0
                            evidence = f"{total} certificate hostnames observed.\\nExamples:\\n{examples}"
                            if omitted > 0:
                                evidence += f"\\n... (and {omitted} more omitted)"
                            findings.append(self.make_finding(
                                "Certificate SANs Reveal Additional Hostnames",
                                "Informational",
                                "Certificate visibility expands observable attack surface and does NOT itself indicate a vulnerability.",
                                evidence,
                                confidence="High",
                                category="information_exposure",
                                owasp="A00: Informational"
                            ))
        except Exception as e:
            logger.debug(f"Infrastructure SAN extraction failed: {e}")

        # Gather CNAME/A/MX/NS for fingerprinting
        cloud_fingerprints = set()
        cname_targets = []
        
        # NS Records
        try:
            ns_url = f"https://dns.google/resolve?name={domain}&type=NS"
            resp = safe_request("GET", ns_url, session=session, timeout=(1.5, 2.5))
            if resp and resp.status_code == 200:
                ns_by_provider = {}
                for rec in resp.json().get("Answer", []):
                    ns = rec.get("data", "").lower().rstrip('.')
                    for provider, patterns in self.DNS_PROVIDERS.items():
                        if any(re.search(p, ns) for p in patterns):
                            if provider not in ns_by_provider:
                                ns_by_provider[provider] = []
                            if ns not in ns_by_provider[provider]:
                                ns_by_provider[provider].append(ns)
                            break
                for provider, records in ns_by_provider.items():
                    evidence_lines = [f"Provider: {provider}"] + [f"- {r}" for r in records]
                    evidence_str = "\n".join(evidence_lines)
                    findings.append(self.make_finding(
                        "DNS Infrastructure Provider Identified",
                        "Informational",
                        "Passively identified the DNS nameserver provider.",
                        evidence_str,
                        confidence="High",
                        category="technology_detection",
                        owasp="A00: Informational"
                    ))
        except Exception:
            pass

        # MX Records
        try:
            mx_url = f"https://dns.google/resolve?name={domain}&type=MX"
            resp = safe_request("GET", mx_url, session=session, timeout=(1.5, 2.5))
            if resp and resp.status_code == 200:
                mx_by_provider = {}
                for rec in resp.json().get("Answer", []):
                    mx = rec.get("data", "").lower().rstrip('.')
                    for provider, patterns in self.MAIL_PROVIDERS.items():
                        if any(re.search(p, mx) for p in patterns):
                            if provider not in mx_by_provider:
                                mx_by_provider[provider] = []
                            if mx not in mx_by_provider[provider]:
                                mx_by_provider[provider].append(mx)
                            break
                for provider, records in mx_by_provider.items():
                    evidence_lines = [f"Provider: {provider}"] + [f"- {r}" for r in records]
                    evidence_str = "\n".join(evidence_lines)
                    findings.append(self.make_finding(
                        "Mail Infrastructure Identified",
                        "Informational",
                        "Passively identified the mail infrastructure provider from MX records.",
                        evidence_str,
                        confidence="High",
                        category="technology_detection",
                        owasp="A00: Informational"
                    ))
        except Exception:
            pass

        # CNAME / A (for target domain and www)
        for h in [domain, f"www.{domain}"]:
            try:
                cname_url = f"https://dns.google/resolve?name={h}&type=CNAME"
                resp = safe_request("GET", cname_url, session=session, timeout=(1.5, 2.5))
                if resp and resp.status_code == 200:
                    for rec in resp.json().get("Answer", []):
                        c = rec.get("data", "").lower().rstrip('.')
                        cname_targets.append(c)
                        for provider, patterns in self.CLOUD_PROVIDERS.items():
                            if any(re.search(p, c) for p in patterns):
                                cloud_fingerprints.add((provider, c))
            except Exception:
                pass
                
        # Aggregate Cloud Fingerprinting
        if cloud_fingerprints:
            evidence = "\\n".join(f"Provider: {p[0]} (Indicator: {p[1]})" for p in list(cloud_fingerprints)[:5])
            findings.append(self.make_finding(
                "Cloud / Hosting Infrastructure Identified",
                "Informational",
                "Passively identified cloud or hosting provider infrastructure.",
                evidence,
                confidence="High",
                category="technology_detection",
                owasp="A00: Informational"
            ))

        # Dangling Cloud Resource Check
        # Test CNAME targets that match cloud providers
        dangling_candidates = []
        for c in cname_targets:
            if any(re.search(p, c) for patterns in self.CLOUD_PROVIDERS.values() for p in patterns):
                dangling_candidates.append(c)
                
        for cand in dangling_candidates[:3]: # Bounded to max 3
            try:
                d_url = f"http://{cand}/"
                d_resp = safe_request("GET", d_url, session=session, timeout=(1.5, 2.5))
                if d_resp:
                    body = d_resp.text
                    status = d_resp.status_code
                    for prov, sig in self.DANGLING_SIGNATURES.items():
                        if status == sig["status"] and sig["body"] in body:
                            findings.append(self.make_finding(
                                "Dangling Cloud Resource Reference Detected",
                                "Medium",
                                "Passive validation indicates that the referenced cloud resource may no longer be configured. This scanner does not attempt resource registration or takeover.",
                                f"Resource: {cand} returned {status} with signature '{sig['body']}'",
                                confidence="Medium",
                                remediation="Remove the dangling CNAME or DNS record pointing to the unprovisioned resource.",
                                category="misconfiguration",
                                owasp="A05: Security Misconfiguration"
                            ))
                            break
            except Exception:
                pass

        return findings
