import logging
from typing import List
import requests

from api.scanner.base import ScannerModule
from api.scanner.transport import safe_request

logger = logging.getLogger(__name__)


class DNSCAAModule(ScannerModule):
    module_name = "DNSCAA"
    description = "Probes CAA records via Google DNS-over-HTTPS."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        domain = hostname[4:] if hostname.startswith("www.") else hostname

        try:
            caa_url = f"https://dns.google/resolve?name={domain}&type=CAA"
            resp = safe_request("GET", caa_url, session=session, timeout=(1.5, 2.5))

            if resp and resp.status_code == 200:
                data = resp.json()
                if "Answer" in data and len(data["Answer"]) > 0:
                    caa_issuers = [rec.get("data", "") for rec in data["Answer"]]
                    findings.append(self.make_finding(
                        "CAA Records Configured",
                        "Passed",
                        "Certificate Authority Authorization (CAA) DNS records restrict which CAs can issue certificates.",
                        ", ".join(caa_issuers),
                        owasp="A02: Cryptographic Failures",
                        category="domain_email"
                    ))
                else:
                    findings.append(self.make_finding(
                        "Missing CAA Record",
                        "Low",
                        "No CAA DNS records found. Any valid Certificate Authority can issue SSL certificates for this domain.",
                        "No CAA record observed for the target domain",
                        confidence="High",
                        remediation="Add CAA records in DNS specifying authorized CAs (e.g., 'issue letsencrypt.org').",
                        owasp="A02: Cryptographic Failures",
                        category="domain_email"
                    ))
        except Exception as e:
            logger.error(f"DNSCAAModule failed: {e}")

        # DNSSEC Check
        try:
            dnssec_url = f"https://dns.google/resolve?name={domain}&type=DS"
            resp = safe_request("GET", dnssec_url, session=session, timeout=(1.5, 2.5))
            if resp and resp.status_code == 200:
                data = resp.json()
                if data.get("Status") == 0 and data.get("Answer"):
                    findings.append(self.make_finding(
                        "DNSSEC Security Enabled",
                        "Passed",
                        "Domain Name System Security Extensions (DNSSEC) is enabled.",
                        "DS record found",
                        owasp="A05: Security Misconfiguration",
                        category="dns_security"
                    ))
                else:
                    findings.append(self.make_finding(
                        "DNSSEC Not Enabled for Domain",
                        "Informational",
                        "Domain Name System Security Extensions (DNSSEC) records are not published for this domain.",
                        "DNSSEC validation records not observed",
                        impact="The domain is more vulnerable to DNS spoofing, cache poisoning, and BGP hijacking attacks.",
                        owasp="A05: Security Misconfiguration",
                        category="dns_security"
                    ))
        except Exception:
            pass

        # Wildcard DNS Detection (Informational)
        try:
            rand_subdomain = f"sainotexist987654321.{domain}"
            wildcard_url = f"https://dns.google/resolve?name={rand_subdomain}&type=A"
            resp = safe_request("GET", wildcard_url, session=session, timeout=(1.5, 2.5))
            if resp and resp.status_code == 200:
                data = resp.json()
                if data.get("Status") == 0 and data.get("Answer"):
                    findings.append(self.make_finding(
                        "Wildcard DNS Record Detected",
                        "Informational",
                        "Wildcard DNS records may cause arbitrary subdomains to resolve to the same infrastructure. This is an attack-surface observation and does not by itself indicate a vulnerability.",
                        "Randomized subdomain successfully resolved to an IP",
                        confidence="Medium",
                        owasp="A00: Informational",
                        category="dns_security"
                    ))
        except Exception:
            pass

        return findings


class DNSEmailSecurityModule(ScannerModule):
    module_name = "DNSEmailSecurity"
    description = "Probes SPF, DMARC, DKIM, and MX records via DNS-over-HTTPS."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        domain = hostname[4:] if hostname.startswith("www.") else hostname

        # SPF
        try:
            spf_url = f"https://dns.google/resolve?name={domain}&type=TXT"
            resp = safe_request("GET", spf_url, session=session, timeout=(1.5, 2.5))
            spf_records = []

            if resp and resp.status_code == 200:
                data = resp.json()
                for rec in data.get("Answer", []):
                    data_str = rec.get("data", "")
                    if "v=spf1" in data_str:
                        spf_records.append(data_str)
                        
                if len(spf_records) > 1:
                    findings.append(self.make_finding(
                        "Multiple SPF Records Detected",
                        "Medium",
                        "Multiple SPF records found. This breaks SPF validation and exposes the domain to spoofing.",
                        "\\n".join(spf_records[:3]),
                        confidence="High",
                        remediation="Consolidate multiple SPF records into a single valid TXT record.",
                        owasp="A05: Security Misconfiguration",
                        category="domain_email"
                    ))
                elif len(spf_records) == 1:
                    data_str = spf_records[0]
                    if "+all" in data_str:
                        findings.append(self.make_finding(
                            "Overly Permissive SPF Record",
                            "High",
                            "SPF record explicitly allows any IP address to spoof emails for this domain (+all).",
                            data_str,
                            confidence="High",
                            remediation="Change '+all' to '~all' or '-all' in your SPF TXT record.",
                            owasp="A05: Security Misconfiguration",
                            category="domain_email"
                        ))
                    else:
                        findings.append(self.make_finding(
                            "SPF Record Configured",
                            "Passed",
                            "Sender Policy Framework (SPF) record is validly configured.",
                            data_str,
                            confidence="High",
                            owasp="A05: Security Misconfiguration",
                            category="domain_email"
                        ))
                        
                if not spf_records:
                    findings.append(self.make_finding(
                        "Missing SPF Record",
                        "Medium",
                        "No SPF TXT record found. The domain is exposed to email spoofing and phishing attacks.",
                        "TXT record absent for v=spf1.",
                        confidence="High",
                        remediation="Publish a valid SPF TXT record (e.g., 'v=spf1 include:_spf.google.com ~all').",
                        owasp="A05: Security Misconfiguration",
                        category="domain_email"
                    ))
        except Exception as e:
            logger.error(f"DNSEmailSecurityModule SPF failed: {e}")

        # DMARC
        try:
            dmarc_url = f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT"
            d_resp = safe_request("GET", dmarc_url, session=session, timeout=(1.5, 2.5))
            dmarc_found = False

            if d_resp and d_resp.status_code == 200:
                d_data = d_resp.json()
                for rec in d_data.get("Answer", []):
                    d_str = rec.get("data", "")
                    if "v=DMARC1" in d_str:
                        dmarc_found = True
                        if "p=none" in d_str.lower():
                            findings.append(self.make_finding(
                                "DMARC Monitoring-Only Policy",
                                "Informational",
                                "DMARC policy is set to 'none', which monitors but does not block spoofed emails.",
                                d_str,
                                confidence="High",
                                remediation="Consider upgrading DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject'.",
                                owasp="A05: Security Misconfiguration",
                                category="domain_email"
                            ))
                        else:
                            findings.append(self.make_finding(
                                "Strong DMARC Policy Configured",
                                "Passed",
                                "DMARC record is enforced with quarantine or reject policy.",
                                d_str,
                                confidence="High",
                                owasp="A05: Security Misconfiguration",
                                category="domain_email"
                            ))
                        break

                if not dmarc_found:
                    findings.append(self.make_finding(
                        "Missing DMARC Policy",
                        "Medium",
                        f"No DMARC record found at _dmarc.{domain}. Increases domain impersonation risk.",
                        "_dmarc TXT record absent.",
                        confidence="High",
                        remediation=f"Publish a DMARC TXT record at _dmarc.{domain} with a valid enforcement policy.",
                        owasp="A05: Security Misconfiguration",
                        category="domain_email"
                    ))
        except Exception as e:
            logger.error(f"DNSEmailSecurityModule DMARC failed: {e}")

        # MTA-STS Check
        try:
            mta_url = f"https://dns.google/resolve?name=_mta-sts.{domain}&type=TXT"
            resp = safe_request("GET", mta_url, session=session, timeout=(1.5, 2.5))
            mta_found = False
            if resp and resp.status_code == 200:
                for rec in resp.json().get("Answer", []):
                    if "v=STSv1" in rec.get("data", ""):
                        mta_found = True
                        findings.append(self.make_finding(
                            "MTA-STS Mail Transport Security Configured",
                            "Passed",
                            "MTA-STS policy is configured to enforce TLS for email transport.",
                            rec.get("data", ""),
                            confidence="High",
                            owasp="A05: Security Misconfiguration",
                            category="domain_email"
                        ))
                        break
                if not mta_found:
                    findings.append(self.make_finding(
                        "Missing MTA-STS Record",
                        "Informational",
                        "No MTA-STS DNS record found.",
                        "DNS record not found",
                        confidence="High",
                        owasp="A05: Security Misconfiguration",
                        category="domain_email"
                    ))
        except Exception:
            pass

        # DKIM (Well-known selectors only, bounded)
        try:
            dkim_found = False
            selectors = ["default", "google", "selector1"]
            for selector in selectors:
                dkim_url = f"https://dns.google/resolve?name={selector}._domainkey.{domain}&type=TXT"
                resp = safe_request("GET", dkim_url, session=session, timeout=(1.0, 1.5))
                if resp and resp.status_code == 200:
                    for rec in resp.json().get("Answer", []):
                        if "v=DKIM1" in rec.get("data", ""):
                            findings.append(self.make_finding(
                                "DKIM Record Observed",
                                "Informational",
                                f"A DKIM record was successfully observed using a known selector ({selector}).",
                                rec.get("data", "")[:180],
                                confidence="High",
                                owasp="A05: Security Misconfiguration",
                                category="domain_email"
                            ))
                            dkim_found = True
                            break
                if dkim_found:
                    break
        except Exception:
            pass

        return findings
