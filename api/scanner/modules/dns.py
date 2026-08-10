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
                        "Your domain has rules that control exactly which security companies are allowed to issue SSL certificates for your website.",
                        ", ".join(caa_issuers),
                        owasp="A02: Cryptographic Failures",
                        category="domain_email"
                    ))
                else:
                    findings.append(self.make_finding(
                        "Missing CAA Record",
                        "Low",
                        "Your domain does not have rules to limit which companies can issue security certificates for your website.",
                        "No CAA record observed for the target domain",
                        impact="A hacker could trick any certificate company into issuing a fake certificate for your site, allowing them to spy on your visitors.",
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
                        "Your domain has advanced security protections enabled to prevent hackers from tampering with your website's internet address.",
                        "DS record found",
                        owasp="A05: Security Misconfiguration",
                        category="dns_security"
                    ))
                else:
                    findings.append(self.make_finding(
                        "DNSSEC Not Enabled for Domain",
                        "Informational",
                        "Your domain does not have advanced security protections to verify its internet address.",
                        "DNSSEC validation records not observed",
                        impact="Hackers might be able to redirect your visitors to a fake copy of your website to steal their passwords or payment info.",
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
                        "Your domain is set up so that any random subdomain (like anything.yourwebsite.com) points to your server.",
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
                        "We found conflicting email rules for your domain, which makes the rules invalid.",
                        "\\n".join(spf_records[:3]),
                        impact="Hackers can easily send fake emails that look exactly like they came from you, potentially scamming your customers.",
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
                            "Your email security rules explicitly allow absolutely anyone to send emails on your behalf.",
                            data_str,
                            impact="Scammers can easily forge emails from your domain to trick your customers and damage your reputation.",
                            confidence="High",
                            remediation="Change '+all' to '~all' or '-all' in your SPF TXT record.",
                            owasp="A05: Security Misconfiguration",
                            category="domain_email"
                        ))
                    else:
                        findings.append(self.make_finding(
                            "SPF Record Configured",
                            "Passed",
                            "Your email security rules are properly set up to help prevent spoofing.",
                            data_str,
                            confidence="High",
                            owasp="A05: Security Misconfiguration",
                            category="domain_email"
                        ))
                        
                if not spf_records:
                    findings.append(self.make_finding(
                        "Missing SPF Record",
                        "Medium",
                        "Your domain lacks basic email security rules that verify who is allowed to send emails on your behalf.",
                        "TXT record absent for v=spf1.",
                        impact="Criminals can easily send fraudulent emails that look like they are coming from your company.",
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
                                "Your advanced email security policy is currently in 'monitoring mode' and will not actually block fake emails.",
                                d_str,
                                impact="While you can see who is trying to spoof your emails, those fake emails will still reach your customers' inboxes.",
                                confidence="High",
                                remediation="Consider upgrading DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject'.",
                                owasp="A05: Security Misconfiguration",
                                category="domain_email"
                            ))
                        else:
                            findings.append(self.make_finding(
                                "Strong DMARC Policy Configured",
                                "Passed",
                                "Your domain has strict rules that actively block unauthorized senders from spoofing your emails.",
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
                        f"Your domain is missing advanced email security rules (DMARC) that tell email providers what to do with fake emails.",
                        "_dmarc TXT record absent.",
                        impact="Email providers won't know how to handle forged emails pretending to be you, increasing the chance your customers get scammed.",
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
                            "Your domain ensures that all emails are securely encrypted while traveling across the internet.",
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
                        "Your domain does not explicitly force emails to be encrypted when traveling across the internet.",
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
                                f"We found digital signatures (DKIM) configured, which helps prove your emails are genuinely from you.",
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
