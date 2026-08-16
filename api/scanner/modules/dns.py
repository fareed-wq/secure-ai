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
        network_failure = False

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
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
            network_failure = True
        except Exception as e:
            logger.error(f"DNSCAAModule failed: {e}")
            findings.append(self.make_finding(
                "CAA Record Verification Inconclusive",
                "Inconclusive",
                "We could not verify your domain's CAA records due to a network timeout with the DNS resolver.",
                "DNS resolution timed out or failed.",
                owasp="A00: Informational",
                category="domain_email"
            ))

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
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
            network_failure = True
        except Exception as e:
            findings.append(self.make_finding(
                "DNSSEC Verification Inconclusive",
                "Inconclusive",
                "We could not verify your domain's DNSSEC status due to a network timeout with the DNS resolver.",
                "DNS resolution timed out or failed.",
                owasp="A00: Informational",
                category="dns_security"
            ))

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
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
            pass
        except Exception:
            pass

        if network_failure:
            findings.append(self.make_finding(
                "DNS Security Verification Inconclusive",
                "Inconclusive",
                "We could not verify your domain's DNS-based security records due to a network timeout with the DNS resolver.",
                "DNS resolution timed out or failed.",
                owasp="A00: Informational",
                category="dns_security"
            ))

        return findings


class DNSEmailSecurityModule(ScannerModule):
    module_name = "DNSEmailSecurity"
    description = "Probes SPF, DMARC, DKIM, and MX records via DNS-over-HTTPS."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        domain = hostname[4:] if hostname.startswith("www.") else hostname
        network_failure = False

        # SPF
        try:
            spf_url = f"https://dns.google/resolve?name={domain}&type=TXT"
            resp = safe_request("GET", spf_url, session=session, timeout=(1.5, 2.5))
            spf_records = []
            all_txt_records = []

            if resp and resp.status_code == 200:
                data = resp.json()
                for rec in data.get("Answer", []):
                    data_str = rec.get("data", "")
                    # Normalize data_str by stripping leading/trailing literal quotes sometimes returned by resolvers
                    if data_str.startswith('"') and data_str.endswith('"'):
                        data_str = data_str[1:-1]
                    all_txt_records.append(data_str)
                    
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

                    tokens = [t.lower() for t in data_str.split()]
                    all_mechanisms = [t for t in tokens if t.endswith("all") and t in ("+all", "-all", "~all", "?all", "all")]
                    if len(all_mechanisms) > 1:
                        findings.append(self.make_finding(
                            "Malformed SPF Record (Multiple 'all' mechanisms)",
                            "Low",
                            "Your SPF record contains multiple conflicting 'all' mechanisms, which may cause email delivery issues or security bypasses.",
                            data_str,
                            impact="Email receivers may ignore the policy, leaving the domain vulnerable to spoofing.",
                            owasp="A05: Security Misconfiguration",
                            category="domain_email"
                        ))

                    if tokens and tokens[0] != "v=spf1":
                        findings.append(self.make_finding(
                            "Malformed SPF Record (Version Not First)",
                            "Low",
                            "Your SPF record is valid but 'v=spf1' is not the very first term, which violates the standard.",
                            data_str,
                            owasp="A05: Security Misconfiguration",
                            category="domain_email"
                        ))

                    include_count = sum(1 for t in tokens if t.startswith("include:"))
                    redirect_count = sum(1 for t in tokens if t.startswith("redirect="))

                    context_msgs = []
                    if len(all_mechanisms) == 1:
                        mech = all_mechanisms[0]
                        if mech == "-all": context_msgs.append("Strict fail policy (-all)")
                        elif mech == "~all": context_msgs.append("Softfail policy (~all)")
                        elif mech == "?all": context_msgs.append("Neutral policy (?all)")

                    if include_count > 0:
                        context_msgs.append(f"Contains {include_count} include mechanism(s)")
                    if redirect_count > 0:
                        context_msgs.append("Contains a redirect modifier")

                    other_mechs = [t for t in tokens if t in ("a", "mx", "ptr", "exists", "exp") or t.startswith(("a:", "mx:", "ip4:", "ip6:", "exists:", "ptr:", "exp="))]
                    if other_mechs:
                        context_msgs.append(f"Uses standard mechanisms/modifiers: {len(other_mechs)}")

                    if "+all" not in data_str:
                        desc = "Your email security rules are properly set up to help prevent spoofing."
                        findings.append(self.make_finding(
                            "SPF Record Configured",
                            "Passed",
                            desc,
                            data_str,
                            confidence="High",
                            owasp="A05: Security Misconfiguration",
                            category="domain_email"
                        ))

                    if context_msgs:
                        desc = "Detailed breakdown of your SPF policy configuration.\\n" + "\\n".join(f"- {msg}" for msg in context_msgs)
                        if include_count > 0:
                            desc += "\\n(Note: SPF contains include mechanisms; recursive DNS lookup cost cannot be determined without resolving the referenced policies)."

                        findings.append(self.make_finding(
                            "SPF Policy Analysis",
                            "Informational",
                            desc,
                            data_str,
                            owasp="A05: Security Misconfiguration",
                            category="domain_email"
                        ))

                # Passive Cloud/Infrastructure TXT Record Analysis
                infrastructure_findings = []
                if all_txt_records:
                    import ipaddress
                    import re
                    
                    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
                    internal_host_pattern = re.compile(r'\b[a-z0-9-]+\.(?:internal|corp|local|lan)(?:\.[a-z0-9-]+)*\b')
                    
                    for txt in all_txt_records:
                        txt_lower = txt.lower()
                        
                        # Structured classification to ignore common verification and protocol records
                        if txt_lower.startswith("v=spf1") or txt_lower.startswith("v=dmarc1") or txt_lower.startswith("v=dkim1"):
                            continue
                            
                        # Verification tokens typically match something-verification=abc or MS=ms123
                        if re.match(r'^[a-z0-9-]*verif(?:ication|y)[a-z0-9-]*\s*=', txt_lower) or txt_lower.startswith("google-site-verification="):
                            continue
                            
                        if re.match(r'^ms=ms\d+', txt_lower) or txt_lower.startswith("apple-domain-verification="):
                            continue
                            
                        val_str = txt.strip()
                        if len(val_str) > 100:
                            val_str = val_str[:97] + "..."
                            
                        # IP address matching
                        ips = ip_pattern.findall(txt)
                        for ip_str in ips:
                            try:
                                ip = ipaddress.ip_address(ip_str)
                                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
                                    infrastructure_findings.append({
                                        "cat": f"Private IP address ({ip_str})",
                                        "val": val_str
                                    })
                            except ValueError:
                                pass
                                
                        # Internal hostname matching
                        hosts = internal_host_pattern.findall(txt_lower)
                        if hosts:
                            infrastructure_findings.append({
                                "cat": f"Internal hostname ({hosts[0]})",
                                "val": val_str
                            })
                            
                if infrastructure_findings:
                    unique_findings = {}
                    high_conf = False
                    for f in infrastructure_findings:
                        if "IP address" in f["cat"]:
                            high_conf = True
                        if f["cat"] not in unique_findings:
                            unique_findings[f["cat"]] = f["val"]
                            
                    evidence_lines = []
                    for cat, val in unique_findings.items():
                        evidence_lines.append(f"{cat} found in TXT: {val}")
                        
                    confidence = "High" if high_conf else "Medium"
                        
                    findings.append(self.make_finding(
                        "Potential Infrastructure Information Disclosure",
                        "Medium",
                        "The domain's publicly retrievable DNS TXT data appears to disclose potentially internal infrastructure information. This may provide useful reconnaissance information to an attacker.",
                        "\n".join(evidence_lines),
                        confidence=confidence,
                        remediation="Remove internal infrastructure details from public DNS records.",
                        owasp="A05: Security Misconfiguration",
                        category="information_exposure"
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
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
            network_failure = True
        except Exception as e:
            logger.error(f"DNSEmailSecurityModule SPF failed: {e}")
            findings.append(self.make_finding(
                "SPF Record Verification Inconclusive",
                "Inconclusive",
                "We could not verify your domain's SPF records due to a network timeout with the DNS resolver.",
                "DNS resolution timed out or failed.",
                owasp="A00: Informational",
                category="domain_email"
            ))

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

                        tags = [t.strip() for t in d_str.strip().strip(';').split(';') if t.strip()]
                        tag_dict = {}
                        duplicate_tags = []
                        malformed = False

                        for tag in tags:
                            if '=' not in tag:
                                malformed = True
                                continue
                            k, v = tag.split('=', 1)
                            k = k.strip().lower()
                            v = v.strip()
                            if k in tag_dict:
                                duplicate_tags.append(k)
                            tag_dict[k] = v

                        if tags and not tags[0].strip().startswith("v=DMARC1"):
                            malformed = True

                        p_val = tag_dict.get("p", "").lower()
                        pct_val = tag_dict.get("pct", "100")
                        sp_val = tag_dict.get("sp", "")

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

                        info_msgs = []
                        if p_val in ("quarantine", "reject"):
                            info_msgs.append(f"Enforcement policy: {p_val}")
                        elif p_val == "none":
                            info_msgs.append("Enforcement policy: none")
                        if sp_val:
                            info_msgs.append(f"Subdomain policy: {sp_val}")
                        if "rua" in tag_dict:
                            info_msgs.append("Aggregate reporting (rua) enabled")
                        if "ruf" in tag_dict:
                            info_msgs.append("Forensic reporting (ruf) enabled")
                        if "adkim" in tag_dict:
                            info_msgs.append(f"DKIM alignment: {tag_dict['adkim']}")
                        if "aspf" in tag_dict:
                            info_msgs.append(f"SPF alignment: {tag_dict['aspf']}")
                        if pct_val != "100":
                            info_msgs.append(f"Policy percentage: {pct_val}%")

                        if info_msgs:
                            desc = "Detailed breakdown of your DMARC policy configuration.\\n" + "\\n".join(f"- {msg}" for msg in info_msgs)
                            findings.append(self.make_finding(
                                "DMARC Policy Analysis",
                                "Informational",
                                desc,
                                d_str,
                                owasp="A05: Security Misconfiguration",
                                category="domain_email"
                            ))

                        if duplicate_tags:
                            findings.append(self.make_finding(
                                "Malformed DMARC Record (Duplicate Tags)",
                                "Low",
                                f"Your DMARC record contains duplicate tags ({', '.join(duplicate_tags)}), which may cause email receivers to ignore the policy.",
                                d_str,
                                owasp="A05: Security Misconfiguration",
                                category="domain_email"
                            ))
                        elif malformed:
                            findings.append(self.make_finding(
                                "Malformed DMARC Record",
                                "Low",
                                "Your DMARC record contains invalid syntax or the 'v=DMARC1' tag is not the first tag.",
                                d_str,
                                owasp="A05: Security Misconfiguration",
                                category="domain_email"
                            ))

                        if p_val in ("quarantine", "reject") and pct_val == "0":
                            findings.append(self.make_finding(
                                "DMARC Enforcement Disabled by pct=0",
                                "Low",
                                "Your DMARC policy is set to block spoofed emails, but 'pct=0' effectively turns off the enforcement for 100% of emails.",
                                d_str,
                                impact="Spoofed emails will still be delivered despite the quarantine/reject policy.",
                                remediation="Remove 'pct=0' or increase the percentage to gradually enforce the policy.",
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
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
            network_failure = True
        except Exception as e:
            logger.error(f"DNSEmailSecurityModule DMARC failed: {e}")
            findings.append(self.make_finding(
                "DMARC Policy Verification Inconclusive",
                "Inconclusive",
                "We could not verify your domain's DMARC policy due to a network timeout with the DNS resolver.",
                "DNS resolution timed out or failed.",
                owasp="A00: Informational",
                category="domain_email"
            ))

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
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
            pass
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
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
            pass
        except Exception:
            pass

        if network_failure:
            findings.append(self.make_finding(
                "Email Security DNS Verification Inconclusive",
                "Inconclusive",
                "We could not verify your domain's email security records (like SPF or DMARC) due to a network timeout with the DNS resolver.",
                "DNS resolution timed out or failed.",
                owasp="A00: Informational",
                category="domain_email"
            ))

        return findings
