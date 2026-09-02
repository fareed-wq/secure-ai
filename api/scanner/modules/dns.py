import uuid
from typing import List
import requests

from api.scanner.base import ScannerModule
from api.scanner.transport import safe_request

def query_doh(name: str, type_str: str, session: requests.Session) -> dict:
    url = f"https://dns.google/resolve?name={name}&type={type_str}"
    try:
        resp = safe_request("GET", url, session=session, timeout=(1.5, 2.5))
        if resp and resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None

class DNSCAAModule(ScannerModule):
    def get_name(self) -> str:
        return "DNS CAA Security"

    def get_description(self) -> str:
        return "Checks for CAA records (Certificate Authority Authorization) and DNSSEC delegation."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        domain = hostname[4:] if hostname.startswith("www.") else hostname

        data = query_doh(domain, "CAA", session)
        if data is not None:
            status = data.get("Status")

            if status == 0 and data.get("Answer"):
                caa_issuers = [rec.get("data", "") for rec in data["Answer"]]
                findings.append(self.make_finding(
                    "CAA Records Observed",
                    "Informational",
                    "One or more CAA DNS records were observed for the domain.",
                    "\\n".join(caa_issuers)[:300] + "\\n(Note: CAA records may define certificate-issuance authorization or reporting information depending on their tags.)",
                    confidence="High",
                    owasp="Not Mapped",
                    category="domain_email"
                ))
            elif status == 0:
                findings.append(self.make_finding(
                    "CAA Record Not Observed",
                    "Informational",
                    "Your domain does not have CAA records observed.",
                    "No CAA record observed for the target domain",
                    impact="Without CAA, any CA could theoretically issue a certificate if an attacker compromised your domain validation.",
                    confidence="High",
                    remediation="Consider adding CAA records in DNS specifying authorized CAs.",
                    owasp="Not Mapped",
                    category="domain_email"
                ))

        # DNSSEC check
        ds_data = query_doh(domain, "DS", session)
        if ds_data is not None:
            ds_status = ds_data.get("Status")
            if ds_status == 0 and ds_data.get("Answer"):
                findings.append(self.make_finding(
                    "DNSSEC Delegation Observed",
                    "Informational",
                    "Your domain has DS records configured, suggesting DNSSEC may be enabled.",
                    "DS record found",
                    owasp="Not Mapped",
                    category="dns_security"
                ))
            elif ds_status == 0:
                findings.append(self.make_finding(
                    "DNSSEC Delegation Not Observed",
                    "Informational",
                    "Your domain does not have DS records published in the parent zone.",
                    "DNSSEC validation records not observed",
                    impact="Weak or missing DNS protections can reduce resilience against certain DNS-based attacks.",
                    owasp="Not Mapped",
                    category="dns_security"
                ))

        # Wildcard DNS Detection
        rand_subdomain = f"{uuid.uuid4().hex[:12]}.{domain}"
        wildcard_data = query_doh(rand_subdomain, "A", session)
        if wildcard_data is not None:
            if wildcard_data.get("Status") == 0 and wildcard_data.get("Answer"):
                findings.append(self.make_finding(
                    "Wildcard DNS Record Detected",
                    "Informational",
                    "A randomized, previously unknown hostname under the domain resolved successfully. This suggests wildcard or catch-all DNS behavior.",
                    "Randomized hostname successfully resolved",
                    confidence="Medium",
                    owasp="Not Mapped",
                    category="dns_security"
                ))

        return findings

class DNSEmailSecurityModule(ScannerModule):
    def get_name(self) -> str:
        return "DNS Email Security"

    def get_description(self) -> str:
        return "Verifies presence and configuration of SPF, DMARC, and MTA-STS."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        domain = hostname[4:] if hostname.startswith("www.") else hostname

        # 1. Query MX
        mx_observed = False
        null_mx = False
        mx_data = query_doh(domain, "MX", session)
        if mx_data is not None and mx_data.get("Status") == 0 and mx_data.get("Answer"):
            mx_observed = True
            for rec in mx_data["Answer"]:
                data_val = rec.get("data", "")
                if data_val.startswith("0 .") or data_val == ".":
                    null_mx = True
                    break

        # 2. Query root TXT / SPF
        spf_data = query_doh(domain, "TXT", session)
        spf_records = []
        all_txt_records = []
        if spf_data is not None and spf_data.get("Status") == 0:
            if spf_data.get("Answer"):
                for rec in spf_data["Answer"]:
                    data_str = rec.get("data", "")
                    if data_str.startswith('"') and data_str.endswith('"'):
                        data_str = data_str[1:-1]
                    all_txt_records.append(data_str)
                    if "v=spf1" in data_str:
                        spf_records.append(data_str)

        # 3. Query DMARC TXT
        dmarc_data = query_doh(f"_dmarc.{domain}", "TXT", session)
        dmarc_records = []
        if dmarc_data is not None and dmarc_data.get("Status") == 0:
            if dmarc_data.get("Answer"):
                for rec in dmarc_data["Answer"]:
                    data_str = rec.get("data", "")
                    if data_str.startswith('"') and data_str.endswith('"'):
                        data_str = data_str[1:-1]
                    if "v=DMARC1" in data_str:
                        dmarc_records.append(data_str)

        # 4. Determine overall mail_observed (MX, SPF, or DMARC indicates mail intent)
        mail_observed = mx_observed or (len(spf_records) > 0) or (len(dmarc_records) > 0)

        # 5. Evaluate SPF
        if spf_data is not None and spf_data.get("Status") == 0:
            if not spf_records:
                if mail_observed and not null_mx:
                    findings.append(self.make_finding(
                        "SPF Record Not Observed",
                        "Low",
                        "Your domain lacks basic email security rules that verify who is allowed to send emails on your behalf.",
                        "TXT record absent for v=spf1. MX observed: True",
                        impact="SPF-based sender authorization was not observed, increasing the risk of email spoofing.",
                        confidence="High",
                        remediation="Publish a valid SPF TXT record (e.g., 'v=spf1 include:_spf.google.com ~all').",
                        owasp="A05: Security Misconfiguration",
                        category="domain_email"
                    ))
                else:
                    findings.append(self.make_finding(
                        "SPF Record Not Observed",
                        "Informational",
                        "No clear mail-service configuration was observed, and no SPF record exists.",
                        "TXT record absent for v=spf1 after successful query.",
                        confidence="High",
                        owasp="Not Mapped",
                        category="domain_email"
                    ))
            else:
                if len(spf_records) > 1:
                    findings.append(self.make_finding(
                        "Multiple SPF Records Detected",
                        "Medium",
                        "We found conflicting email rules for your domain, which makes the rules invalid.",
                        "\n".join(spf_records[:3]),
                        impact="Without strong SPF/DMARC, the domain is more susceptible to email spoofing.",
                        confidence="High",
                        remediation="Consolidate multiple SPF records into a single valid TXT record.",
                        owasp="A05: Security Misconfiguration",
                        category="domain_email"
                    ))
                elif len(spf_records) == 1:
                    data_str = spf_records[0]
                    spf_malformed = False
                    tokens = [t.lower() for t in data_str.split()]

                    if "+all" in tokens or "all" in tokens:
                        spf_malformed = True
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

                    all_mechanisms = [t for t in tokens if t.endswith("all") and t in ("+all", "-all", "~all", "?all", "all")]
                    if len(all_mechanisms) > 1:
                        spf_malformed = True
                        findings.append(self.make_finding(
                            "Malformed SPF Record (Multiple 'all' mechanisms)",
                            "Low",
                            "Your SPF record contains multiple conflicting 'all' mechanisms, which may cause email delivery issues or security bypasses.",
                            data_str,
                            impact="Email receivers may ignore the policy, reducing its effectiveness against spoofing.",
                            owasp="A05: Security Misconfiguration",
                            category="domain_email"
                        ))

                    if tokens and tokens[0] != "v=spf1":
                        spf_malformed = True
                        findings.append(self.make_finding(
                            "Malformed SPF Record (Version Not First)",
                            "Low",
                            "Your SPF record is valid but 'v=spf1' is not the very first term, which violates the standard.",
                            data_str,
                            owasp="A05: Security Misconfiguration",
                            category="domain_email"
                        ))

                    # Passed ONLY if effectively -all or ~all and NOT malformed
                    # NO passed for ?all
                    has_strict_or_softfail = "-all" in tokens or "~all" in tokens
                    if not spf_malformed and has_strict_or_softfail:
                        findings.append(self.make_finding(
                            "SPF Record Configured",
                            "Passed",
                            "Your email security rules are properly set up to help prevent spoofing.",
                            data_str,
                            confidence="High",
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
                        elif mech == "+all": context_msgs.append("Permissive policy (+all)")
                        elif mech == "all": context_msgs.append("Permissive policy (all without modifier defaults to +all)")

                    if include_count > 0: context_msgs.append(f"Includes other domains: {include_count}")
                    if redirect_count > 0: context_msgs.append(f"Redirects to another domain: {redirect_count}")
                    if not context_msgs and not has_strict_or_softfail: context_msgs.append("Uses standard mechanisms/modifiers")

                    if context_msgs:
                        desc = "Detailed breakdown of your SPF policy configuration.\n" + "\n".join(f"- {msg}" for msg in context_msgs)
                        if include_count > 0:
                            desc += "\n(Note: SPF contains include mechanisms; recursive DNS lookup cost cannot be determined without resolving the referenced policies)."
                        findings.append(self.make_finding(
                            "SPF Policy Analysis",
                            "Informational",
                            desc,
                            data_str,
                            owasp="Not Mapped",
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
                for f_item in infrastructure_findings:
                    if "IP address" in f_item["cat"]:
                        high_conf = True
                    if f_item["cat"] not in unique_findings:
                        unique_findings[f_item["cat"]] = f_item["val"]

                evidence_lines = []
                for cat, val in unique_findings.items():
                    evidence_lines.append(f"{cat} found in TXT: {val}")

                confidence = "High" if high_conf else "Medium"

                findings.append(self.make_finding(
                    "Potential Infrastructure Information Disclosure",
                    "Medium",
                    "The domain's publicly retrievable DNS TXT data appears to disclose potentially internal infrastructure information, assisting reconnaissance.",
                    "\n".join(evidence_lines),
                    confidence=confidence,
                    remediation="Remove internal infrastructure details from public DNS records.",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))

        # 6. Evaluate DMARC
        if dmarc_data is not None and dmarc_data.get("Status") == 0:
            if not dmarc_records:
                if mail_observed and not null_mx:
                    findings.append(self.make_finding(
                        "DMARC Record Not Observed",
                        "Low",
                        "Your domain is missing advanced email security rules (DMARC) that tell email providers what to do with fake emails.",
                        "_dmarc TXT record absent.",
                        impact="No domain-published DMARC handling policy was observed.",
                        confidence="High",
                        remediation=f"Publish a DMARC TXT record at _dmarc.{domain} with a valid enforcement policy.",
                        owasp="A05: Security Misconfiguration",
                        category="domain_email"
                    ))
                else:
                    findings.append(self.make_finding(
                        "DMARC Record Not Observed",
                        "Informational",
                        "No clear mail-service configuration was observed, and no DMARC record exists.",
                        "_dmarc TXT record absent after successful query.",
                        confidence="High",
                        owasp="Not Mapped",
                        category="domain_email"
                    ))
            elif len(dmarc_records) > 1:
                findings.append(self.make_finding(
                    "Multiple DMARC Records Detected",
                    "Medium",
                    "We found multiple DMARC records for your domain, which makes the policy ambiguous and potentially invalid.",
                    "\n".join(dmarc_records[:3]),
                    impact="Receivers might ignore your DMARC policy entirely, allowing spoofed emails to be delivered.",
                    remediation="Consolidate multiple DMARC records into a single valid TXT record.",
                    owasp="A05: Security Misconfiguration",
                    category="domain_email"
                ))
            elif len(dmarc_records) == 1:
                d_str = dmarc_records[0]
                tags = [t.strip() for t in d_str.split(";")]
                tag_dict = {}
                duplicate_tags = []
                malformed = False

                for tag in tags:
                    if not tag: continue
                    parts = tag.split("=", 1)
                    if len(parts) == 2:
                        k, v = parts[0].strip().lower(), parts[1].strip()
                        if k in tag_dict:
                            duplicate_tags.append(k)
                        tag_dict[k] = v
                    else:
                        malformed = True

                p_val = tag_dict.get("p", "")
                if p_val not in ("none", "quarantine", "reject"):
                    malformed = True

                if tags and not tags[0].lower().startswith("v=dmarc1"):
                    malformed = True

                # validate pct
                pct_val = tag_dict.get("pct", "100")
                pct_int = 100
                if not pct_val.isdigit():
                    malformed = True
                else:
                    try:
                        pct_int = int(pct_val)
                        if pct_int < 0 or pct_int > 100:
                            malformed = True
                    except:
                        malformed = True

                if p_val == "none":
                    findings.append(self.make_finding(
                        "DMARC Monitoring-Only Policy",
                        "Informational",
                        "Your advanced email security policy is currently in 'monitoring mode' and will not actually block fake emails.",
                        d_str,
                        impact="While you can see who is trying to spoof your emails, those fake emails will still reach your customers' inboxes.",
                        confidence="High",
                        remediation="Consider upgrading DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject'.",
                        owasp="Not Mapped",
                        category="domain_email"
                    ))
                elif not malformed and not duplicate_tags and p_val in ("quarantine", "reject"):
                    if pct_int == 100:
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
                sp_val = tag_dict.get("sp", "")
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
                if not malformed and pct_int != 100:
                    info_msgs.append(f"Policy percentage: {pct_int}%")

                if info_msgs:
                    desc = "Detailed breakdown of your DMARC policy configuration.\n" + "\n".join(f"- {msg}" for msg in info_msgs)
                    findings.append(self.make_finding(
                        "DMARC Policy Analysis",
                        "Informational",
                        desc,
                        d_str,
                        owasp="Not Mapped",
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

                if p_val in ("quarantine", "reject") and not malformed and pct_int == 0:
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
                elif not malformed and not duplicate_tags and p_val in ("quarantine", "reject") and 0 < pct_int < 100:
                    findings.append(self.make_finding(
                        "Partial DMARC Enforcement",
                        "Informational",
                        f"Your DMARC policy enforces the quarantine/reject rule on only {pct_int}% of emails.",
                        d_str,
                        impact="Spoofed emails not falling within this percentage will still be delivered.",
                        remediation="Consider gradually increasing pct to 100.",
                        owasp="Not Mapped",
                        category="domain_email"
                    ))

        # 7. Evaluate MTA-STS
        if mx_observed and not null_mx:
            mta_data = query_doh(f"_mta-sts.{domain}", "TXT", session)
            mta_status = mta_data.get("Status") if mta_data else None

            if mta_status == 0:
                mta_found = False
                if mta_data.get("Answer"):
                    for rec in mta_data["Answer"]:
                        if "v=STSv1" in rec.get("data", ""):
                            mta_found = True
                            findings.append(self.make_finding(
                                "MTA-STS TXT Record Observed",
                                "Informational",
                                "An MTA-STS DNS TXT record was observed.",
                                rec.get("data", "") + "\n(Note: The HTTPS MTA-STS policy file and enforcement behavior were not verified.)",
                                confidence="High",
                                owasp="Not Mapped",
                                category="domain_email"
                            ))
                            break
                if not mta_found:
                    findings.append(self.make_finding(
                        "MTA-STS TXT Record Not Observed",
                        "Informational",
                        "No MTA-STS DNS TXT record was observed for this mail-receiving domain.",
                        "DNS record not found",
                        confidence="High",
                        owasp="Not Mapped",
                        category="domain_email"
                    ))

        return findings
