import ssl
import socket
import datetime
import re
import requests
from typing import List

from api.scanner.base import ScannerModule
from api.scanner.socket_helper import safe_create_connection

WHITESPACE_REGEX = re.compile(r'\s+')

class EnhancedTLSModule(ScannerModule):
    module_name = "EnhancedTLS"
    description = "Parses SANs, signature algorithms, expiration, ciphers, and validation errors."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        context = ssl.create_default_context()

        try:
            with safe_create_connection((hostname, 443), timeout=2.5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()

                    findings.append(self.make_finding(
                        "Valid SSL/TLS Certificate",
                        "Passed",
                        "Your website uses a valid digital certificate to prove its identity and secure the connection.",
                        f"Version: {version}",
                        owasp="A02: Cryptographic Failures",
                        category="encryption_tls",
                        impact="This ensures visitors that they are on the genuine website and keeps their data safe from eavesdroppers."
                    ))

                    if version == "TLSv1.3":
                        findings.append(self.make_finding(
                            "Modern TLS 1.3 Supported",
                            "Informational",
                            "Your website supports TLS 1.3, the latest and most secure version of the TLS protocol.",
                            "Version: TLSv1.3",
                            owasp="Not Mapped",
                            category="encryption_tls",
                            impact="TLS 1.3 removes obsolete and insecure features from previous versions and speeds up secure connections."
                        ))

                    cipher_info = ssock.cipher()
                    if cipher_info:
                        cipher_name, tls_ver, bit_len = cipher_info[0], cipher_info[1], cipher_info[2]
                        findings.append(self.make_finding(
                            "Negotiated TLS Cipher Identified",
                            "Informational",
                            "Identifies the specific encryption method (cipher suite) negotiated between our scanner and your server.",
                            f"Protocol: {tls_ver}\\nNegotiated cipher: {cipher_name}\\nBits: {bit_len}",
                            owasp="Not Mapped",
                            category="encryption_tls"
                        ))

                        weak_keywords = ["RC4", "3DES", "DES", "NULL", "EXPORT"]
                        if any(kw in cipher_name.upper() for kw in weak_keywords):
                            findings.append(self.make_finding(
                                "Weak TLS Cipher Negotiated",
                                "Medium",
                                "The scanner successfully negotiated a known-weak or obsolete encryption method.",
                                f"Cipher: {cipher_name}",
                                impact="Weak cryptography provides insufficient protection for sensitive data in transit.",
                                remediation="Disable weak ciphers (such as RC4, 3DES, or EXPORT) in your server configuration.",
                                owasp="A02: Cryptographic Failures",
                                category="encryption_tls"
                            ))

                    subject = dict(x[0] for x in cert.get("subject", []))
                    cn = subject.get("commonName", "")

                    sans = cert.get("subjectAltName", [])
                    dns_names = [san[1] for san in sans if san[0] == "DNS"]

                    is_wildcard = cn.startswith("*") or any(name.startswith("*") for name in dns_names)
                    if is_wildcard:
                        findings.append(self.make_finding(
                            "Wildcard Certificate in Use",
                            "Informational",
                            "Your website uses a 'wildcard' certificate that covers multiple subdomains at once.",
                            f"CN: {cn}",
                            remediation="Consider using specific SANs instead of wildcards.",
                            owasp="Not Mapped",
                            category="encryption_tls",
                            impact="A compromised wildcard certificate affects all subdomains, expanding the potential impact of key material disclosure."
                        ))

                    not_after = cert.get("notAfter")
                    expire_date = None
                    if not_after:
                        try:
                            clean_date = WHITESPACE_REGEX.sub(' ', not_after)
                            expire_date = datetime.datetime.strptime(
                                clean_date, "%b %d %H:%M:%S %Y %Z"
                            ).replace(tzinfo=datetime.timezone.utc)
                            now = datetime.datetime.now(datetime.timezone.utc)
                            days_left = (expire_date - now).days

                            if days_left <= 7:
                                findings.append(self.make_finding(
                                    "Certificate Expiring Very Soon",
                                    "Medium",
                                    f"Your website's digital security certificate is about to expire in {days_left} days.",
                                    f"Expires: {not_after}",
                                    remediation="Renew the TLS certificate immediately.",
                                    owasp="A02: Cryptographic Failures",
                                    category="encryption_tls",
                                    impact="If your certificate expires, web browsers will display a scary security warning to your visitors."
                                ))
                            elif days_left <= 30:
                                findings.append(self.make_finding(
                                    "Certificate Expiring Soon",
                                    "Low",
                                    f"Your website's digital security certificate is about to expire in {days_left} days.",
                                    f"Expires: {not_after}",
                                    remediation="Renew the TLS certificate soon.",
                                    owasp="A02: Cryptographic Failures",
                                    category="encryption_tls",
                                    impact="If your certificate expires, web browsers will display a scary security warning to your visitors."
                                ))
                        except Exception:
                            pass

                    not_before = cert.get("notBefore")
                    if not_after and not_before and expire_date:
                        try:
                            clean_not_before = WHITESPACE_REGEX.sub(' ', not_before)
                            issue_date = datetime.datetime.strptime(
                                clean_not_before, "%b %d %H:%M:%S %Y %Z"
                            ).replace(tzinfo=datetime.timezone.utc)

                            lifespan_days = (expire_date - issue_date).days
                            findings.append(self.make_finding(
                                "Certificate Validity Period Identified",
                                "Informational",
                                "The lifespan of the presented certificate.",
                                f"Validity period: {lifespan_days} days (Issued: {issue_date.date()}, Expires: {expire_date.date()})",
                                owasp="Not Mapped",
                                category="encryption_tls"
                            ))
                        except Exception:
                            pass

                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    issuer_cn = issuer.get("commonName")
                    issuer_org = issuer.get("organizationName")
                    if issuer_cn or issuer_org:
                        issuer_parts = []
                        if issuer_cn:
                            issuer_parts.append(f"Common Name: {issuer_cn}")
                        if issuer_org:
                            issuer_parts.append(f"Organization: {issuer_org}")

                        findings.append(self.make_finding(
                            "Certificate Issuer Identified",
                            "Informational",
                            "Identifies the Certificate Authority (CA) that issued your digital certificate.",
                            "\\n".join(issuer_parts),
                            owasp="Not Mapped",
                            category="encryption_tls"
                        ))

                    if dns_names:
                        findings.append(self.make_finding(
                            "Certificate Subject Alternative Names (SANs)",
                            "Informational",
                            "Lists all the hostnames and subdomains covered by this single digital certificate.",
                            "\\n".join(f"- {name}" for name in dns_names),
                            owasp="Not Mapped",
                            category="encryption_tls"
                        ))

        except ssl.SSLCertVerificationError as e:
            err_reason = e.verify_message if hasattr(e, 'verify_message') else str(e)
            err_code = e.verify_code if hasattr(e, 'verify_code') else "Unknown"

            finding_name = "Certificate Validation Failed"
            err_lower = err_reason.lower()
            if "expired" in err_lower:
                finding_name = "Expired Certificate"
            elif "hostname" in err_lower or "match" in err_lower:
                finding_name = "Hostname Mismatch"
            elif "self signed" in err_lower or "unable to get local issuer" in err_lower:
                finding_name = "Self-Signed or Untrusted Certificate"

            evidence_str = f"Hostname: {hostname}\\nReason: {err_reason}\\nCode: {err_code}"

            findings.append(self.make_finding(
                finding_name,
                "Medium",
                "The digital certificate presented by the scanned hostname failed validation.",
                evidence_str,
                remediation="Ensure the server is presenting a valid, trusted certificate matching the requested hostname.",
                owasp="A02: Cryptographic Failures",
                category="encryption_tls"
            ))
        except Exception:
            pass

        # Legacy TLS Probe
        legacy_supported = False
        try:
            legacy_context = ssl.create_default_context()
            legacy_context.options &= ~ssl.OP_NO_TLSv1
            legacy_context.options &= ~ssl.OP_NO_TLSv1_1
            legacy_context.minimum_version = ssl.TLSVersion.TLSv1
            legacy_context.maximum_version = ssl.TLSVersion.TLSv1_1

            with safe_create_connection((hostname, 443), timeout=2.5) as sock:
                with legacy_context.wrap_socket(sock, server_hostname=hostname):
                    legacy_supported = True
        except Exception:
            pass

        if legacy_supported:
            findings.append(self.make_finding(
                "Deprecated TLS 1.0/1.1 Supported",
                "Medium",
                "Your website allows connections using outdated security protocols (TLS 1.0 or 1.1).",
                "Server accepted connection via TLS 1.0/1.1",
                remediation="Disable TLS 1.0 and TLS 1.1 on the server.",
                owasp="A05: Security Misconfiguration",
                category="encryption_tls",
                impact="Legacy TLS protocols have known cryptographic weaknesses and should be disabled to ensure secure transit."
            ))

        return findings
