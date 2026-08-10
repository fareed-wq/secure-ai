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
    description = "Parses SANs, signature algorithms, and expiration."

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

                    subject = dict(x[0] for x in cert.get("subject", []))
                    cn = subject.get("commonName", "")
                    if cn.startswith("*"):
                        findings.append(self.make_finding(
                            "Wildcard Certificate in Use",
                            "Informational",
                            "Your website uses a 'wildcard' certificate that covers multiple subdomains at once.",
                            f"CN: {cn}",
                            remediation="Consider using specific SANs instead of wildcards.",
                            owasp="A02: Cryptographic Failures",
                            category="encryption_tls",
                            impact="If a hacker manages to steal this certificate, they can create fake secure pages for any of your subdomains, putting your entire brand at risk."
                        ))

                    not_after = cert.get("notAfter")
                    if not_after:
                        clean_date = WHITESPACE_REGEX.sub(' ', not_after)
                        expire_date = datetime.datetime.strptime(
                            clean_date, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=datetime.timezone.utc)
                        now = datetime.datetime.now(datetime.timezone.utc)
                        days_left = (expire_date - now).days

                        if days_left < 30:
                            findings.append(self.make_finding(
                                "Certificate Expiring Soon",
                                "Medium",
                                f"Your website's digital security certificate is about to expire in {days_left} days.",
                                not_after,
                                remediation="Renew the TLS certificate immediately.",
                                owasp="A02: Cryptographic Failures",
                                category="encryption_tls",
                                impact="If your certificate expires, web browsers will display a scary security warning to your visitors, blocking them from accessing your site and damaging your reputation."
                            ))
        except Exception as e:
            findings.append(self.make_finding(
                "SSL/TLS Connection Failure",
                "High",
                "Your website failed to establish a secure, encrypted connection.",
                str(e),
                remediation="Ensure the server supports standard TLS protocols.",
                owasp="A02: Cryptographic Failures",
                category="encryption_tls",
                impact="Visitors cannot securely connect to your website, meaning their data could be easily intercepted and web browsers may warn them away."
            ))

        # Legacy TLS Probe
        legacy_supported = False
        try:
            legacy_context = ssl.create_default_context()
            legacy_context.options &= ~ssl.OP_NO_TLSv1
            legacy_context.options &= ~ssl.OP_NO_TLSv1_1
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
                impact="These old connection methods have known flaws. Hackers could potentially break the encryption and steal sensitive data like passwords or credit card numbers from your visitors."
            ))
        else:
            findings.append(self.make_finding(
                "Legacy TLS Protocols Disabled",
                "Passed",
                "Your website correctly rejects outdated and insecure connection methods.",
                "TLS 1.2+ Only",
                owasp="A02: Cryptographic Failures",
                category="encryption_tls",
                impact="This protects your visitors by ensuring they only connect using modern, strong security standards."
            ))

        return findings
