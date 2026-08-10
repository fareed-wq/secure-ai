import logging
import re
import requests
from urllib.parse import urljoin
from html.parser import HTMLParser

from api.scanner.base import ScannerModule
from api.scanner.transport import safe_request
from api.scanner.core import Config

logger = logging.getLogger(__name__)


class SimpleHTMLResourceParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.insecure_resources = []
        self.insecure_forms = []

    def handle_starttag(self, tag, attrs):
        attr_dict = {k.lower(): v for k, v in attrs if k and v}
        
        # Check subresource URLs
        target_attr = None
        if tag in ["script", "img", "iframe", "embed", "audio", "video", "source"]:
            target_attr = attr_dict.get("src")
        elif tag == "link" and "stylesheet" in attr_dict.get("rel", "").lower():
            target_attr = attr_dict.get("href")

        if target_attr and target_attr.strip().lower().startswith("http://"):
            self.insecure_resources.append((tag, target_attr.strip()))

        # Check HTML Form submissions
        if tag == "form":
            action = attr_dict.get("action", "").strip()
            if action.lower().startswith("http://"):
                self.insecure_forms.append(action)


class MixedContentModule(ScannerModule):
    module_name = "MixedContent"
    description = "Checks for active/passive mixed content and insecure HTTP forms on HTTPS pages."

    def run(self, url: str, hostname: str, session: requests.Session) -> list[dict]:
        findings = []
        try:
            hp_resp = safe_request("HEAD", url, session=session, timeout=(1.5, 2.5))
            if hp_resp:
                ctype = hp_resp.headers.get("Content-Type", "")
                if "application/json" in ctype or hostname.startswith("api."):
                    return findings
        except Exception as e:
            logger.debug("MixedContentModule HEAD request failed: %s", e)

        if not url.startswith("https"):
            return findings

        try:
            resp = safe_request("GET", url, session=session, timeout=(1.5, 2.5), stream=True)
            if not resp:
                return findings

            parser = SimpleHTMLResourceParser()
            bytes_read = 0
            for chunk in resp.iter_content(chunk_size=16384):
                if chunk:
                    parser.feed(chunk.decode('utf-8', errors='ignore'))
                    bytes_read += len(chunk)
                    if bytes_read >= 2000000:  # 2MB limit
                        break

            if parser.insecure_resources:
                sample_count = len(parser.insecure_resources)
                samples = ", ".join([f"<{tag} src='{src}'>" for tag, src in parser.insecure_resources[:3]])
                findings.append(self.make_finding(
                    "Mixed Content Detected",
                    "Medium",
                    f"Your secure webpage is loading {sample_count} file(s) over an insecure connection.",
                    f"Examples: {samples}",
                    impact="Hackers can intercept these insecure files to steal sensitive user data or secretly alter the appearance and behavior of your website.",
                    remediation="Update all resource links (scripts, styles, images) to use relative paths or HTTPS URLs.",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))

            if parser.insecure_forms:
                findings.append(self.make_finding(
                    "Insecure Form Action (HTTP)",
                    "High",
                    "A form on your secure website is sending user information over an unencrypted connection.",
                    f"Form action: {', '.join(parser.insecure_forms[:2])}",
                    impact="Any information submitted through this form, such as passwords or personal details, can be easily intercepted and read by hackers.",
                    remediation="Ensure all form 'action' attributes use relative paths or explicit 'https://' URLs.",
                    owasp="A02: Cryptographic Failures",
                    category="encryption_tls"
                ))

            if not parser.insecure_resources and not parser.insecure_forms:
                findings.append(self.make_finding(
                    "No Mixed Content Detected",
                    "Passed",
                    "All parts of your website are safely using secure connections.",
                    "Clean HTML subresources",
                    impact="Your visitors are protected from eavesdropping and tampering when loading resources and submitting forms on your page.",
                    owasp="A05: Security Misconfiguration",
                    category="encryption_tls"
                ))

        except Exception as e:
            logger.error(f"MixedContentModule error: {e}")

        return findings


class ScriptTagParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.script_srcs = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            attr_dict = {k.lower(): v for k, v in attrs if k and v}
            src = attr_dict.get("src")
            if src:
                self.script_srcs.append(src.strip())


