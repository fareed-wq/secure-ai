from typing import List
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
import re

from api.scanner.base import ScannerModule
from api.scanner.transport import safe_request
import logging

logger = logging.getLogger(__name__)


class ExposedFilesModule(ScannerModule):
    module_name = "ExposedFiles"
    description = "Checks for publicly exposed sensitive files (.env, .git)."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        scheme = "https" if url.startswith("https") else "http"
        base_url = f"{scheme}://{hostname}/"
        homepage_len = 0
        try:
            hp_resp = safe_request("GET", base_url, session=session, timeout=(1.5, 2.5))
            if hp_resp and hp_resp.text:
                homepage_len = len(hp_resp.text)
        except Exception as e:
            logger.debug("ExposedFilesModule head check failed: %s", e)

        try:
            env_url = f"{scheme}://{hostname}/.env"
            resp = safe_request("GET", env_url, session=session, timeout=(1.5, 2.5))
            if resp and resp.status_code == 200 and not self.is_spa_fallback(resp, homepage_len):
                env_text = resp.text.upper()
                if any(k in env_text for k in ["APP_ENV=", "DB_", "DATABASE_URL=", "SECRET", "PASSWORD", "APP_KEY", "API_KEY"]):
                    findings.append(self.make_finding(
                        "Exposed .env Configuration File",
                        "Critical",
                        "A configuration file containing sensitive passwords and secret keys is publicly visible on your website.",
                        env_url,
                        impact="Hackers can use these passwords to take full control of your website, access your database, and steal customer data.",
                        remediation="Restrict web server access to dotfiles or move .env outside the web root immediately.",
                        owasp="A05: Security Misconfiguration",
                        category="information_exposure",
                        confidence="High"
                    ))
        except Exception as e:
            logger.debug("ExposedFilesModule env fetch failed: %s", e)

        try:
            git_url = f"{scheme}://{hostname}/.git/HEAD"
            resp = safe_request("GET", git_url, session=session, timeout=(1.5, 2.5))
            if resp and resp.status_code == 200 and not self.is_spa_fallback(resp, homepage_len) and resp.text.startswith("ref: refs/"):
                findings.append(self.make_finding(
                    "Exposed .git Repository",
                    "High",
                    "A folder containing the entire blueprint and source code of your website is publicly accessible.",
                    git_url,
                    impact="Anyone can download your website's exact source code, making it easy for hackers to find hidden flaws and bypass your security.",
                    remediation="Configure the web server to block access to the /.git directory.",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure",
                    confidence="High"
                ))
        except Exception as e:
            logger.debug("ExposedFilesModule git config failed: %s", e)

        try:
            phpinfo_url = f"{scheme}://{hostname}/phpinfo.php"
            resp = safe_request("GET", phpinfo_url, session=session, timeout=(1.5, 2.5))
            if resp and resp.status_code == 200 and not self.is_spa_fallback(resp, homepage_len):
                if "<title>phpinfo()</title>" in resp.text.lower() or "zend engine" in resp.text.lower():
                    findings.append(self.make_finding(
                        "Exposed phpinfo() File",
                        "Medium",
                        "A test file revealing technical details about your web server is left public.",
                        phpinfo_url,
                        impact="Hackers can use this detailed technical information to identify outdated software and plan a highly targeted attack against your website.",
                        remediation="Remove or restrict access to the phpinfo.php file.",
                        owasp="A05: Security Misconfiguration",
                        category="information_exposure",
                        confidence="High"
                    ))
        except Exception as e:
            logger.debug("ExposedFilesModule phpinfo fetch failed: %s", e)

        # Smart Path Scoping: Skip path probes if the root endpoint is a JSON API
        is_json_api = False
        try:
            if 'application/json' in self.get_header_safe(hp_resp, 'Content-Type', '').lower():
                is_json_api = True
        except Exception as e:
            logger.debug("ExposedFilesModule ds_store fetch failed: %s", e)

        if not is_json_api:
            def check_dir_index(path):
                try:
                    target_url = urljoin(base_url, path)
                    resp = safe_request("GET", target_url, session=session, timeout=(1.5, 2.5))
                    if resp and resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', '').lower():
                        if "Index of /" in resp.text or "<title>Index of" in resp.text:
                            return self.make_finding(
                                f"Directory Indexing Enabled ({path})",
                                "Medium",
                                "Your website allows anyone to see a raw list of all the files and folders stored in this directory.",
                                target_url,
                                impact="Hackers can browse these folders like a file manager to find hidden files, backups, and sensitive documents that were not meant to be public.",
                                owasp="A05: Security Misconfiguration",
                                category="information_exposure"
                            )
                except requests.exceptions.RequestException:
                    pass
                except Exception as e:
                    logger.debug("ExposedFilesModule sensitive path fetch failed: %s", e)
                    pass
                return None

            paths_to_probe = ['/uploads/', '/images/', '/assets/', '/static/']
            with ThreadPoolExecutor(max_workers=2) as executor:
                for result in executor.map(check_dir_index, paths_to_probe):
                    if result:
                        findings.append(result)

            def check_exposed_log(path):
                try:
                    target_url = urljoin(base_url, path)
                    resp = safe_request("GET", target_url, session=session, timeout=(1.5, 2.5))
                    if resp and resp.status_code == 200 and 'text/html' not in resp.headers.get('Content-Type', '').lower():
                        try:
                            chunk_text = resp.text[:1024]
                        except Exception:
                            chunk_text = ""
                        if any(x in chunk_text for x in ['[202', '[ERROR]', '[DEBUG]', 'Stack trace:']):
                            return self.make_finding(
                                f"Exposed Application Log File ({path})",
                                "High",
                                f"A system log file recording background activity for your website is publicly readable at {path}.",
                                target_url,
                                impact="These logs often contain sensitive user information, error messages, and secret tokens that hackers can use to bypass security.",
                                owasp="A05: Security Misconfiguration",
                                category="information_exposure"
                            )
                except requests.exceptions.RequestException:
                    pass
                except Exception as e:
                    logger.debug("ExposedFilesModule source code fetch failed: %s", e)
                    pass
                return None

            log_paths = ['/laravel.log', '/error.log', '/app.log', '/debug.log', '/logs/laravel.log']
            with ThreadPoolExecutor(max_workers=2) as executor:
                for result in executor.map(check_exposed_log, log_paths):
                    if result:
                        findings.append(result)

            def check_exposed_dump(path):
                try:
                    target_url = urljoin(base_url, path)
                    resp = safe_request("GET", target_url, session=session, timeout=(1.5, 2.5))
                    if resp and resp.status_code == 200 and 'text/html' not in resp.headers.get('Content-Type', '').lower():
                        chunk = resp.content[:1024]
                        is_zip = chunk.startswith(b'PK\x03\x04') or chunk.startswith(b'\x1f\x8b')

                        try:
                            chunk_text = chunk.decode('utf-8', errors='ignore')
                        except Exception:
                            chunk_text = ""

                        is_sql = '-- MySQL dump' in chunk_text or 'CREATE TABLE' in chunk_text or 'INSERT INTO' in chunk_text

                        if is_zip or is_sql:
                            return self.make_finding(
                                f"Exposed Site / Database Backup Dump ({path})",
                                "Critical",
                                f"A complete backup of your website or database is publicly available for anyone to download at {path}.",
                                target_url,
                                impact="Hackers can instantly download all your customer data, passwords, and private files, leading to a massive data breach.",
                                owasp="A05: Security Misconfiguration",
                                category="information_exposure"
                            )
                except requests.exceptions.RequestException:
                    pass
                except Exception as e:
                    logger.debug("ExposedFilesModule php info fetch failed: %s", e)
                    pass
                return None

            dump_paths = ['/backup.zip', '/site.tar.gz', '/db.sql', '/dump.sql', '/backup.sql']
            with ThreadPoolExecutor(max_workers=2) as executor:
                for result in executor.map(check_exposed_dump, dump_paths):
                    if result:
                        findings.append(result)

            def check_env_file(path):
                try:
                    target_url = urljoin(base_url, path)
                    resp = safe_request("GET", target_url, session=session, timeout=(1.5, 2.5))
                    if resp and resp.status_code == 200:
                        body = resp.text.lower() if resp.text else ""
                        if "db_password=" in body or "app_key=" in body or "aws_access_key_id=" in body or "secret_key=" in body:
                            return self.make_finding(
                                f"Exposed Environment File ({path})",
                                "Critical",
                                f"A configuration file containing sensitive passwords and secret keys is publicly visible at {path}.",
                                target_url,
                                impact="Hackers can use these passwords to take full control of your website, access your database, and steal customer data.",
                                owasp="A05: Security Misconfiguration",
                                category="information_exposure"
                            )
                except requests.exceptions.RequestException:
                    pass
                except Exception as e:
                    logger.debug("ExposedFilesModule env file fetch failed: %s", e)
                    pass
                return None

            env_result = check_env_file('/.env')
            if env_result:
                findings.append(env_result)

            def check_admin_panel(path):
                try:
                    target_url = urljoin(base_url, path)
                    resp = safe_request("GET", target_url, session=session, timeout=(1.5, 2.5))
                    if resp and resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', '').lower():
                        if "password" in resp.text.lower() and "admin" in resp.text.lower():
                            return self.make_finding(
                                "Administrative Interface Exposed",
                                "Low",
                                "A private admin login page for managing your website is open to the public.",
                                target_url,
                                impact="Hackers can attempt to guess passwords or exploit vulnerabilities on this login page to take over your website.",
                                confidence="Medium",
                                owasp="A01: Broken Access Control",
                                category="api_surface"
                            )
                except requests.exceptions.RequestException:
                    pass
                except Exception as e:
                    logger.debug("ExposedFilesModule admin check failed: %s", e)
                return None

            admin_result = check_admin_panel('/admin')
            if admin_result:
                findings.append(admin_result)

        return findings


class InformationDisclosureModule(ScannerModule):
    module_name = "InformationDisclosure"
    description = "Checks for verbose server banners."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=(1.5, 2.5))
            if not resp:
                return findings
            server = self.get_header_safe(resp, "Server")
            if any(char.isdigit() for char in server) and ("/" in server or "-" in server):
                findings.append(self.make_finding(
                    "Verbose Server Banner",
                    "Low",
                    "Your web server publicly announces its exact software name and version.",
                    server,
                    impact="Hackers can easily look up the exact version of your server to find known security flaws and launch a targeted attack against your website.",
                    remediation="Configure server to only return generic names (e.g., 'nginx').",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))

            if resp.text:
                import re
                # Passive IP disclosure check
                private_ip_regex = re.compile(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b')
                matches = private_ip_regex.findall(resp.text[:2000000])
                if matches:
                    unique_ips = list(set([m[0] if isinstance(m, tuple) else m for m in matches]))
                    findings.append(self.make_finding(
                        "Private IP Disclosure",
                        "Low",
                        "Your website is leaking internal network addresses.",
                        ", ".join(unique_ips[:3]),
                        impact="Attackers can use these internal addresses to map out your private network and launch targeted attacks.",
                        remediation="Remove internal IP addresses from the public response.",
                        owasp="A01: Broken Access Control",
                        category="information_exposure"
                    ))

                # Passive Stack Trace check
                signatures = ["SQLSTATE[", "PostgreSQL query failed", "Django Version", "Traceback (most recent call last)", "Express error:", "java.lang.NullPointerException", "at System.Web."]
                text_lower = resp.text[:2000000].lower()
                for sig in signatures:
                    if sig.lower() in text_lower:
                        findings.append(self.make_finding(
                            "Verbose Backend Error / Stack Trace Disclosure",
                            "Low",
                            "Your website displays highly detailed technical crash reports or stack traces.",
                            sig,
                            impact="These detailed reports reveal exactly how your system is built, giving attackers a blueprint for finding weaknesses.",
                            remediation="Configure production environment to mask verbose error stack traces.",
                            owasp="A05: Security Misconfiguration",
                            category="information_exposure"
                        ))
                        break
        except Exception as e:
            logger.debug("InformationDisclosureModule head check failed: %s", e)
        return findings


class RobotsTxtModule(ScannerModule):
    module_name = "RobotsTxt"
    description = "Fetches and analyzes robots.txt."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            scheme = "https" if url.startswith("https") else "http"
            base_url = f"{scheme}://{hostname}/"
            homepage_len = 0
            hp_resp = safe_request("GET", base_url, session=session, timeout=(1.5, 2.5))
            if hp_resp and hp_resp.text:
                homepage_len = len(hp_resp.text)

            target = f"{scheme}://{hostname}/robots.txt"
            resp = safe_request("GET", target, session=session, timeout=(1.5, 2.5))
            content_type = self.get_header_safe(resp, "Content-Type", "").lower()
            if resp and resp.status_code == 200 and "text/plain" in content_type and "user-agent" in resp.text.lower() and not self.is_spa_fallback(resp, homepage_len):
                lines = len(resp.text.splitlines())

                interesting_paths = []
                privileged_paths = []
                priv_indicators = ['/admin', '/administrator', '/staff', '/management', '/control-panel', '/dashboard', '/internal', '/private', '/secure', '/backend']

                for line in resp.text.splitlines():
                    lower_line = line.lower()
                    if lower_line.startswith("disallow:") or lower_line.startswith("allow:"):
                        path = lower_line.split(":", 1)[1].strip()

                        # Existing sensitive path check
                        if any(path.startswith(x) for x in ['/internal', '/staging', '/backup', '/dev', '/.env', '/admin_dev']):
                            if path not in interesting_paths:
                                interesting_paths.append(path)

                        # PHASE 31: Privileged Surface Discovery
                        if lower_line.startswith("disallow:"):
                            if any(path.startswith(x) or path.startswith(f"*{x}") for x in priv_indicators):
                                if path not in privileged_paths:
                                    privileged_paths.append(path)

                if interesting_paths:
                    findings.append(self.make_finding(
                        "Internal Paths Disclosed in Robots.txt",
                        "Low",
                        "Your website's search engine configuration file reveals hidden internal folders.",
                        "\\n".join(interesting_paths[:10]),
                        impact="Hackers can read this file to discover secret administrative or development areas of your website that were supposed to be hidden.",
                        owasp="A05: Security Misconfiguration",
                        category="information_exposure"
                    ))

                if privileged_paths:
                    findings.append(self.make_finding(
                        "Privileged / Administrative Surface Discovered",
                        "Informational",
                        "Your website publicly lists the addresses of administrative login pages or control panels.",
                        "\\n".join(privileged_paths[:10]),
                        impact="Hackers can easily find where to launch attacks to try and guess passwords and take control of your website.",
                        confidence="High",
                        owasp="A01: Broken Access Control",
                        category="api_surface"
                    ))

                findings.append(self.make_finding(
                    "robots.txt Found",
                    "Informational",
                    "Your website provides instructions for search engines.",
                    target,
                    impact="This is normal and helps search engines know what parts of your site to index.",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
            else:
                findings.append(self.make_finding(
                    "robots.txt Missing",
                    "Informational",
                    "Your website does not provide instructions for search engines.",
                    target,
                    impact="Search engines might index parts of your website you didn't intend to be public, or they might not index your site efficiently.",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
        except Exception as e:
            logger.debug("RobotsTxtModule check failed: %s", e)
        return findings


class SitemapModule(ScannerModule):
    module_name = "SitemapXml"
    description = "Checks for sitemap.xml."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            scheme = "https" if url.startswith("https") else "http"
            base_url = f"{scheme}://{hostname}/"
            homepage_len = 0
            hp_resp = safe_request("GET", base_url, session=session, timeout=(1.5, 2.5))
            if hp_resp and hp_resp.text:
                homepage_len = len(hp_resp.text)

            target = f"{scheme}://{hostname}/sitemap.xml"
            resp = safe_request("GET", target, session=session, timeout=(1.5, 2.5))
            content_type = self.get_header_safe(resp, "Content-Type", "").lower()
            if resp and resp.status_code == 200 and ("xml" in content_type or "text" in content_type) and ("<urlset" in resp.text or "<sitemapindex" in resp.text) and not self.is_spa_fallback(resp, homepage_len):
                findings.append(self.make_finding(
                    "sitemap.xml Found",
                    "Informational",
                    "A map of your website's pages was found.",
                    target,
                    impact="This is a standard file that helps search engines discover all the public pages on your website.",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
            else:
                findings.append(self.make_finding(
                    "sitemap.xml Missing",
                    "Informational",
                    "Your website is missing a map of its pages.",
                    target,
                    impact="Search engines might have a harder time discovering and ranking all the public pages on your website.",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
        except Exception as e:
            logger.debug("SitemapModule check failed: %s", e)
        return findings


class SecurityTxtModule(ScannerModule):
    module_name = "SecurityTxt"
    description = "Checks for security.txt."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        try:
            scheme = "https" if url.startswith("https") else "http"
            base_url = f"{scheme}://{hostname}/"
            homepage_len = 0
            hp_resp = safe_request("GET", base_url, session=session, timeout=(1.5, 2.5))
            if hp_resp and hp_resp.text:
                homepage_len = len(hp_resp.text)

            target = f"{scheme}://{hostname}/.well-known/security.txt"
            resp = safe_request("GET", target, session=session, timeout=(1.5, 2.5))

            if resp and resp.status_code == 200 and not self.is_spa_fallback(resp, homepage_len):
                content_type = self.get_header_safe(resp, "Content-Type", "").lower()

                # Bounded response text to prevent excessive processing
                content = resp.text[:100000] if resp.text else ""

                if "text/plain" not in content_type:
                    findings.append(self.make_finding(
                        "security.txt Incorrect Content-Type",
                        "Informational",
                        "Your security.txt file is not served with the text/plain Content-Type as required by RFC 9116.",
                        f"Content-Type: {content_type}",
                        owasp="A05: Security Misconfiguration",
                        category="information_exposure"
                    ))

                # Parse lines
                contacts = []
                expires_lines = []
                policies = []
                languages = []

                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" not in line:
                        continue

                    key, val = line.split(":", 1)
                    key = key.strip().lower()
                    val = val.strip()

                    if key == "contact":
                        if val:
                            contacts.append(val)
                    elif key == "expires":
                        if val:
                            expires_lines.append(val)
                    elif key == "policy":
                        if val:
                            policies.append(val)
                    elif key == "preferred-languages":
                        if val:
                            languages.append(val)

                # Contact
                if not contacts:
                    findings.append(self.make_finding(
                        "security.txt Missing Contact",
                        "Low",
                        "Your security.txt file is missing the required Contact directive or it is empty.",
                        target,
                        remediation="Add at least one valid Contact directive (e.g., Contact: mailto:security@example.com).",
                        owasp="A05: Security Misconfiguration",
                        category="information_exposure"
                    ))

                # Expires
                if not expires_lines:
                    findings.append(self.make_finding(
                        "security.txt Missing Expires",
                        "Low",
                        "Your security.txt file is missing the required Expires directive.",
                        target,
                        remediation="Add an Expires directive with an RFC3339 formatted date.",
                        owasp="A05: Security Misconfiguration",
                        category="information_exposure"
                    ))
                elif len(expires_lines) > 1:
                    findings.append(self.make_finding(
                        "security.txt Multiple Expires",
                        "Low",
                        "Your security.txt file contains multiple Expires directives, which violates RFC 9116.",
                        target,
                        remediation="Ensure exactly one Expires directive exists.",
                        owasp="A05: Security Misconfiguration",
                        category="information_exposure"
                    ))
                else:
                    # Parse RFC3339 date
                    expires_str = expires_lines[0]
                    import datetime

                    clean_date = expires_str.upper().replace('Z', '+00:00')
                    try:
                        exp_date = datetime.datetime.fromisoformat(clean_date)
                        now = datetime.datetime.now(datetime.timezone.utc)
                        if exp_date.tzinfo is None:
                            exp_date = exp_date.replace(tzinfo=datetime.timezone.utc)

                        if exp_date < now:
                            findings.append(self.make_finding(
                                "Expired security.txt",
                                "Medium",
                                "Your security.txt file has expired and may contain stale reporting instructions.",
                                expires_str,
                                remediation="Review your security.txt policies and update the Expires date.",
                                owasp="A05: Security Misconfiguration",
                                category="information_exposure"
                            ))
                        elif contacts:
                            findings.append(self.make_finding(
                                "Valid security.txt",
                                "Passed",
                                "Your website publishes a standard and valid security contact file.",
                                target,
                                impact="This is an excellent practice that allows security researchers to safely report vulnerabilities.",
                                owasp="A05: Security Misconfiguration",
                                category="information_exposure"
                            ))

                    except ValueError:
                        findings.append(self.make_finding(
                            "security.txt Invalid Expires",
                            "Low",
                            f"The Expires directive is not formatted correctly as RFC3339: {expires_str}",
                            target,
                            remediation="Format the date using RFC3339 (e.g., 2024-12-31T23:59:59Z).",
                            owasp="A05: Security Misconfiguration",
                            category="information_exposure"
                        ))

                # Optional info
                if policies:
                    findings.append(self.make_finding(
                        "security.txt Policy Configured",
                        "Informational",
                        "Your security.txt file includes a vulnerability disclosure policy link.",
                        policies[0],
                        category="information_exposure",
                        owasp="A05: Security Misconfiguration"
                    ))
                if languages:
                    findings.append(self.make_finding(
                        "security.txt Preferred-Languages Configured",
                        "Informational",
                        "Your security.txt file specifies preferred languages for security reports.",
                        languages[0],
                        category="information_exposure",
                        owasp="A05: Security Misconfiguration"
                    ))
            else:
                findings.append(self.make_finding(
                    "security.txt Missing",
                    "Informational",
                    "Your website does not have a standard security contact file.",
                    target,
                    impact="Friendly security researchers may have a hard time contacting you if they find a vulnerability, leaving you at risk.",
                    remediation="Publish a security.txt file at /.well-known/security.txt.",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
        except Exception as e:
            logger.debug("SecurityTxtModule check failed: %s", e)
        return findings


class OpenApiModule(ScannerModule):
    module_name = "OpenApiDiscovery"
    description = "Checks for exposed OpenAPI/Swagger specifications."

    PRIV_PATTERN = re.compile(r'/(admin|administrator|staff|management|roles|permissions|users|accounts|config|settings|payments|billing|internal)\b', re.IGNORECASE)
    VERSION_PATTERN = re.compile(r'/(v\d+)/', re.IGNORECASE)

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        scheme = "https" if url.startswith("https") else "http"
        base_url = f"{scheme}://{hostname}"
        paths = ["/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs", "/swagger-ui.html"]

        def check_path(path):
            local_findings = []
            try:
                target = base_url + path
                resp = safe_request("GET", target, session=session, timeout=(1.5, 2.5))
                if resp and resp.status_code == 200 and "application/json" in resp.headers.get("Content-Type", "").lower():
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                            local_findings.append(self.make_finding(
                                "Public OpenAPI / Swagger Specification Exposed",
                                "Informational",
                                "Your website publicly exposes technical documentation about its inner workings and data connections.",
                                target,
                                impact="Hackers can use this documentation as a blueprint to understand exactly how your website works and find ways to attack it.",
                                confidence="High",
                                category="information_exposure",
                                owasp="A05: Security Misconfiguration"
                            ))

                            # PHASE 31: AUTHORIZATION & ACCESS CONTROL INTELLIGENCE
                            schemes_found = set()
                            components = data.get("components", {})
                            if isinstance(components, dict):
                                security_schemes = components.get("securitySchemes", {})
                            else:
                                security_schemes = {}

                            if "securityDefinitions" in data and isinstance(data["securityDefinitions"], dict):
                                security_schemes.update(data["securityDefinitions"])

                            if isinstance(security_schemes, dict):
                                for scheme_name, scheme_details in security_schemes.items():
                                    if isinstance(scheme_details, dict):
                                        scheme_type = scheme_details.get("type", "unknown")
                                        scheme_scheme = scheme_details.get("scheme", "")
                                        schemes_found.add(f"{scheme_name} ({scheme_type} {scheme_scheme})".strip())

                            if schemes_found:
                                local_findings.append(self.make_finding(
                                    "API Authorization Scheme Disclosed",
                                    "Informational",
                                    "Your website publicly reveals how it handles security logins and authentication methods.",
                                    f"Authorization scheme(s): {', '.join(list(schemes_found)[:5])}",
                                    impact="Hackers can use this information to focus their attacks on your specific security mechanisms.",
                                    confidence="High",
                                    category="authentication",
                                    owasp="A05: Security Misconfiguration"
                                ))

                            has_global_security = bool(data.get("security", []))
                            privileged_routes = set()
                            unprotected_privileged = set()
                            api_versions = set()

                            paths_dict = data.get("paths", {})
                            if isinstance(paths_dict, dict):
                                for route_path, operations in paths_dict.items():
                                    if self.VERSION_PATTERN.search(route_path):
                                        api_versions.add(self.VERSION_PATTERN.search(route_path).group(1).lower())

                                    if self.PRIV_PATTERN.search(route_path) and isinstance(operations, dict):
                                        for method, op_details in operations.items():
                                            if method.lower() not in ['get', 'post', 'put', 'patch', 'delete']:
                                                continue

                                            privileged_routes.add(f"{method.upper()} {route_path}")

                                            if isinstance(op_details, dict):
                                                local_security = op_details.get("security")
                                                if not has_global_security and (local_security is None or (isinstance(local_security, list) and len(local_security) == 0)):
                                                    unprotected_privileged.add(f"{method.upper()} {route_path}")

                            if privileged_routes:
                                local_findings.append(self.make_finding(
                                    "Privileged API Routes Publicly Documented",
                                    "Informational",
                                    "Your website publicly documents secret administrative connections and data channels.",
                                    "\\n".join(list(privileged_routes)[:5]),
                                    impact="Hackers can use these details to try to bypass security and access sensitive administrative functions.",
                                    confidence="High",
                                    category="api_surface",
                                    owasp="A01: Broken Access Control"
                                ))

                            if unprotected_privileged:
                                local_findings.append(self.make_finding(
                                    "Potentially Unprotected Privileged API Operation",
                                    "Medium",
                                    "Your website's documentation suggests that some sensitive administrative functions might not require a password.",
                                    "\\n".join(list(unprotected_privileged)[:5]),
                                    impact="If true, anyone could perform administrative actions on your website without needing to log in.",
                                    confidence="Medium",
                                    category="authentication",
                                    owasp="A01: Broken Access Control"
                                ))

                            if api_versions:
                                local_findings.append(self.make_finding(
                                    "Versioned API Surface Discovered",
                                    "Informational",
                                    "Your website publicly reveals the version numbers of its internal data connections.",
                                    f"Versions observed: {', '.join(api_versions)}",
                                    impact="Hackers can check if you are using outdated versions and target older, potentially vulnerable features of your website.",
                                    confidence="High",
                                    category="api_surface",
                                    owasp="A00: Informational"
                                ))

                            return local_findings
                    except ValueError:
                        pass
            except Exception as e:
                logger.debug("OpenApiModule check failed for %s: %s", path, e)
            return local_findings

        with ThreadPoolExecutor(max_workers=2) as executor:
            for result_list in executor.map(check_path, paths):
                if result_list:
                    findings.extend(result_list)
                    break  # Return on first finding to reduce noise
        return findings


class GraphqlIdeModule(ScannerModule):
    module_name = "GraphqlIdeDiscovery"
    description = "Checks for exposed GraphQL IDE interfaces."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        scheme = "https" if url.startswith("https") else "http"
        base_url = f"{scheme}://{hostname}"
        paths = ["/graphiql", "/playground", "/graphql/console"]

        def check_path(path):
            try:
                target = base_url + path
                resp = safe_request("GET", target, session=session, timeout=(1.5, 2.5))
                if resp and resp.status_code == 200 and "text/html" in resp.headers.get("Content-Type", "").lower():
                    lower_text = resp.text.lower()
                    if "graphiql" in lower_text or "graphql playground" in lower_text:
                        return self.make_finding(
                            "Interactive GraphQL Developer IDE Exposed",
                            "Informational",
                            "A developer tool used to test data connections is left publicly accessible on your live website.",
                            target,
                            impact="Hackers can use this interactive tool to easily explore and extract hidden data from your database.",
                            confidence="High",
                            category="information_exposure",
                            owasp="A05: Security Misconfiguration"
                        )
            except Exception as e:
                logger.debug("GraphqlIdeModule check failed for %s: %s", path, e)
            return None

        with ThreadPoolExecutor(max_workers=2) as executor:
            for result in executor.map(check_path, paths):
                if result:
                    findings.append(result)
                    break
        return findings


class ActuatorModule(ScannerModule):
    module_name = "ActuatorDiscovery"
    description = "Checks for exposed Spring Boot Actuator endpoints."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        scheme = "https" if url.startswith("https") else "http"
        base_url = f"{scheme}://{hostname}"
        paths = ["/actuator", "/actuator/health", "/actuator/env"]

        def check_path(path):
            try:
                target = base_url + path
                resp = safe_request("GET", target, session=session, timeout=(1.5, 2.5))
                if resp and resp.status_code == 200 and "json" in resp.headers.get("Content-Type", "").lower():
                    try:
                        data = resp.json()
                        if isinstance(data, dict):
                            is_health = path == "/actuator/health" and "status" in data
                            is_env = path == "/actuator/env" and ("propertySources" in data or "activeProfiles" in data)
                            is_base = path == "/actuator" and "_links" in data

                            if is_env:
                                return self.make_finding(
                                    "Sensitive Spring Boot Actuator Config Exposed",
                                    "High",
                                    "Detailed configuration settings for your website's framework are publicly accessible.",
                                    target,
                                    impact="Hackers can read these settings to uncover secret passwords, database credentials, and internal network details.",
                                    confidence="High",
                                    category="information_exposure",
                                    owasp="A05: Security Misconfiguration",
                                    remediation="Restrict access to actuator endpoints."
                                )
                            elif is_health or is_base:
                                return self.make_finding(
                                    "Spring Boot Actuator Endpoint Exposed",
                                    "Informational",
                                    "Diagnostic tools for your website's framework are publicly accessible.",
                                    target,
                                    impact="Hackers can use these tools to monitor your server's health and gather intelligence to plan an attack.",
                                    confidence="High",
                                    category="information_exposure",
                                    owasp="A05: Security Misconfiguration"
                                )
                    except ValueError:
                        pass
            except Exception as e:
                logger.debug("ActuatorModule check failed for %s: %s", path, e)
            return None

        with ThreadPoolExecutor(max_workers=2) as executor:
            for result in executor.map(check_path, paths):
                if result:
                    findings.append(result)

        # Deduplicate to keep the highest severity
        highest_severity_finding = None
        severity_order = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}
        for finding in findings:
            if highest_severity_finding is None or severity_order.get(finding["severity"], 0) > severity_order.get(highest_severity_finding["severity"], 0):
                highest_severity_finding = finding

        return [highest_severity_finding] if highest_severity_finding else []


class XmlRpcModule(ScannerModule):
    module_name = "XmlRpcDiscovery"
    description = "Checks for exposed XML-RPC endpoints."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        scheme = "https" if url.startswith("https") else "http"
        target = f"{scheme}://{hostname}/xmlrpc.php"

        try:
            resp = safe_request("GET", target, session=session, timeout=(1.5, 2.5))
            if resp and resp.status_code == 405 and "XML-RPC server accepts POST requests only" in resp.text:
                findings.append(self.make_finding(
                    "Legacy XML-RPC Endpoint Exposed",
                    "Low",
                    "An outdated remote access feature is enabled on your website.",
                    target,
                    impact="Hackers often use this feature to launch massive automated attacks to guess passwords and bring down your website.",
                    confidence="High",
                    category="information_exposure",
                    owasp="A05: Security Misconfiguration",
                    remediation="Disable XML-RPC if it is not required by your CMS."
                ))
        except Exception as e:
            logger.debug("XmlRpcModule check failed: %s", e)

        return findings
