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
                        "A .env file containing sensitive credentials or API keys is publicly accessible.",
                        env_url,
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
                    "The Git source code repository is publicly exposed, allowing source code downloading.",
                    git_url,
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
                        "A phpinfo() page is publicly exposed, revealing server configuration and PHP environment variables.",
                        phpinfo_url,
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
                                "Web server is configured to display raw directory file listings when an index page is missing.",
                                target_url,
                                impact="Allows unauthenticated users to browse and download internal media uploads, unlinked assets, and temporary server files.",
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
                    resp = safe_request("GET", target_url, session=session, timeout=(1.5, 2.5), stream=True)
                    if resp and resp.status_code == 200 and 'text/html' not in resp.headers.get('Content-Type', '').lower():
                        chunk = next(resp.iter_content(1024), b'')
                        resp.close()
                        try:
                            chunk_text = chunk.decode('utf-8', errors='ignore')
                        except Exception:
                            chunk_text = ""
                        if any(x in chunk_text for x in ['[202', '[ERROR]', '[DEBUG]', 'Stack trace:']):
                            return self.make_finding(
                                f"Exposed Application Log File ({path})",
                                "High",
                                "Publicly accessible application log file discovered at {path}.",
                                target_url,
                                impact="Log files frequently expose unhandled stack traces, database query parameters, internal file paths, user emails, and API session tokens.",
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
                    resp = safe_request("GET", target_url, session=session, timeout=(1.5, 2.5), stream=True)
                    if resp and resp.status_code == 200 and 'text/html' not in resp.headers.get('Content-Type', '').lower():
                        chunk = next(resp.iter_content(1024), b'')
                        resp.close()
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
                                f"A publicly downloadable database or source code backup dump was found at {path}.",
                                target_url,
                                impact="Grants unauthenticated attackers immediate access to the full application database, hashed user passwords, internal tables, and raw source code.",
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
                                f"A publicly accessible .env file was found at {path}.",
                                target_url,
                                impact="Grants unauthenticated attackers immediate access to the application's configuration secrets, database credentials, and API keys.",
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
                                "An administrative login panel or interface was found publicly accessible.",
                                target_url,
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
            server = self.get_header_safe(resp, "Server")
            if any(char.isdigit() for char in server) and ("/" in server or "-" in server):
                findings.append(self.make_finding(
                    "Verbose Server Banner",
                    "Low",
                    "Server header leaks exact version numbers.",
                    server,
                    remediation="Configure server to only return generic names (e.g., 'nginx').",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
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
                        "The robots.txt file discloses sensitive or internal application paths.",
                        "\\n".join(interesting_paths[:10]),
                        owasp="A05: Security Misconfiguration",
                        category="information_exposure"
                    ))
                    
                if privileged_paths:
                    findings.append(self.make_finding(
                        "Privileged / Administrative Surface Discovered",
                        "Informational",
                        "Administrative or privileged application paths were discovered via robots.txt.",
                        "\\n".join(privileged_paths[:10]),
                        confidence="High",
                        owasp="A01: Broken Access Control",
                        category="api_surface"
                    ))
                
                findings.append(self.make_finding(
                    "robots.txt Found",
                    "Informational",
                    f"Found robots.txt with {lines} lines.",
                    target,
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
            else:
                findings.append(self.make_finding(
                    "robots.txt Missing",
                    "Informational",
                    "No robots.txt found.",
                    target,
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
                    "Found XML sitemap.",
                    target,
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
            else:
                findings.append(self.make_finding(
                    "sitemap.xml Missing",
                    "Informational",
                    "No sitemap.xml found.",
                    target,
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
            content_type = self.get_header_safe(resp, "Content-Type", "").lower()
            if resp and resp.status_code == 200 and "text/plain" in content_type and "contact" in resp.text.lower() and not self.is_spa_fallback(resp, homepage_len):
                findings.append(self.make_finding(
                    "security.txt Found",
                    "Passed",
                    "Organization has published security.txt.",
                    target,
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
            else:
                findings.append(self.make_finding(
                    "security.txt Missing",
                    "Informational",
                    "No standard security.txt found.",
                    target,
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
                                "A public API documentation specification was discovered.",
                                target,
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
                                    "The API specification explicitly declares its security/authorization scheme.",
                                    f"Authorization scheme(s): {', '.join(list(schemes_found)[:5])}",
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
                                    "Sensitive or administrative API routes were discovered in the public documentation.",
                                    "\\n".join(list(privileged_routes)[:5]),
                                    confidence="High",
                                    category="api_surface",
                                    owasp="A01: Broken Access Control"
                                ))
                                
                            if unprotected_privileged:
                                local_findings.append(self.make_finding(
                                    "Potentially Unprotected Privileged API Operation",
                                    "Medium",
                                    "This is an OpenAPI documentation-level indicator and does not confirm that the live endpoint is actually unauthenticated. Privileged operations lack a documented security requirement.",
                                    "\\n".join(list(unprotected_privileged)[:5]),
                                    confidence="Medium",
                                    category="authentication",
                                    owasp="A01: Broken Access Control"
                                ))
                                
                            if api_versions:
                                local_findings.append(self.make_finding(
                                    "Versioned API Surface Discovered",
                                    "Informational",
                                    "Versioned API endpoints were identified in the specification.",
                                    f"Versions observed: {', '.join(api_versions)}",
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
                            "An interactive GraphQL developer UI is publicly accessible.",
                            target,
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
                                    "Sensitive actuator endpoint (/actuator/env) is publicly accessible, leaking configuration.",
                                    target,
                                    confidence="High",
                                    category="information_exposure",
                                    owasp="A05: Security Misconfiguration",
                                    remediation="Restrict access to actuator endpoints."
                                )
                            elif is_health or is_base:
                                return self.make_finding(
                                    "Spring Boot Actuator Endpoint Exposed",
                                    "Informational",
                                    "Spring Boot Actuator health or root endpoint is publicly accessible.",
                                    target,
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
                    "An active XML-RPC endpoint is publicly accessible.",
                    target,
                    confidence="High",
                    category="information_exposure",
                    owasp="A05: Security Misconfiguration",
                    remediation="Disable XML-RPC if it is not required by your CMS."
                ))
        except Exception as e:
            logger.debug("XmlRpcModule check failed: %s", e)
        
        return findings
