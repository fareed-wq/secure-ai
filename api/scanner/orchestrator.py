import logging
import socket
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

from api.scanner.core import Config
from api.scanner.transport import is_public_hostname, get_http_session, safe_request
from api.scanner.validation import canonicalize_url
from api.scanner.metadata import check_liveness, _get_whois_data, get_metadata
from api.scanner.fallback import get_waf_fallback_payload
from api.scanner.scoring import calculate_score
from api.scanner.data.registry import REGISTERED_MODULES
from api.scanner.modules.network_checks import SubdomainProbingModule

logger = logging.getLogger(__name__)

def scan_url(url: str, probe_subdomains: bool = False) -> dict:
    url = canonicalize_url(url)
    hostname = urlparse(url).hostname
    if not hostname:
        return {"url": url, "error": "Could not parse a hostname from that URL."}
    if not is_public_hostname(hostname):
        return {"url": url, "error": "That host resolves to a private/internal address and can't be scanned."}

    if not check_liveness(hostname):
        # Target is dead or blocking us. Return an explicit failed status instead of a mock report.
        return {
            "status": "failed",
            "url": url,
            "error": "Unable to complete the security scan because the target could not be reached or the connection timed out."
        }

    metadata = {}
    all_findings = []
    import time as _time
    scan_start = _time.monotonic()

    # Get active modules from registry based on profile
    from api.scanner.data.registry import REGISTERED_MODULES
    active_modules = [m for m in REGISTERED_MODULES if getattr(m, 'enabled', True)]
    if probe_subdomains:
        active_modules.append(SubdomainProbingModule())

    # Fetch initial payload safely to pass down if needed
    with get_http_session() as session:
        req_start = _time.monotonic()
        try:
            initial_resp = safe_request("GET", url, session=session, timeout=(1.8, 2.2), verify=False, stream=True, allow_redirects=True)
            if _time.monotonic() - req_start > 3.0:
                raise requests.exceptions.ReadTimeout("Initial request took longer than 3.0 seconds, assuming WAF tarpit.")
        except requests.exceptions.Timeout as e:
            return {
                "status": "timeout",
                "url": url,
                "error": f"Connection timed out: {str(e)}"
            }
        except (requests.exceptions.RequestException, socket.timeout, Exception) as e:
            return {
                "status": "failed",
                "url": url,
                "error": f"Failed to establish connection: {str(e)}"
            }

        metadata = get_metadata(hostname, initial_resp, url)

        scan_start = _time.monotonic()
        SCAN_BUDGET_SECONDS = 25  # Global time budget for all modules

        pool = ThreadPoolExecutor(max_workers=Config.THREAD_POOL_SIZE)
        futures = {pool.submit(mod.run, url, hostname, session): mod for mod in active_modules}
        try:
            for future in as_completed(futures, timeout=SCAN_BUDGET_SECONDS):
                mod = futures[future]
                elapsed = _time.monotonic() - scan_start
                remaining = max(1, SCAN_BUDGET_SECONDS - elapsed)
                try:
                    mod_findings = future.result(timeout=min(getattr(mod, 'timeout', 8), remaining))
                    all_findings.extend(mod_findings)
                except Exception as e:
                    logger.error(f"Module {mod.module_name} failed ({elapsed:.1f}s elapsed): {e}")
                    
                    # Mask internal paths from being leaked in finding evidence
                    safe_error_msg = str(e)[:180]
                    # Mask Unix paths
                    safe_error_msg = re.sub(r'(?:/[A-Za-z0-9_.-]+){2,}/[A-Za-z0-9_.-]+\.py', '<path_masked>', safe_error_msg)
                    # Mask Windows paths
                    safe_error_msg = re.sub(r'[a-zA-Z]:\\[^\n]+\.py', '<path_masked>', safe_error_msg)
                    
                    all_findings.append({
                        "name": f"Module Timeout / Error: {mod.module_name}",
                        "severity": "Informational",
                        "category": "information_exposure",
                        "description": f"The {mod.module_name} module was skipped due to timeout or an unexpected error.",
                        "evidence": {"raw": safe_error_msg},
                        "confidence": "High",
                        "remediation": "N/A",
                        "remediation_snippets": {},
                        "owasp": "N/A",
                        "compliance": {"pci_dss": "N/A", "nist": "N/A", "iso27001": "N/A"}
                    })
        except TimeoutError:
            logger.warning(f"Scan budget of {SCAN_BUDGET_SECONDS}s exceeded; collecting partial results.")
            for future, mod in futures.items():
                if not future.done():
                    logger.warning(f"Module {mod.module_name} cancelled (budget exceeded).")
                    future.cancel()
        finally:
            # Cancel any futures still running after budget expires
            for future in futures:
                if not future.done():
                    future.cancel()
            pool.shutdown(wait=False, cancel_futures=True)

        # Phase 28 Cross-Module Intelligence Correlation
        # Correlate hostnames from various modules
        discovered_hostnames = set()
        for f in all_findings:
            if f.get("name") in ["Subdomains Discovered", "Client-Side API Endpoints Discovered", "Certificate SANs Reveal Additional Hostnames"]:
                evidence_raw = str(f.get("evidence", ""))
                # Extract potential hostnames (simple regex for basic domain structures)
                # Since evidence is often formatted like "Examples:\napi.example.com", we parse lines
                for line in evidence_raw.split("\\n"):
                    line = line.strip()
                    # Remove protocols and paths
                    line = re.sub(r'^https?://', '', line)
                    line = line.split('/')[0]
                    # Validate basic hostname shape
                    if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', line):
                        # Normalize
                        line = line.lower().rstrip('.')
                        if line.startswith('*.'):
                            line = line[2:]
                        discovered_hostnames.add(line)

        if discovered_hostnames:
            classifications = {"API": 0, "Administrative": 0, "Development/Staging": 0, "Mail": 0, "VPN": 0, "Internal": 0, "Other": 0}
            
            for h in discovered_hostnames:
                parts = h.split('.')
                prefix = parts[0]
                
                if prefix.startswith('api') or 'api' in parts:
                    classifications["API"] += 1
                elif prefix in ['admin', 'portal', 'manage']:
                    classifications["Administrative"] += 1
                elif prefix in ['dev', 'development', 'stage', 'staging', 'test', 'uat', 'qa']:
                    classifications["Development/Staging"] += 1
                elif prefix in ['mail', 'smtp', 'imap', 'pop']:
                    classifications["Mail"] += 1
                elif prefix == 'vpn':
                    classifications["VPN"] += 1
                elif prefix in ['internal', 'intranet'] or 'internal' in parts:
                    classifications["Internal"] += 1
                else:
                    classifications["Other"] += 1
                    
            evidence_lines = []
            for role, count in classifications.items():
                if count > 0:
                    evidence_lines.append(f"{role}: {count}")
                    
            if evidence_lines:
                all_findings.append({
                    "name": "Infrastructure Hostnames Classified",
                    "severity": "Informational",
                    "category": "information_exposure",
                    "description": "Correlated hostnames discovered across multiple intelligence modules and classified by operational role.",
                    "evidence": {"raw": "\\n".join(evidence_lines)},
                    "confidence": "High",
                    "remediation": "N/A",
                    "remediation_snippets": {},
                    "owasp": "A00: Informational",
                    "compliance": {"pci_dss": "N/A", "nist": "N/A", "iso27001": "N/A"}
                })

        # Phase 31 Cross-Module Intelligence Correlation
        priv_routes = set()
        priv_roles = set()
        auth_schemes = set()
        priv_sources = set()
        
        for f in all_findings:
            fname = f.get("name", "")
            ev_raw = str(f.get("evidence", ""))
            
            if fname in ["Privileged API Surface Discovered in Client-Side Code", "Privileged API Routes Publicly Documented", "Privileged / Administrative Surface Discovered"]:
                priv_sources.add(fname)
                for line in ev_raw.split("\\n"):
                    if line.strip():
                        priv_routes.add(line.strip())
                        
            elif fname == "Authorization Roles / Permissions Disclosed":
                priv_sources.add("JavaScript")
                for line in ev_raw.split("\\n"):
                    if line.strip():
                        priv_roles.add(line.strip())
                        
            elif fname == "API Authorization Scheme Disclosed":
                priv_sources.add("OpenAPI")
                if ":" in ev_raw:
                    schemes = ev_raw.split(":", 1)[1].strip()
                    for s in schemes.split(","):
                        if s.strip():
                            auth_schemes.add(s.strip())

        if priv_routes or priv_roles or auth_schemes:
            evidence_lines = []
            if priv_routes:
                evidence_lines.append(f"Privileged Routes ({len(priv_routes)}):")
                evidence_lines.extend([f"- {r}" for r in list(priv_routes)[:5]])
                if len(priv_routes) > 5:
                    evidence_lines.append(f"  ... and {len(priv_routes)-5} more")
            if priv_roles:
                evidence_lines.append(f"Roles/Permissions ({len(priv_roles)}):")
                evidence_lines.extend([f"- {r}" for r in list(priv_roles)[:5]])
            if auth_schemes:
                evidence_lines.append(f"Authorization Schemes:")
                evidence_lines.extend([f"- {s}" for s in list(auth_schemes)[:5]])
            if priv_sources:
                s_map = {
                    "Privileged API Surface Discovered in Client-Side Code": "JavaScript",
                    "Privileged API Routes Publicly Documented": "OpenAPI",
                    "Privileged / Administrative Surface Discovered": "HTML/Robots",
                    "JavaScript": "JavaScript",
                    "OpenAPI": "OpenAPI"
                }
                sources_clean = set(s_map.get(s, s) for s in priv_sources)
                evidence_lines.append(f"Sources: {', '.join(sources_clean)}")
                
            all_findings.append({
                "name": "Privileged Application Surface Correlated",
                "severity": "Informational",
                "category": "api_surface",
                "description": "Cross-module correlation consolidated findings from JavaScript, OpenAPI, robots.txt, and HTML to map the application's privileged surface.",
                "evidence": {"raw": "\\n".join(evidence_lines)},
                "confidence": "High",
                "remediation": "N/A",
                "remediation_snippets": {},
                "owasp": "A01: Broken Access Control",
                "compliance": {"pci_dss": "N/A", "nist": "N/A", "iso27001": "N/A"}
            })

    return calculate_score(url, all_findings, metadata, initial_resp)
