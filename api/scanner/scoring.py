from typing import Optional
import requests
from api.scanner.core import Config
from api.scanner.data.registry import DOMAIN_MAP

def calculate_score(url: str, all_findings: list, metadata: dict, initial_resp: Optional[requests.Response], scan_incomplete: bool = False, completed_modules: int = -1) -> dict:
    # Auto-assign security domains to findings based on their source module
    for f in all_findings:
        if not f.get("domain"):
            f["domain"] = DOMAIN_MAP.get(f.get("module", ""), "browser_defense")

    if metadata.get("ipv6_supported"):
        all_findings.append({
            "name": "IPv6 Dual-Stack Supported",
            "severity": "Passed",
            "category": "encryption_tls",
            "description": "The server supports IPv6 connectivity.",
            "evidence": "IPv6 Address Reachable",
            "confidence": "High",
            "remediation": "N/A",
            "remediation_snippets": {},
            "owasp": "A05: Security Misconfiguration",
            "compliance": {"pci_dss": "N/A", "nist": "N/A", "iso27001": "N/A"},
            "module": "Network",
            "impact": "N/A",
            "cvss": None
        })

    if metadata.get("http2_supported") or metadata.get("http3_supported"):
        all_findings.append({
            "name": "Modern Protocol Supported (HTTP/2 or HTTP/3)",
            "severity": "Passed",
            "category": "encryption_tls",
            "description": "The server uses modern, performant HTTP protocols.",
            "evidence": "HTTP/2 or HTTP/3 detected",
            "confidence": "High",
            "remediation": "N/A",
            "remediation_snippets": {},
            "owasp": "A05: Security Misconfiguration",
            "compliance": {"pci_dss": "N/A", "nist": "N/A", "iso27001": "N/A"},
            "module": "Network",
            "impact": "N/A",
            "cvss": None
        })

    # --- SCORING & CATEGORY ENGINE ---
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Passed": 0}
    penalties = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    max_penalties = {"Critical": 100, "High": 30, "Medium": 20, "Low": 10, "Informational": 0}

    category_penalties = {
        "encryption_tls": 0,
        "http_headers": 0,
        "domain_email": 0,
        "session_cookies": 0,
        "information_exposure": 0
    }

    owasp_categories = set()
    failed_pci, passed_pci = set(), set()
    failed_nist, passed_nist = set(), set()
    failed_iso, passed_iso = set(), set()

    high_critical_failed_pci = set()
    high_critical_failed_nist = set()
    high_critical_failed_iso = set()

    cat_weights = {"Critical": 25, "High": 15, "Medium": 10, "Low": 5, "Informational": 0, "Passed": 0}

    # Deduplication tracking for scoring
    scored_identities = set()
    
    # Sort findings by severity weight descending so we always process highest severity duplicates first
    sorted_findings = sorted(all_findings, key=lambda f: abs(Config.SEVERITY_WEIGHTS.get(f.get("severity", "Informational"), 0)), reverse=True)

    for f in sorted_findings:
        sev = f.get("severity", "Informational")
        cat = f.get("category", "information_exposure")
        name = f.get("name", "")

        # Stable identity mapping to prevent duplicate penalties
        identity = name
        if "TLS" in name or "Cipher" in name or "Handshake" in name:
            identity = "TLS_Configuration_Issue"
        elif "Security-Policy" in name or "COOP" in name or "COEP" in name or "CORP" in name:
            identity = "Security_Headers_Issue"

        is_duplicate = False
        if sev not in ["Passed", "Informational"]:
            if identity in scored_identities:
                is_duplicate = True
            else:
                scored_identities.add(identity)

        if sev in severity_counts:
            severity_counts[sev] += 1

        if not is_duplicate:
            weight = abs(Config.SEVERITY_WEIGHTS.get(sev, 0))
            if sev in penalties:
                penalties[sev] = min(penalties[sev] + weight, max_penalties[sev])

            # Category sub-scores deduction
            if cat in category_penalties:
                category_penalties[cat] += cat_weights.get(sev, 0)

        owasp = f.get("owasp")
        if owasp and owasp != "N/A":
            owasp_categories.add(owasp)

        comp = f.get("compliance", {})
        p_c = comp.get("pci_dss")
        n_c = comp.get("nist")
        i_c = comp.get("iso27001")

        if sev in ["Critical", "High", "Medium", "Low"]:
            if p_c and p_c != "N/A":
                failed_pci.add(p_c)
                if not is_duplicate and sev in ["Critical", "High"]:
                    high_critical_failed_pci.add(p_c)
            if n_c and n_c != "N/A":
                failed_nist.add(n_c)
                if not is_duplicate and sev in ["Critical", "High"]:
                    high_critical_failed_nist.add(n_c)
            if i_c and i_c != "N/A":
                failed_iso.add(i_c)
                if not is_duplicate and sev in ["Critical", "High"]:
                    high_critical_failed_iso.add(i_c)
        elif sev == "Passed":
            if p_c and p_c != "N/A":
                passed_pci.add(p_c)
            if n_c and n_c != "N/A":
                passed_nist.add(n_c)
            if i_c and i_c != "N/A":
                passed_iso.add(i_c)

    # Process severity counts for ALL findings (to preserve original UI counts)
    # The sorted loop mutated severity_counts, but we want all findings to be counted, which it does.
    # We should recount severity_counts using original all_findings just in case, but sorted_findings has same elements.
    pass

    def process_compliance(failed_set: set, passed_set: set):
        # 1. Deduplicate failed
        failed_dedup = {}
        for c in failed_set:
            code = c.split(" ")[0]
            if code not in failed_dedup:
                failed_dedup[code] = c

        # 2. Deduplicate passed, excluding ANY code that is in failed_dedup
        passed_dedup = {}
        for c in passed_set:
            code = c.split(" ")[0]
            if code not in failed_dedup and code not in passed_dedup:
                passed_dedup[code] = c

        return sorted(list(failed_dedup.values())), sorted(list(passed_dedup.values()))

    failed_pci_list, passed_pci_list = process_compliance(failed_pci, passed_pci)
    failed_nist_list, passed_nist_list = process_compliance(failed_nist, passed_nist)
    failed_iso_list, passed_iso_list = process_compliance(failed_iso, passed_iso)

    def get_status(failed_high_crit: set, passed_list: list) -> str:
        if len(failed_high_crit) == 0 and len(passed_list) >= 2:
            return "Compliant"
        return "Action Required"

    score = max(0, 100 - sum(penalties.values()))

    # Calculate Radar Sub-scores out of 100
    category_scores = {
        cat: max(0, 100 - pen) for cat, pen in category_penalties.items()
    }

    # Compute target surface summary
    server_hdr = metadata.get("server_header", "")
    waf_cdn = metadata.get("waf_cdn_detection", "Direct Origin")
    target_surface = {
        "waf_server": waf_cdn or "Direct Origin",
        "waf_status": metadata.get("http_status", "Unknown"),
        "performance": metadata.get("performance_rating", "Unknown Latency")
    }

    # 1. Frontend Stack
    frontend_stack = "Standard Web Stack"
    frontend_subtext = "HTML5 / JavaScript Application"
    if initial_resp:
        body = initial_resp.text.lower() if hasattr(initial_resp, 'text') and initial_resp.text else ""
        headers = initial_resp.headers
        cookies = str(initial_resp.cookies).lower() if hasattr(initial_resp, 'cookies') else ""
        
        techs = []
        x_powered = headers.get("X-Powered-By", "").lower()
        if "next" in x_powered or "_next/static" in body:
            techs.append("Next.js App")
        elif "react" in body or "data-reactroot" in body or "react-dom" in body:
            techs.append("React SPA")
        elif "wp-content" in body or "wordpress" in body:
            techs.append("WordPress CMS")
        elif "laravel_session" in cookies or "laravel" in x_powered:
            techs.append("Laravel / PHP")
        elif "nuxt" in body or "_nuxt" in body:
            techs.append("Nuxt.js Vue App")
        
        subtechs = []
        if "tailwindcss" in body or "tailwind" in body:
            subtechs.append("Tailwind CSS")
        if "express" in x_powered:
            subtechs.append("Express.js Node")
        if "php" in x_powered:
            subtechs.append("PHP Backend")
            
        if techs:
            frontend_stack = techs[0]
            if subtechs:
                frontend_subtext = " • ".join(subtechs)
            else:
                frontend_subtext = "Verified Modern Stack"

    target_surface["frontend_stack"] = frontend_stack
    target_surface["frontend_subtext"] = frontend_subtext
    target_surface["frontend_pill"] = "VERIFIED STACK"

    # 2. API Surface — extract precise endpoint path from evidence
    api_surface = "Unknown" if scan_incomplete else "No Public Spec Exposed"
    api_subtext = "Not Assessed" if scan_incomplete else "GraphQL / OpenAPI Clean"
    api_pill = "NO DATA" if scan_incomplete else "CLEAN SURFACE"
    
    for f in all_findings:
        fname = f.get("name", "")
        fsev = f.get("severity", "")
        fevidence = str(f.get("evidence", ""))
        
        if fsev == "Passed":
            continue

        if fname == "Interactive GraphQL Developer IDE Exposed" or fname == "GraphQL Introspection Query Enabled":
            if api_surface == "No Public Spec Exposed":
                api_surface = "API Surface Detected"
                api_pill = "API DETECTED"
                api_subtext = "GraphQL Playground (/graphql)" if "IDE" in fname else "GraphQL Introspection"
            # Do not break in case a confirmed spec is found later
        
        if fname == "Public OpenAPI / Swagger Specification Exposed":
            api_surface = "Public API Spec Exposed"
            api_pill = "EXPOSED API"
            # Extract specific path from evidence
            if "/swagger.json" in fevidence or "swagger" in fevidence.lower():
                api_subtext = "OpenAPI Spec (/swagger.json)"
            elif "/openapi.json" in fevidence:
                api_subtext = "OpenAPI Spec (/openapi.json)"
            elif "Public API Specification at" in fevidence:
                path_match = fevidence.split("Public API Specification at")[-1].strip().rstrip("'\"}")
                api_subtext = f"API Spec ({path_match})" if path_match else "Exposed Specification Found"
            else:
                api_subtext = fname
            break

        if ("API" in fname or "Swagger" in fname or "OpenAPI" in fname) and "Module" not in fname:
            if api_surface == "No Public Spec Exposed":
                api_surface = "API Surface Detected"
                api_pill = "API DETECTED"
                if "/wp-json" in fevidence or "WordPress" in fname:
                    api_subtext = "WordPress REST API (/wp-json/)"
                elif "Exposed Admin" in fevidence:
                    api_subtext = "Exposed Admin Portal Detected"
                else:
                    api_subtext = fname
            # Do not break, in case a confirmed spec is found later in the loop

    target_surface["api_surface"] = api_surface
    target_surface["api_subtext"] = api_subtext
    target_surface["api_pill"] = api_pill

    # 3. JS Health
    map_leaks = sum(1 for f in all_findings if "Source Map" in f.get("name", "") and f.get("severity") != "Passed")
    if map_leaks > 0:
        target_surface["js_health"] = f"{map_leaks} .map File(s) Leaked"
        target_surface["js_subtext"] = "Source Code Reconstruction Risk"
        target_surface["js_pill"] = "LEAKS DETECTED"
    else:
        target_surface["js_health"] = "Unknown" if scan_incomplete else "Clean Build"
        target_surface["js_subtext"] = "Not Assessed" if scan_incomplete else "0 .map Leaks Detected"
        target_surface["js_pill"] = "NO DATA" if scan_incomplete else "0 LEAKS DETECTED"

    # If we have completed_modules=0, this means NO meaningful checks finished.
    # Therefore, we do not have enough data to issue a 100/100 score.
    final_score = score if completed_modules != 0 else None

    return {
        "url": url,
        "status": "INCOMPLETE" if scan_incomplete else "COMPLETED",
        "score": final_score,
        "penalties": penalties,
        "severity_counts": severity_counts,
        "category_scores": category_scores,
        "owasp_coverage": list(owasp_categories),
        "target_surface": target_surface,
        "technical_compliance": {
            "pci_dss_4_0": {
                "status": get_status(high_critical_failed_pci, passed_pci_list),
                "failed_controls": failed_pci_list,
                "passed_controls": passed_pci_list
            },
            "nist_sp_800_53": {
                "status": get_status(high_critical_failed_nist, passed_nist_list),
                "failed_controls": failed_nist_list,
                "passed_controls": passed_nist_list
            },
            "iso_27001": {
                "status": get_status(high_critical_failed_iso, passed_iso_list),
                "failed_controls": failed_iso_list,
                "passed_controls": passed_iso_list
            }
        },
        "findings": all_findings,
        "metadata": metadata,
        "potential_issues_count": sum(c for k, c in severity_counts.items() if k in ["Critical", "High", "Medium", "Low"]),
        "executive_summary": f"Scan did not complete fully. Showing partial findings with a provisional score of {final_score}/100." if scan_incomplete and final_score is not None else "Scan aborted or target unreachable. Insufficient data for a score." if scan_incomplete else f"Scan completed. Detected {severity_counts['High'] + severity_counts['Critical']} high-priority issues resulting in a score of {score}/100.",
        "disclaimer": "Passive scan only. Modular engine execution."
    }
