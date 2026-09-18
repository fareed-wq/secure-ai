import re
import copy
from typing import List, Dict, Optional, Any

CPE_MAP = {
    "nginx": "cpe:2.3:a:nginx:nginx",
    "Microsoft IIS": "cpe:2.3:a:microsoft:internet_information_services",
    "WordPress": "cpe:2.3:a:wordpress:wordpress",
    "Apache": "cpe:2.3:a:apache:http_server",
    "PHP": "cpe:2.3:a:php:php",
    "jQuery": "cpe:2.3:a:jquery:jquery",
    "Node.js": "cpe:2.3:a:nodejs:node.js",
    "React": "cpe:2.3:a:facebook:react",
    "Vue.js": "cpe:2.3:a:vuejs:vue"
}

def _generate_cpe(product: str, version: Optional[str], precision: str) -> Optional[str]:
    if not product or product not in CPE_MAP:
        return None
    if not version or precision not in ("EXACT_OBSERVED", "PARSED_OBSERVED"):
        return None
    # Safely encode/validate CPE 2.3 components
    if not re.match(r'^[a-zA-Z0-9\.\-_]+$', version):
        return None
    return f"{CPE_MAP[product]}:{version}:*:*:*:*:*:*:*"

# Phase 4A: Real-Producer + Determinism Hardening

def normalize_vendor(product: str) -> Optional[str]:
    nl = product.lower()
    if nl == "nginx": return "nginx"
    if nl == "microsoft iis": return "Microsoft"
    if nl == "wordpress": return "WordPress"
    return None

def normalize_product(name: str) -> str:
    nl = name.strip().lower()
    if nl in ("nginx", "nginx."): return "nginx"
    if nl in ("iis", "microsoft-iis", "microsoft iis"): return "Microsoft IIS"
    if nl == "wordpress": return "WordPress"
    if nl in ("react", "react.js", "reactjs"): return "React"
    if nl in ("vue", "vue.js", "vuejs"): return "Vue.js"
    if nl in ("next.js", "nextjs", "next"): return "Next.js"
    if nl in ("nuxt", "nuxtjs", "nuxt.js"): return "Nuxt"
    return name.strip()

def get_layer(product: str) -> Optional[str]:
    nl = product.lower()
    if nl in ("cloudflare", "fastly", "akamai", "cloudfront", "imperva"): return "edge_cdn_waf"
    if nl in ("nginx", "microsoft iis", "apache", "caddy", "lighttpd", "litespeed"): return "web_server_proxy"
    if nl in ("wordpress", "asp.net", "asp.net mvc", "django", "laravel", "rails", "spring", "express", "next.js", "nuxt"): return "application_framework"
    if nl in ("react", "vue.js", "angular", "jquery", "lodash", "bootstrap", "moment", "moment.js"): return "client_side_library"
    if nl in ("php", "java", "node.js", "python", "ruby"): return "runtime_platform"
    return None

def _clean_version(ver: Any) -> Optional[str]:
    if not isinstance(ver, str):
        return None
    v = ver.strip()
    if not v:
        return None
    return v

def _clean_str(val: Any, default: str) -> str:
    if not isinstance(val, str):
        return default
    return val.strip()

def deduplicate_identities(identities: List[Dict]) -> List[Dict]:
    merged = {}
    
    conf_scores = {"High": 3, "Medium": 2, "Low": 1}
    verif_scores = {"OBSERVED": 3, "INFERRED": 2, "NOT_VERIFIED": 1}
    prec_scores = {"EXACT_OBSERVED": 4, "PARSED_OBSERVED": 3, "INFERRED": 2, "UNKNOWN": 1}
    
    for ident in identities:
        layer = ident.get("layer")
        prod = ident.get("product")
        if not layer or not prod:
            continue
            
        key = (layer, ident.get("vendor"), prod, ident.get("version"))
        
        if key not in merged:
            merged[key] = {
                "vendor": ident.get("vendor"),
                "product": prod,
                "version": ident.get("version"),
                "layer": layer,
                "confidence": ident.get("confidence", "Low"),
                "verification_state": ident.get("verification_state", "NOT_VERIFIED"),
                "version_precision": ident.get("version_precision", "UNKNOWN"),
                "sources": list(ident.get("sources", []))
            }
        else:
            existing = merged[key]
            
            # Merge sources uniquely
            existing_sources_tups = {(s.get("module",""), s.get("rule_id",""), s.get("source_type","")) for s in existing["sources"]}
            for s in ident.get("sources", []):
                tup = (s.get("module",""), s.get("rule_id",""), s.get("source_type",""))
                if tup not in existing_sources_tups:
                    existing["sources"].append(s)
                    existing_sources_tups.add(tup)
                    
            # Precedence: Confidence > Verification > Precision > Source tuple
            curr_conf = conf_scores.get(ident.get("confidence", "Low"), 0)
            exist_conf = conf_scores.get(existing.get("confidence", "Low"), 0)
            
            curr_verif = verif_scores.get(ident.get("verification_state", "NOT_VERIFIED"), 0)
            exist_verif = verif_scores.get(existing.get("verification_state", "NOT_VERIFIED"), 0)
            
            curr_prec = prec_scores.get(ident.get("version_precision", "UNKNOWN"), 0)
            exist_prec = prec_scores.get(existing.get("version_precision", "UNKNOWN"), 0)
            
            def should_replace():
                if curr_conf > exist_conf: return True
                if curr_conf < exist_conf: return False
                if curr_verif > exist_verif: return True
                if curr_verif < exist_verif: return False
                if curr_prec > exist_prec: return True
                if curr_prec < exist_prec: return False
                
                # Tie breaker: stable canonical source tuple comparison
                def _get_src_tup(ident_dict):
                    srcs = ident_dict.get("sources", [])
                    if not srcs: return ("", "", "")
                    # Sort internally to get the deterministic "first" source for the tie break
                    sorted_srcs = sorted([(s.get("module",""), s.get("rule_id",""), s.get("source_type","")) for s in srcs])
                    return sorted_srcs[0]
                    
                c_src_tup = _get_src_tup(ident)
                e_src_tup = _get_src_tup(existing)
                return c_src_tup > e_src_tup

            if should_replace():
                existing["confidence"] = ident.get("confidence", "Low")
                existing["verification_state"] = ident.get("verification_state", "NOT_VERIFIED")
                existing["version_precision"] = ident.get("version_precision", "UNKNOWN")
                
    # Finalize derived fields and sort sources
    for k in merged:
        merged[k]["cpe"] = _generate_cpe(merged[k]["product"], merged[k]["version"], merged[k]["version_precision"])
        merged[k]["sources"].sort(key=lambda x: (x.get("module", ""), x.get("rule_id", ""), x.get("source_type", "")))
        
    return sorted(list(merged.values()), key=lambda x: (x.get("layer", ""), x.get("vendor") or "", x.get("product", ""), x.get("version") or ""))

def extract_technology_identities(findings: List[Dict]) -> List[Dict]:
    raw_identities = []
    
    if not isinstance(findings, list):
        return []

    for f in findings:
        if not isinstance(f, dict):
            continue
            
        rule_id = f.get("rule_id")
        if not isinstance(rule_id, str):
            continue
            
        module = _clean_str(f.get("module"), "Unknown")
        finding_confidence = _clean_str(f.get("confidence"), "Low")
        if finding_confidence not in ("High", "Medium", "Low"):
            finding_confidence = "Low"
            
        ev = f.get("evidence")
        ev_raw = ev.get("raw", "") if isinstance(ev, dict) else str(ev) if ev is not None else ""
        
        # 1. TechFingerprintModule
        if rule_id == "technology_detected":
            if isinstance(ev, dict) and "product" in ev:
                raw_prod = ev.get("product")
                if not isinstance(raw_prod, str): continue
                
                raw_ver = _clean_version(ev.get("version"))
                source_desc = _clean_str(ev.get("source"), "unknown")
                
                prod = normalize_product(raw_prod)
                layer = get_layer(prod)
                if not layer: continue
                
                vend = normalize_vendor(prod)
                version_precision = "PARSED_OBSERVED" if raw_ver else "UNKNOWN"
                
                # Canonicalize source type
                sd_lower = source_desc.lower()
                if "server" in sd_lower: src_type = "server_header"
                elif "x-powered-by" in sd_lower: src_type = "x_powered_by_header"
                elif "generator" in sd_lower: src_type = "meta_generator"
                elif "html" in sd_lower or "marker" in sd_lower or "wp-" in sd_lower or "nuxt" in sd_lower or "next" in sd_lower: src_type = "html_marker"
                else: 
                    # EXCLUDE if provenance is unknown, no fallback fabrication
                    continue
                
                verification_state = "OBSERVED" if src_type in ("server_header", "x_powered_by_header") else "INFERRED"
                
                ident_conf = finding_confidence
                if ident_conf == "High":
                    ident_conf = "Medium"
                    
                raw_identities.append({
                    "vendor": vend,
                    "product": prod,
                    "version": raw_ver,
                    "version_precision": version_precision,
                    "layer": layer,
                    "confidence": ident_conf,
                    "verification_state": verification_state,
                    "sources": [{"module": module, "rule_id": rule_id, "source_type": src_type}]
                })
                
        # 2. InformationDisclosureModule
        elif rule_id == "info_disclosure_server_banner":
            match = re.search(r'^([A-Za-z0-9\-]+)/([\d\.]+)', ev_raw)
            if match:
                raw_prod = match.group(1)
                raw_ver = _clean_version(match.group(2))
                prod = normalize_product(raw_prod)
                layer = get_layer(prod)
                if layer:
                    raw_identities.append({
                        "vendor": normalize_vendor(prod),
                        "product": prod,
                        "version": raw_ver,
                        "version_precision": "PARSED_OBSERVED",
                        "layer": layer,
                        "confidence": "Medium",
                        "verification_state": "OBSERVED",
                        "sources": [{"module": module, "rule_id": rule_id, "source_type": "server_header"}]
                    })
                    
        # 3. JavaScriptSecurityModule
        elif rule_id == "technology_outdated_library":
            for lib in ev_raw.split(", "):
                match = re.match(r'^(.*?)\s+v([\d\.]+)$', lib.strip())
                if match:
                    raw_prod = match.group(1)
                    raw_ver = _clean_version(match.group(2))
                    prod = normalize_product(raw_prod)
                    layer = get_layer(prod)
                    if layer:
                        raw_identities.append({
                            "vendor": normalize_vendor(prod),
                            "product": prod,
                            "version": raw_ver,
                            "version_precision": "PARSED_OBSERVED",
                            "layer": layer,
                            "confidence": "Medium",
                            "verification_state": "INFERRED",
                            "sources": [{"module": module, "rule_id": rule_id, "source_type": "js_asset"}]
                        })
                        
        elif rule_id == "technology_js_frameworks_detected":
            for fw in ev_raw.split(", "):
                if not fw.strip(): continue
                prod = normalize_product(fw)
                layer = get_layer(prod)
                if layer:
                    raw_identities.append({
                        "vendor": normalize_vendor(prod),
                        "product": prod,
                        "version": None,
                        "version_precision": "UNKNOWN",
                        "layer": layer,
                        "confidence": "Medium",
                        "verification_state": "INFERRED",
                        "sources": [{"module": module, "rule_id": rule_id, "source_type": "js_framework_marker"}]
                    })
                    
        # 4. AuthenticationSessionSecurityModule
        elif rule_id == "auth_session_tech_fingerprinted":
            if "Technologies:" in ev_raw:
                techs_str = ev_raw.split("Technologies:")[1].strip()
                for t in techs_str.split(", "):
                    if not t.strip(): continue
                    prod = normalize_product(t.strip())
                    layer = get_layer(prod)
                    if layer:
                        raw_identities.append({
                            "vendor": normalize_vendor(prod),
                            "product": prod,
                            "version": None,
                            "version_precision": "UNKNOWN",
                            "layer": layer,
                            "confidence": "Medium",
                            "verification_state": "INFERRED",
                            "sources": [{"module": module, "rule_id": rule_id, "source_type": "session_cookie"}]
                        })

    return deduplicate_identities(raw_identities)
