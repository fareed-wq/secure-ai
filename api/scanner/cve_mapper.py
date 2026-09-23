import requests
import logging
import copy

logger = logging.getLogger(__name__)

def get_cached_cves(cpe: str, supabase_url: str, supabase_key: str, session: requests.Session = None) -> list:
    """
    Retrieve deterministic, authoritative CVE matching data from the local cpe_cve_cache.
    Returns None if the cache is stale or missing, distinguishing 'unavailable' from 'no vulnerabilities'.
    """
    if not supabase_url or not supabase_key:
        return None

    sess = session or requests.Session()
    headers = {
        "apikey": supabase_key,
        "Authorization": f"Bearer {supabase_key}",
        "Content-Type": "application/json"
    }

    import urllib.parse
    from datetime import datetime, timezone
    now_utc = datetime.now(timezone.utc).isoformat()

    try:
        query = f"cpe=eq.{urllib.parse.quote(cpe)}&expires_at=gt.{urllib.parse.quote(now_utc)}"
        resp = sess.get(
            f"{supabase_url.rstrip('/')}/rest/v1/cpe_cve_cache?{query}",
            headers=headers,
            timeout=5.0
        )
        if resp.status_code == 200:
            data = resp.json()
            if data and len(data) > 0:
                # Return the cached deterministic CVE list
                return data[0].get("cves_json", [])
            else:
                # Targeted refresh: ensure a shell record exists so the background sync job picks it up
                payload = {
                    "cpe": cpe,
                    "cves_json": [],
                    "fetched_at": "1970-01-01T00:00:00Z",
                    "expires_at": "1970-01-01T00:00:00Z",
                    "updated_at": "1970-01-01T00:00:00Z"
                }
                headers_upsert = headers.copy()
                headers_upsert["Prefer"] = "return=minimal, resolution=ignore-duplicates"
                try:
                    sess.post(f"{supabase_url.rstrip('/')}/rest/v1/cpe_cve_cache", headers=headers_upsert, json=payload, timeout=2.0)
                except Exception:
                    pass
    except Exception as e:
        logger.warning(f"Failed to fetch cached CVEs for {cpe}: {e}")

    return None

# EXACT MIGRATION POINT:
# The function `enrich_with_cves` below currently introduces an unbounded live-network dependency
# (querying NVD directly for each CPE) and fabricates CVSS metadata.
# For Phase 5 deterministic matching, `enrich_with_cves` should be replaced or rewritten to strictly consume
# `get_cached_cves()` without falling back to a live network request, enforcing the use of the offline
# authoritative cache populated by `api.scanner.cve_sync.sync_cpe_cve_cache`.

def enrich_with_cves(identities: list) -> list:
    enriched = copy.deepcopy(identities)
    
    for identity in enriched:
        identity["cves"] = []
        
        cpe = identity.get("cpe")
        precision = identity.get("version_precision")
        
        if not cpe:
            continue
            
        if precision not in ("EXACT_OBSERVED", "PARSED_OBSERVED"):
            continue
            
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"
            resp = requests.get(url, timeout=5.0)
            
            if resp.status_code != 200:
                logger.warning(f"NVD API returned {resp.status_code} for {cpe}")
                continue
                
            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            parsed_cves = []
            for vuln_item in vulnerabilities:
                if len(parsed_cves) >= 5:
                    break
                    
                cve_data = vuln_item.get("cve", {})
                cve_id = cve_data.get("id")
                if not cve_id:
                    continue
                    
                descriptions = cve_data.get("descriptions", [])
                summary = "No description provided."
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        summary = desc.get("value")
                        break
                        
                metrics = cve_data.get("metrics", {})
                severity = "UNKNOWN"
                
                if "cvssMetricV31" in metrics and len(metrics["cvssMetricV31"]) > 0:
                    severity = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                elif "cvssMetricV30" in metrics and len(metrics["cvssMetricV30"]) > 0:
                    severity = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                elif "cvssMetricV2" in metrics and len(metrics["cvssMetricV2"]) > 0:
                    severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
                    
                parsed_cves.append({
                    "id": cve_id,
                    "severity": severity,
                    "summary": summary
                })
                
            identity["cves"] = parsed_cves
            
        except requests.exceptions.Timeout:
            logger.warning(f"NVD API timeout for {cpe}")
            continue
        except Exception as e:
            logger.warning(f"Failed to fetch CVEs for {cpe}: {e}")
            continue
            
    return enriched
