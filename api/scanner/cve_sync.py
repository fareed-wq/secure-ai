import os
import requests
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

def sync_cpe_cve_cache(cpe: str, session: Optional[requests.Session] = None) -> bool:
    """
    Authoritatively fetch CVEs for a CPE from NVD and upsert into the local cache.
    Returns True if successful, False if the sync failed (preserving existing cache).
    
    This fulfills the Phase 5A requirement for bounded, retry-safe, deterministic,
    idempotent, and provenance-aware ingestion.
    """
    supabase_url = os.environ.get("VITE_SUPABASE_URL") or os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_SECRET_KEY")
    
    if not supabase_url or not supabase_key:
        logger.error("Supabase credentials not configured for CVE sync")
        return False
        
    sess = session or requests.Session()
    headers = {
        "apikey": supabase_key,
        "Authorization": f"Bearer {supabase_key}",
        "Content-Type": "application/json",
        "Prefer": "return=representation, resolution=merge-duplicates"
    }
    
    # 1. Fetch from NVD (bounded network call, no unbounded loop)
    try:
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={requests.utils.quote(cpe)}"
        resp = sess.get(nvd_url, timeout=15.0)
        
        if resp.status_code != 200:
            logger.warning(f"NVD API returned {resp.status_code} for {cpe}. Preserving existing cache.")
            return False
            
        data = resp.json()
    except Exception as e:
        logger.warning(f"NVD sync failed for {cpe}: {e}. Preserving existing cache.")
        return False

    # 2. Deterministic Parsing & Provenance
    parsed_cves: List[Dict[str, Any]] = []
    seen_cves = set()
    vulnerabilities = data.get("vulnerabilities", [])
    
    for vuln_item in vulnerabilities:
        cve_data = vuln_item.get("cve", {})
        cve_id = cve_data.get("id")
        if not cve_id or cve_id in seen_cves:
            continue
            
        seen_cves.add(cve_id)
        
        # Provenance and timestamps from authoritative source
        published = cve_data.get("published")
        last_modified = cve_data.get("lastModified")
        
        summary = "No description provided."
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                summary = desc.get("value")
                break
                
        # Store minimum needed for deterministic matching without fabricating CVSS/CWE.
        parsed_cves.append({
            "id": cve_id,
            "cpe": cpe,
            "summary": summary,
            "provenance": {
                "source": "NVD",
                "source_timestamp": last_modified or published,
                "fetched_at": datetime.now(timezone.utc).isoformat()
            }
        })
        
    # Stable deterministic ordering (by CVE ID)
    parsed_cves.sort(key=lambda x: x["id"])
    
    # 3. Upsert into Supabase cache
    now = datetime.now(timezone.utc)
    # Default to 7 days freshness; could be made configurable
    expires = (now + timedelta(days=7)).isoformat()
    
    payload = {
        "cpe": cpe,
        "cves_json": parsed_cves,
        "fetched_at": now.isoformat(),
        "expires_at": expires,
        "updated_at": now.isoformat()
    }
    
    try:
        upsert_resp = sess.post(
            f"{supabase_url.rstrip('/')}/rest/v1/cpe_cve_cache",
            headers=headers,
            json=payload,
            timeout=10.0
        )
        if upsert_resp.status_code not in (200, 201):
            logger.error(f"Failed to upsert cache for {cpe}: {upsert_resp.status_code} {upsert_resp.text}")
            return False
            
        return True
    except Exception as e:
        logger.error(f"Failed to upsert cache for {cpe}: {e}")
        return False
