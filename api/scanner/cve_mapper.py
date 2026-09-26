import requests
import logging

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
