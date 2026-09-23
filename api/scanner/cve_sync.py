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
    import urllib.parse
    existing_cves = {}
    try:
        ext_url = f"{supabase_url.rstrip('/')}/rest/v1/cpe_cve_cache?cpe=eq.{urllib.parse.quote(cpe)}&select=cves_json"
        ext_resp = sess.get(ext_url, headers=headers, timeout=10.0)
        if ext_resp.status_code == 200 and ext_resp.json():
            for c in ext_resp.json()[0].get("cves_json", []):
                existing_cves[c["id"]] = c
    except Exception as e:
        logger.warning(f"Could not fetch existing cache for {cpe}: {e}")

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

        # 1. Extract CVSS with deterministic precedence (v4 > v3.1 > v3.0 > v2)
        metrics = cve_data.get("metrics", {})
        cvss_score = None
        cvss_severity = None
        cvss_vector = None
        cvss_version = None
        cvss_source = None

        # Helper to extract
        def extract_cvss(metric_list, version_key):
            if not metric_list: return None
            # Pick primary if available, else first
            best_m = metric_list[0]
            for m in metric_list:
                if m.get("type") == "Primary":
                    best_m = m
                    break
            data = best_m.get("cvssData", {})

            base_score = data.get("baseScore")

            severity = data.get("baseSeverity")
            if not severity:
                severity = best_m.get("baseSeverity")

            return {
                "score": float(base_score) if base_score is not None else None,
                "severity": severity.upper() if severity else None,
                "vector": data.get("vectorString") or None,
                "version": data.get("version", version_key),
                "source": best_m.get("source") or None
            }

        cvss_info = None
        if "cvssMetricV40" in metrics and metrics["cvssMetricV40"]:
            cvss_info = extract_cvss(metrics["cvssMetricV40"], "4.0")
        elif "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_info = extract_cvss(metrics["cvssMetricV31"], "3.1")
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss_info = extract_cvss(metrics["cvssMetricV30"], "3.0")
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_info = extract_cvss(metrics["cvssMetricV2"], "2.0")

        if cvss_info:
            cvss_score = cvss_info["score"]
            cvss_severity = cvss_info["severity"]
            cvss_vector = cvss_info["vector"]
            cvss_version = cvss_info["version"]
            cvss_source = cvss_info["source"]

        # 2. Extract CWEs deterministically
        cwes = set()
        for w in cve_data.get("weaknesses", []):
            for desc in w.get("description", []):
                if desc.get("lang") == "en" and desc.get("value"):
                    cwes.add(desc.get("value"))

        # 3. KEV Extraction
        date_added = cve_data.get("cisaExploitAdd")
        ransomware_use = cve_data.get("cisaKnownRansomwareCampaignUse") or cve_data.get("cisaRansomwareCampaignUse")
        
        kev_info = {
            "status": "IN_KEV" if date_added else "NOT_IN_KEV",
            "date_added": date_added,
            "known_ransomware_campaign_use": ransomware_use,
            "provenance": "CISA-KEV-via-NVD"
        }

        # 4. SSVC Extraction
        ssvc_info = {"status": "NOT_FOUND"}
        cisa_records = []
        import json
        for ssvc_key in ["ssvcV203", "ssvcV2", "ssvc"]:
            for s in metrics.get(ssvc_key, []):
                src = str(s.get("source", "")).strip().lower()
                # 134c704f-9b21-4f2e-91b3-4a467353bcc0 is CISA-ADP UUID in NVD
                if src == "cisa-adp" or src == "134c704f-9b21-4f2e-91b3-4a467353bcc0":
                    cisa_records.append(s)

        if cisa_records:
            def ssvc_sort_key(record):
                data = record.get("ssvcData", {})
                ts = str(data.get("timestamp", ""))
                ver = str(data.get("version", ""))
                rec_id = str(data.get("id", ""))
                return (ts, ver, rec_id)
                
            cisa_records.sort(key=ssvc_sort_key, reverse=True)
            cisa_ssvc = cisa_records[0]
            ssvc_data = cisa_ssvc.get("ssvcData", {})
            options_list = ssvc_data.get("options", [])
            options_dict = {}
            
            import re
            def _to_lower_camel(k):
                parts = [p for p in re.split(r'[\s\-_]+', str(k).strip()) if p]
                if not parts: return ""
                return parts[0].lower() + "".join(p.capitalize() for p in parts[1:])
                
            if isinstance(options_list, list):
                for opt in options_list:
                    for k, v in opt.items():
                        options_dict[_to_lower_camel(k)] = str(v)
            elif isinstance(options_list, dict):
                for k, v in options_list.items():
                    options_dict[_to_lower_camel(k)] = str(v)
            
            ssvc_info = {
                "status": "AVAILABLE",
                "exploitation": options_dict.get("exploitation"),
                "automatable": options_dict.get("automatable"),
                "technicalImpact": options_dict.get("technicalImpact") or options_dict.get("technicalimpact"),
                "version": ssvc_data.get("version"),
                "timestamp": ssvc_data.get("timestamp"),
                "source": cisa_ssvc.get("source"),
                "provenance": "CISA-ADP-via-NVD"
            }

        # Store metadata
        parsed_cves.append({
            "id": cve_id,
            "cpe": cpe,
            "summary": summary,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cvss_vector": cvss_vector,
            "cvss_version": cvss_version,
            "cvss_source": cvss_source,
            "cwes": sorted(list(cwes)),
            "kev_info": kev_info,
            "ssvc_info": ssvc_info,
            "epss_info": None, # Populated in bulk below
            "provenance": {
                "source": "NVD",
                "source_timestamp": last_modified or published,
                "fetched_at": datetime.now(timezone.utc).isoformat()
            }
        })

    # 5. Bulk EPSS Extraction
    cve_ids = [c["id"] for c in parsed_cves]
    epss_map = {}
    epss_chunk_failed = set()
    if cve_ids:
        chunk_size = 50
        for i in range(0, len(cve_ids), chunk_size):
            chunk = cve_ids[i:i+chunk_size]
            try:
                epss_resp = sess.get(f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}", timeout=10.0)
                if epss_resp.status_code == 200:
                    epss_data = epss_resp.json().get("data", [])
                    for item in epss_data:
                        try:
                            epss_map[item.get("cve")] = {
                                "status": "AVAILABLE",
                                "epss": float(item.get("epss")),
                                "percentile": float(item.get("percentile")),
                                "date": item.get("date"),
                                "source": "FIRST"
                            }
                        except Exception:
                            pass
                else:
                    epss_chunk_failed.update(chunk)
            except Exception as e:
                logger.warning(f"EPSS bulk fetch failed: {e}")
                epss_chunk_failed.update(chunk)
                
    # Attach EPSS to parsed_cves
    for c in parsed_cves:
        cve_id = c["id"]
        if cve_id in epss_chunk_failed:
            old_epss = existing_cves.get(cve_id, {}).get("epss_info")
            if old_epss and old_epss.get("status") == "AVAILABLE":
                c["epss_info"] = old_epss
            else:
                c["epss_info"] = {"status": "UNAVAILABLE"}
        else:
            if cve_id in epss_map:
                c["epss_info"] = epss_map[cve_id]
            else:
                c["epss_info"] = {"status": "NOT_FOUND"}

    # Stable deterministic ordering (by CVE ID)
    parsed_cves.sort(key=lambda x: x["id"])

    # 6. Upsert into Supabase cache
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
