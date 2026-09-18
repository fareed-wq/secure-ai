import os
import logging
from datetime import datetime, timezone
import requests
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
worker_router = APIRouter()

QSTASH_CURRENT_SIGNING_KEY = os.environ.get("QSTASH_CURRENT_SIGNING_KEY")
QSTASH_NEXT_SIGNING_KEY = os.environ.get("QSTASH_NEXT_SIGNING_KEY")
SUPABASE_URL = os.environ.get("VITE_SUPABASE_URL") or os.environ.get("SUPABASE_URL")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY")

async def verify_qstash_signature(request: Request):
    try:
        from qstash import Receiver
    except ImportError:
        logger.error("qstash package not installed")
        raise HTTPException(status_code=500, detail="QStash not installed")

    if not Receiver or not QSTASH_CURRENT_SIGNING_KEY or not QSTASH_NEXT_SIGNING_KEY:
        logger.error("QStash signature keys not configured")
        raise HTTPException(status_code=500, detail="QStash keys missing in production")

    signature = request.headers.get("Upstash-Signature")
    if not signature:
        logger.error("Missing Upstash-Signature")
        raise HTTPException(status_code=401, detail="Missing signature")

    body = await request.body()

    receiver = Receiver(
        current_signing_key=QSTASH_CURRENT_SIGNING_KEY,
        next_signing_key=QSTASH_NEXT_SIGNING_KEY
    )

    try:
        receiver.verify(
            body=body.decode("utf-8"),
            signature=signature,
            url=str(request.url)
        )
    except Exception as e:
        logger.error(f"QStash signature verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid signature")

    return True

@worker_router.post("/enrich-cve")
async def enrich_cve_worker(request: Request, verified: bool = Depends(verify_qstash_signature)):
    import time
    start_time = time.time()
    BUDGET = 45.0

    def remaining_time(max_val=10.0):
        return max(1.0, min(max_val, BUDGET - (time.time() - start_time)))

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON"})

    scan_id = body.get("scan_id")
    if not scan_id:
        return JSONResponse(status_code=400, content={"error": "Missing scan_id"})

    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        logger.error("Supabase not configured")
        return JSONResponse(status_code=500, content={"error": "Supabase not configured"})

    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

    retried_count = int(request.headers.get("Upstash-Retried", "0"))
    is_last_retry = retried_count >= 3

    # 1. Fetch Scan
    scan_resp = requests.get(f"{SUPABASE_URL.rstrip('/')}/rest/v1/scans?id=eq.{scan_id}", headers=headers, timeout=remaining_time())
    if scan_resp.status_code != 200 or not scan_resp.json():
        logger.warning(f"Scan {scan_id} not found or deleted")
        return JSONResponse(status_code=200, content={"status": "skipped", "reason": "scan_not_found"})

    scan_row = scan_resp.json()[0]
    report_data = scan_row.get("report_data", {})

    curr_status = report_data.get("cve_enrichment_status")
    if curr_status in ("COMPLETED", "FAILED"):
        return JSONResponse(status_code=200, content={"status": "skipped", "reason": "already_terminal"})

    # Claim idempotently: QUEUED -> RUNNING, NOT_REQUESTED -> RUNNING, or RUNNING(expired) -> RUNNING
    claim_res = requests.post(
        f"{SUPABASE_URL.rstrip('/')}/rest/v1/rpc/atomic_update_cve_status",
        headers=headers,
        json={"p_scan_id": scan_id, "p_expected_status": "QUEUED", "p_new_status": "RUNNING", "p_lease_duration_sec": 55},
        timeout=remaining_time()
    )
    if claim_res.status_code != 200 or claim_res.json() is not True:
        # Race: worker arrived before main request upgraded NOT_REQUESTED -> QUEUED
        claim_res = requests.post(
            f"{SUPABASE_URL.rstrip('/')}/rest/v1/rpc/atomic_update_cve_status",
            headers=headers,
            json={"p_scan_id": scan_id, "p_expected_status": "NOT_REQUESTED", "p_new_status": "RUNNING", "p_lease_duration_sec": 55},
            timeout=remaining_time()
        )
        if claim_res.status_code != 200 or claim_res.json() is not True:
            # If we couldn't claim it, another worker holds an active lease or it's a network error.
            # Returning 503 ensures QStash will retry.
            return JSONResponse(status_code=503, content={"error": "lease_active_or_error", "status": 503})

    identities = report_data.get("technology_identities", [])
    if not identities:
        comp_res = requests.post(
            f"{SUPABASE_URL.rstrip('/')}/rest/v1/rpc/atomic_update_cve_status",
            headers=headers,
            json={"p_scan_id": scan_id, "p_expected_status": "RUNNING", "p_new_status": "COMPLETED"},
            timeout=remaining_time()
        )
        if comp_res.status_code != 200 or comp_res.json() is not True:
            logger.error(f"Failed to persist COMPLETED state for {scan_id}")
            return JSONResponse(status_code=500, content={"error": "persistence_failed"})
        return JSONResponse(status_code=200, content={"status": "completed", "reason": "no_identities"})

    def release_worker_state(reason_str):
        if is_last_retry:
            res = requests.post(
                f"{SUPABASE_URL.rstrip('/')}/rest/v1/rpc/atomic_update_cve_status",
                headers=headers,
                json={"p_scan_id": scan_id, "p_expected_status": "RUNNING", "p_new_status": "FAILED"},
                timeout=max(1.0, remaining_time())
            )
            if res.status_code != 200 or res.json() is not True:
                logger.error(f"Failed to persist FAILED state for {scan_id}")
                return JSONResponse(status_code=500, content={"error": "persistence_failed"})
            return JSONResponse(status_code=200, content={"status": "failed", "reason": f"{reason_str}_exhausted"})
        else:
            res = requests.post(
                f"{SUPABASE_URL.rstrip('/')}/rest/v1/rpc/atomic_update_cve_status",
                headers=headers,
                json={"p_scan_id": scan_id, "p_expected_status": "RUNNING", "p_new_status": "QUEUED"},
                timeout=max(1.0, remaining_time())
            )
            if res.status_code != 200 or res.json() is not True:
                logger.error(f"Failed to persist QUEUED (release) state for {scan_id}")
                return JSONResponse(status_code=500, content={"error": "persistence_failed"})
            return JSONResponse(status_code=503, content={"error": f"{reason_str}, retry", "status": 503})

    try:
        enriched_identities = []
        for identity in identities:
            if time.time() - start_time > BUDGET:
                logger.warning(f"Time budget exceeded for scan {scan_id}")
                return release_worker_state("budget")

            cpe = identity.get("cpe")
            precision = identity.get("version_precision")

            if "cves" not in identity:
                identity["cves"] = []

            if not cpe or precision not in ("EXACT_OBSERVED", "PARSED_OBSERVED"):
                enriched_identities.append(identity)
                continue

            # If already has CVEs and not empty (from partial execution), we could skip
            if identity.get("cves") and len(identity["cves"]) > 0:
                enriched_identities.append(identity)
                continue

            # 3. Check Cache
            cache_resp = requests.get(f"{SUPABASE_URL.rstrip('/')}/rest/v1/cpe_cve_cache?cpe=eq.{requests.utils.quote(cpe)}", headers=headers, timeout=remaining_time(10.0))
            cached_cves = None
            if cache_resp.status_code == 200 and cache_resp.json():
                cache_row = cache_resp.json()[0]
                expires_at_str = cache_row.get("expires_at")
                if expires_at_str:
                    expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
                    if expires_at > datetime.now(timezone.utc):
                        cached_cves = cache_row.get("cves_json", [])

            if cached_cves is not None:
                identity["cves"] = cached_cves
                enriched_identities.append(identity)
                continue

            # 4. NVD Lookup (Cache Miss)
            try:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={requests.utils.quote(cpe)}"
                resp = requests.get(url, timeout=remaining_time(5.0))

                if resp.status_code == 200:
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])

                    parsed_cves = []
                    for vuln_item in vulnerabilities:
                        if len(parsed_cves) >= 5:
                            break
                        cve_data = vuln_item.get("cve", {})
                        cve_id = cve_data.get("id")
                        if not cve_id: continue

                        summary = "No description provided."
                        for desc in cve_data.get("descriptions", []):
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

                        parsed_cves.append({"id": cve_id, "severity": severity, "summary": summary})

                    identity["cves"] = parsed_cves

                    # 5. Save to Cache
                    from datetime import timedelta
                    now = datetime.now(timezone.utc)
                    expires = (now + timedelta(days=1)).isoformat()

                    cache_payload = {
                        "cpe": cpe,
                        "cves_json": parsed_cves,
                        "fetched_at": now.isoformat(),
                        "expires_at": expires,
                        "updated_at": now.isoformat()
                    }
                    requests.post(
                        f"{SUPABASE_URL.rstrip('/')}/rest/v1/cpe_cve_cache",
                        headers={**headers, "Prefer": "resolution=merge-duplicates"},
                        json=cache_payload,
                        timeout=remaining_time(10.0)
                    )
                else:
                    logger.warning(f"NVD API returned {resp.status_code} for {cpe}")
                    return release_worker_state("nvd_error")
            except requests.exceptions.Timeout:
                logger.warning(f"NVD API timeout for {cpe}")
                return release_worker_state("nvd_timeout")
            except Exception as e:
                logger.warning(f"Failed to fetch CVEs for {cpe}: {e}")
                return release_worker_state("nvd_exception")

            enriched_identities.append(identity)

        save_res = requests.post(
            f"{SUPABASE_URL.rstrip('/')}/rest/v1/rpc/atomic_save_enriched_identities",
            headers=headers,
            json={"p_scan_id": scan_id, "p_expected_status": "RUNNING", "p_status": "COMPLETED", "p_identities": enriched_identities},
            timeout=remaining_time(10.0)
        )
        if save_res.status_code != 200 or save_res.json() is not True:
            logger.error(f"Failed to persist enriched identities and COMPLETED state for {scan_id}")
            return JSONResponse(status_code=500, content={"error": "persistence_failed"})
        return JSONResponse(status_code=200, content={"status": "completed"})

    except Exception as e:
        logger.error(f"Enrichment worker failed: {e}")
        try:
            return release_worker_state("worker_exception")
        except Exception as inner_e:
            logger.error(f"Failed to release worker state after exception: {inner_e}")
            return JSONResponse(status_code=500, content={"error": "Internal error", "status": 500})
