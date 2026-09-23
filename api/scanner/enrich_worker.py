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
    import copy
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

    def _get_match_metadata(identity: dict) -> tuple:
        match_confidence = identity.get("cpe_match_confidence", "LOW")
        rationale_code = None
        rationale_text = None

        sources = identity.get("sources", [])
        if any(s.get("source_type") in ("server_header", "x_powered_by") for s in sources):
            match_confidence = "MEDIUM"
            rationale_code = "SPOOFABLE_SOURCE"
            rationale_text = "Match is based on a spoofable HTTP header."

        return match_confidence, rationale_code, rationale_text

    try:
        from api.scanner.cve_mapper import get_cached_cves
        identity_parsed_cves = []
        cpe_to_cached_cves = {}
        has_terminal_intelligence_failure = False

        import time
        import copy
        from datetime import datetime, timezone

        for identity in identities:
            if time.time() - start_time > BUDGET:
                logger.warning(f"Time budget exceeded for scan {scan_id}")
                return release_worker_state("budget")

            cpe = identity.get("cpe_candidate") or identity.get("cpe")
            cpe_auth = identity.get("cpe_authority")

            # Explicit no-match semantics
            if identity.get("vulnerability_state") == "NOT_EVALUATED" and identity.get("vulnerability_state_reason") in ("INSUFFICIENT_VERSION", "NO_CPE_MAPPING"):
                identity_parsed_cves.append((identity, None))
                continue

            if not cpe or cpe_auth != "AUTHORITATIVE" or identity.get("vulnerability_state") in ("MATCHED", "NO_MATCH", "UNAVAILABLE"):
                identity_parsed_cves.append((identity, None))
                continue

            # Deterministic cache lookup
            if cpe in cpe_to_cached_cves:
                cached_cves = cpe_to_cached_cves[cpe]
            else:
                cached_cves = get_cached_cves(cpe, SUPABASE_URL, SUPABASE_SECRET_KEY)
                cpe_to_cached_cves[cpe] = cached_cves

            if cached_cves is None:
                has_terminal_intelligence_failure = True
                identity["vulnerability_state"] = "UNAVAILABLE"
                identity["vulnerability_state_reason"] = "INTELLIGENCE_UNAVAILABLE"
                identity["cves"] = []
                identity_parsed_cves.append((identity, None))
            else:
                identity_parsed_cves.append((identity, cached_cves))

        enriched_identities = []
        for identity, parsed_cves in identity_parsed_cves:
            if parsed_cves is not None:
                cves_copy = copy.deepcopy(parsed_cves)
                match_confidence, rationale_code, rationale_text = _get_match_metadata(identity)
                for c in cves_copy:
                    c["match_confidence"] = match_confidence
                    c["rationale_code"] = rationale_code
                    c["rationale_text"] = rationale_text

                identity["cves"] = cves_copy
                identity["vulnerability_state"] = "MATCHED" if cves_copy else "NO_MATCH"
                identity["vulnerability_state_reason"] = None if cves_copy else "NO_KNOWN_NVD_MATCH"

            enriched_identities.append(identity)

        save_res = requests.post(
            f"{SUPABASE_URL.rstrip('/')}/rest/v1/rpc/atomic_save_enriched_identities",
            headers=headers,
            json={"p_scan_id": scan_id, "p_expected_status": "RUNNING", "p_status": "FAILED" if has_terminal_intelligence_failure else "COMPLETED", "p_identities": enriched_identities},
            timeout=remaining_time(10.0)
        )
        if save_res.status_code != 200 or save_res.json() is not True:
            logger.error(f"Failed to persist enriched identities and COMPLETED state for {scan_id}")
            return JSONResponse(status_code=500, content={"error": "persistence_failed"})
        return JSONResponse(status_code=200, content={"status": "failed" if has_terminal_intelligence_failure else "completed"})

    except Exception as e:
        logger.error(f"Enrichment worker failed: {e}")
        if is_last_retry:
            try:
                res = requests.post(
                    f"{SUPABASE_URL.rstrip('/')}/rest/v1/rpc/atomic_update_cve_status",
                    headers=headers,
                    json={"p_scan_id": scan_id, "p_expected_status": "RUNNING", "p_status": "FAILED"}
                )
                if res.status_code == 200 and res.json() is True:
                    return JSONResponse(status_code=200, content={"status": "failed"})
            except Exception as final_e:
                logger.error(f"Failed to set status to FAILED: {final_e}")

        try:
            return release_worker_state("worker_exception")
        except Exception as inner_e:
            logger.error(f"Failed to release worker state after exception: {inner_e}")
            return JSONResponse(status_code=500, content={"error": "Internal error", "status": 500})

@worker_router.post("/sync-intelligence")
async def sync_intelligence_worker(request: Request, verified: bool = Depends(verify_qstash_signature)):
    """
    Background job triggered periodically via QStash to refresh stale CPEs in the local cache.
    """
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        return JSONResponse(status_code=500, content={"error": "Supabase not configured"})

    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Content-Type": "application/json"
    }

    import requests
    from datetime import datetime, timezone

    # 1. Query stale CPEs
    now_utc = datetime.now(timezone.utc).isoformat()
    url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/cpe_cve_cache?expires_at=lt.{now_utc}&limit=10"

    try:
        resp = requests.get(url, headers=headers, timeout=10.0)
        if resp.status_code != 200:
            logger.error("Failed to fetch stale cache records")
            return JSONResponse(status_code=500, content={"error": "cache_fetch_failed"})

        stale_records = resp.json()
    except Exception as e:
        logger.error(f"Failed to fetch stale cache: {e}")
        return JSONResponse(status_code=500, content={"error": "db_error"})

    if not stale_records:
        return JSONResponse(status_code=200, content={"status": "completed", "synced": 0})

    from api.scanner.cve_sync import sync_cpe_cve_cache
    sess = requests.Session()

    import time
    start_time = time.time()
    BUDGET = 45.0

    synced_count = 0
    failed_count = 0
    seen = set()

    for rec in stale_records:
        if time.time() - start_time > BUDGET:
            break

        cpe = rec.get("cpe")
        if not cpe or cpe in seen:
            continue
        seen.add(cpe)

        success = sync_cpe_cve_cache(cpe, session=sess)
        if success:
            synced_count += 1
        else:
            failed_count += 1

    return JSONResponse(status_code=200, content={
        "status": "completed",
        "synced": synced_count,
        "failed": failed_count,
        "total": len(stale_records)
    })
