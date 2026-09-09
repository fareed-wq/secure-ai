import os
import json
import logging
from datetime import datetime, timedelta
import requests

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse

from api.auth.entitlements import is_scheduled_scans_eligible
from api.scanner.orchestrator import scan_url, validate_scan_target
from api.scheduling.time_utils import get_next_run_at

try:
    from qstash import Receiver
except ImportError:
    Receiver = None

logger = logging.getLogger(__name__)
worker_router = APIRouter()

SUPABASE_URL = os.environ.get("VITE_SUPABASE_URL") or os.environ.get("SUPABASE_URL")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY")
QSTASH_CURRENT_SIGNING_KEY = os.environ.get("QSTASH_CURRENT_SIGNING_KEY")
QSTASH_NEXT_SIGNING_KEY = os.environ.get("QSTASH_NEXT_SIGNING_KEY")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "https://www.urlscanonline.com")

def get_db_headers():
    return {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Content-Type": "application/json"
    }

@worker_router.post("/scheduled-scan")
async def handle_scheduled_scan(request: Request):
    if not Receiver or not QSTASH_CURRENT_SIGNING_KEY or not QSTASH_NEXT_SIGNING_KEY:
        logger.error("QStash signature keys not configured")
        return JSONResponse(status_code=500, content={"error": "Server misconfigured"})

    signature = request.headers.get("Upstash-Signature")
    if not signature:
        return JSONResponse(status_code=401, content={"error": "Missing signature"})

    body_bytes = await request.body()

    receiver = Receiver(
        current_signing_key=QSTASH_CURRENT_SIGNING_KEY,
        next_signing_key=QSTASH_NEXT_SIGNING_KEY
    )

    worker_url = f"{APP_BASE_URL.rstrip('/')}/api/internal/scheduled-scan"

    try:
        receiver.verify(
            body=body_bytes.decode("utf-8"),
            signature=signature,
            url=worker_url
        )
    except Exception as e:
        logger.error(f"Invalid signature: {e}")
        return JSONResponse(status_code=403, content={"error": "Invalid signature"})

    msg_id = request.headers.get("Upstash-Message-Id")
    qs_schedule_id = request.headers.get("Upstash-Schedule-Id")

    try:
        body = json.loads(body_bytes)
        schedule_id = body.get("schedule_id")
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    if not schedule_id:
        return JSONResponse(status_code=400, content={"error": "Missing schedule_id"})

    # Fetch schedule
    db_headers = get_db_headers()
    url = f"{SUPABASE_URL}/rest/v1/scan_schedules?id=eq.{schedule_id}&select=*"
    resp = requests.get(url, headers=db_headers)
    if resp.status_code != 200 or len(resp.json()) == 0:
        logger.info("Scheduled worker skipped", extra={"reason": "schedule_deleted"})
        return JSONResponse(status_code=200, content={"status": "skipped", "reason": "schedule_deleted"})

    sched = resp.json()[0]

    # Check schedule_id from header if present
    if qs_schedule_id and sched.get("qstash_schedule_id") != qs_schedule_id:
        logger.info("Scheduled worker skipped", extra={"reason": "schedule_id_mismatch"})
        return JSONResponse(status_code=200, content={"status": "skipped", "reason": "schedule_id_mismatch"})

    if not sched.get("is_enabled"):
        logger.info("Scheduled worker skipped", extra={"reason": "disabled"})
        return JSONResponse(status_code=200, content={"status": "skipped", "reason": "disabled"})

    user_id = sched["user_id"]

    # Check entitlement via centralized eligibility
    if not is_scheduled_scans_eligible(user_id):
        requests.patch(f"{SUPABASE_URL}/rest/v1/scan_schedules?id=eq.{schedule_id}", headers=db_headers, json={
            "is_enabled": False, "last_status": "paused_entitlement"
        })
        # Try to pause QStash
        from api.scheduling.router import QStashClient, QSTASH_TOKEN
        if QStashClient and QSTASH_TOKEN and sched.get("qstash_schedule_id"):
            try:
                qstash_url = os.environ.get("QSTASH_URL")
                if qstash_url:
                    QStashClient(QSTASH_TOKEN, base_url=qstash_url).schedule.pause(sched["qstash_schedule_id"])
                else:
                    QStashClient(QSTASH_TOKEN).schedule.pause(sched["qstash_schedule_id"])
            except Exception:
                pass

        logger.info("Scheduled worker skipped", extra={"reason": "entitlement_lost"})
        return JSONResponse(status_code=200, content={"status": "skipped", "reason": "entitlement_lost"})

    # Revalidate target
    validation_err = validate_scan_target(sched["target_url"], "passive")
    if validation_err:
        requests.patch(f"{SUPABASE_URL}/rest/v1/scan_schedules?id=eq.{schedule_id}", headers=db_headers, json={
            "is_enabled": False, "last_status": "failed", "last_error_code": "target_invalid"
        })
        logger.info("Scheduled worker skipped", extra={"reason": "target_invalid"})
        return JSONResponse(status_code=200, content={"status": "skipped", "reason": "target_invalid"})

    now = datetime.utcnow()
    scheduled_for = now.isoformat()

    # Insert run table (idempotency by qstash_message_id)
    run_payload = {
        "schedule_id": schedule_id,
        "user_id": user_id,
        "qstash_message_id": msg_id,
        "qstash_schedule_id": qs_schedule_id,
        "scheduled_for": scheduled_for,
        "status": "pending",
        "started_at": scheduled_for
    }

    run_resp = requests.post(
        f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs",
        headers={**db_headers, "Prefer": "return=representation"},
        json=run_payload
    )

    if run_resp.status_code == 409:
        # duplicate
        logger.info("Scheduled worker skipped", extra={"reason": "already_processed"})
        return JSONResponse(status_code=200, content={"status": "skipped", "reason": "already_processed"})
    elif run_resp.status_code not in (200, 201):
        # some other error
        pass

    run_id = run_resp.json()[0]["id"] if run_resp.status_code in (200, 201) else None

    # Claim lease atomically: worker_lease_until < now OR IS NULL
    current_time_str = datetime.utcnow().isoformat()
    claim_query = f"?id=eq.{schedule_id}&or=(worker_lease_until.is.null,worker_lease_until.lt.{current_time_str})"
    lease_until = (now + timedelta(minutes=5)).isoformat()
    claim_resp = requests.patch(
        f"{SUPABASE_URL}/rest/v1/scan_schedules{claim_query}",
        headers={**db_headers, "Prefer": "return=representation"},
        json={"worker_lease_until": lease_until, "last_status": "running"}
    )
    if claim_resp.status_code != 200 or len(claim_resp.json()) == 0:
        if run_id:
            requests.patch(f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}", headers=db_headers, json={"status": "skipped"})
        logger.info("Scheduled worker skipped", extra={"reason": "lease_active"})
        return JSONResponse(status_code=200, content={"status": "skipped", "reason": "lease_active"})

    # Execute Scan
    scan_id = None
    try:
        # ALWAYS passive
        result = scan_url(sched["target_url"], False, "passive")

        # Insert to scans
        if "scan_mode" not in result:
            result["scan_mode"] = "passive"

        scan_payload = {
            "user_id": user_id,
            "target_url": result.get("url", sched["target_url"]),
            "score": result.get("score", 0),
            "report_data": result,
            "created_at": scheduled_for,
            "trigger_type": "scheduled",
            "schedule_id": schedule_id
        }
        db_res = requests.post(f"{SUPABASE_URL}/rest/v1/scans", headers={**db_headers, "Prefer": "return=representation"}, json=scan_payload)
        if db_res.status_code in (200, 201):
            scan_id = db_res.json()[0].get("id")
            status = "completed"
            err_code = None
        else:
            status = "failed"
            err_code = "db_insert_failed"
    except Exception as e:
        logger.error(f"Scheduled scan failed: {e}")
        status = "failed"
        err_code = "scan_exception"
    finally:
        # Finalize and clear lease
        completed_at = datetime.utcnow().isoformat()

        # Calculate next_run_at
        from api.scheduling.time_utils import get_next_run_at
        from datetime import time
        try:
            tod_str = sched["time_of_day"]
            parts = tod_str.split(":")
            tod = time(int(parts[0]), int(parts[1]), int(parts[2]) if len(parts) > 2 else 0)
            next_run_dt = get_next_run_at(
                frequency=sched["frequency"],
                time_of_day=tod,
                timezone_str=sched["timezone"],
                day_of_week=sched.get("day_of_week"),
                day_of_month=sched.get("day_of_month"),
                now_utc=datetime.utcnow()
            )
            next_run_at = next_run_dt.isoformat()
        except Exception as e:
            logger.error(f"Failed to calculate next_run_at: {e}")
            next_run_at = None

        if run_id:
            requests.patch(f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}", headers=db_headers, json={
                "status": status, "completed_at": completed_at, "error_code": err_code, "scan_id": scan_id
            })

        update_payload = {
            "last_status": status,
            "last_run_at": completed_at,
            "last_error_code": err_code,
            "last_scan_id": scan_id,
            "worker_lease_until": None
        }
        if next_run_at:
            update_payload["next_run_at"] = next_run_at

        requests.patch(f"{SUPABASE_URL}/rest/v1/scan_schedules?id=eq.{schedule_id}", headers=db_headers, json=update_payload)

    return JSONResponse(status_code=200, content={"status": status})
