import os
import json
import logging
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
import requests


from api.utils.email_helper import send_email, EmailResult
from api.utils.pdf_generator import generate_pdf, MAX_EMAIL_PDF_BYTES


logger = logging.getLogger(__name__)
router = APIRouter()

SUPABASE_URL = os.environ.get("VITE_SUPABASE_URL") or os.environ.get("SUPABASE_URL")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY")

def get_db_headers():
    return {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Content-Type": "application/json"
    }

@router.post("/scheduled-report-email")
async def handle_scheduled_email(request: Request):
        # 1. Verify Signature
    body_bytes = await request.body()
    signature = request.headers.get("Upstash-Signature")

    if not signature:
        logger.error("Missing Upstash-Signature")
        return JSONResponse(status_code=400, content={"error": "Missing signature"})

    current_signing_key = os.environ.get("QSTASH_CURRENT_SIGNING_KEY")
    next_signing_key = os.environ.get("QSTASH_NEXT_SIGNING_KEY")
    if not current_signing_key or not next_signing_key:
        logger.error("QStash signature keys not configured")
        return JSONResponse(status_code=500, content={"error": "Server configuration error"})

    from qstash import Receiver
    receiver = Receiver(
        current_signing_key=current_signing_key,
        next_signing_key=next_signing_key,
    )

    from api.scheduling.router import APP_BASE_URL
    worker_url = f"{APP_BASE_URL.rstrip('/')}/api/internal/scheduled-report-email"

    try:
        receiver.verify(
            body=body_bytes.decode("utf-8"),
            signature=signature,
            url=worker_url
        )
    except Exception as e:
        logger.error("Invalid signature")
        return JSONResponse(status_code=401, content={"error": "Invalid signature"})

    # 2. Parse JSON
    try:
        body = json.loads(body_bytes)
        run_id = body.get("run_id")
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    if not run_id:
        return JSONResponse(status_code=400, content={"error": "missing_run_id"})

    import uuid
    try:
        uuid_obj = uuid.UUID(str(run_id))
        run_id = str(uuid_obj)
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "invalid_run_id"})

    db_headers = get_db_headers()

    # 3. Authoritative Run Lookup
    run_url = f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}&select=id,user_id,scan_id,schedule_id,status,email_status,email_lease_until"
    try:
        run_resp = requests.get(run_url, headers=db_headers, timeout=10.0)
    except Exception as e:
        logger.error(f"Email worker run lookup retry run={run_id} reason=run_lookup_exception")
        return JSONResponse(status_code=503, content={"status": "retry", "reason": "run_lookup_transient"})

    if run_resp.status_code != 200:
        logger.error(f"Email worker run lookup retry run={run_id} reason=run_lookup_http_error")
        return JSONResponse(status_code=503, content={"status": "retry", "reason": "run_lookup_transient"})

    try:
        run_json = run_resp.json()
    except Exception:
        logger.error(f"Email worker run lookup retry run={run_id} reason=run_lookup_invalid_json")
        return JSONResponse(status_code=503, content={"status": "retry", "reason": "run_lookup_transient"})

    if len(run_json) == 0:
        logger.info(f"Email worker run lookup retry run={run_id} reason=run_lookup_empty")
        return JSONResponse(status_code=503, content={"status": "retry", "reason": "run_lookup_pending"})

    run_row = run_json[0]
    email_status = run_row.get("email_status")

    if email_status in ["sent", "failed", "not_requested"]:
        logger.info(f"Email worker skipped run={run_id} reason=terminal_email_status status={email_status}")
        return JSONResponse(status_code=200, content={"status": "skipped", "reason": f"status_{email_status}"})

    user_id = run_row.get("user_id")
    scan_id = run_row.get("scan_id")

    if not scan_id:
        logger.error("No scan_id found for run")
        requests.patch(f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}", headers=db_headers, json={"email_status": "failed", "email_error_code": "missing_scan", "email_lease_until": None})
        return JSONResponse(status_code=200, content={"status": "failed", "reason": "missing_scan"})

    # Fetch scan
    scan_url = f"{SUPABASE_URL}/rest/v1/scans?id=eq.{scan_id}&select=*"
    scan_resp = requests.get(scan_url, headers=db_headers)
    if scan_resp.status_code != 200 or len(scan_resp.json()) == 0:
        logger.error("Scan not found")
        requests.patch(f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}", headers=db_headers, json={"email_status": "failed", "email_error_code": "missing_scan", "email_lease_until": None})
        return JSONResponse(status_code=200, content={"status": "failed", "reason": "missing_scan"})

    scan_row = scan_resp.json()[0]
    if scan_row.get("user_id") != user_id:
        logger.error("Scan user_id mismatch")
        requests.patch(f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}", headers=db_headers, json={"email_status": "failed", "email_error_code": "user_mismatch", "email_lease_until": None})
        return JSONResponse(status_code=200, content={"status": "failed", "reason": "user_mismatch"})

    if not scan_row.get("report_data"):
        logger.error("Scan missing report_data")
        requests.patch(f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}", headers=db_headers, json={"email_status": "failed", "email_error_code": "missing_report_data", "email_lease_until": None})
        return JSONResponse(status_code=200, content={"status": "failed", "reason": "missing_report_data"})

    # 4. Atomic Email Claim
    now_utc = datetime.now(timezone.utc)
    import urllib.parse
    current_time_str = urllib.parse.quote(now_utc.isoformat())
    lease_until_str = (now_utc + timedelta(minutes=5)).isoformat()

    # Claim if status is pending OR (status is sending AND lease expired)
    claim_query = f"?id=eq.{run_id}&or=(email_status.eq.pending,and(email_status.eq.sending,email_lease_until.lt.{current_time_str}))"
    try:
        claim_resp = requests.patch(
            f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs{claim_query}",
            headers={**db_headers, "Prefer": "return=representation"},
            json={
                "email_status": "sending",
                "email_lease_until": lease_until_str,
                "email_error_code": None
            },
            timeout=10.0
        )
        if claim_resp.status_code == 200:
            if len(claim_resp.json()) == 0:
                logger.info(f"Email worker skipped run={run_id} reason=lease_active")
                return JSONResponse(status_code=503, content={"status": "retry", "reason": "lease_active"})
        else:
            logger.error(f"Claim patch failed {claim_resp.status_code}")
            return JSONResponse(status_code=503, content={"status": "retry", "reason": "db_claim_error"})
    except Exception as e:
        logger.error(f"Claim patch exception: {type(e).__name__}")
        return JSONResponse(status_code=503, content={"status": "retry", "reason": "db_claim_exception"})

        # 5. Fetch Recipient via Supabase Admin Auth API
    try:
        auth_url = f"{SUPABASE_URL.rstrip('/')}/auth/v1/admin/users/{user_id}"
        user_resp = requests.get(auth_url, headers=db_headers, timeout=10.0)

        if user_resp.status_code != 200:
            if user_resp.status_code == 404:
                requests.patch(f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}", headers=db_headers, json={"email_status": "failed", "email_error_code": "recipient_missing", "email_lease_until": None})
                return JSONResponse(status_code=200, content={"status": "failed", "reason": "recipient_missing"})
            elif user_resp.status_code >= 500 or user_resp.status_code == 429:
                requests.patch(f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}", headers=db_headers, json={"email_status": "pending", "email_error_code": "account_lookup_transient", "email_lease_until": None})
                return JSONResponse(status_code=503, content={"status": "retry", "reason": "account_lookup_transient"})
            else:
                logger.error(f"Auth fetch failed {user_resp.status_code}")
                requests.patch(f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}", headers=db_headers, json={"email_status": "failed", "email_error_code": "account_lookup_error", "email_lease_until": None})
                return JSONResponse(status_code=200, content={"status": "failed", "reason": "account_lookup_error"})

        auth_user = user_resp.json()
    except Exception as e:
        logger.error(f"Auth fetch error: {type(e).__name__}")
        requests.patch(f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}", headers=db_headers, json={"email_status": "pending", "email_error_code": "account_lookup_transient", "email_lease_until": None})
        return JSONResponse(status_code=503, content={"status": "retry", "reason": "account_lookup_transient"})



    if not auth_user:
        requests.patch(f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}", headers=db_headers, json={"email_status": "failed", "email_error_code": "recipient_missing", "email_lease_until": None})
        return JSONResponse(status_code=200, content={"status": "failed", "reason": "recipient_missing"})

    recipient_email = auth_user.get('email')
    email_confirmed_at = auth_user.get('email_confirmed_at')



    if not recipient_email or not email_confirmed_at:
        requests.patch(f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}", headers=db_headers, json={"email_status": "failed", "email_error_code": "recipient_unverified", "email_lease_until": None})
        return JSONResponse(status_code=200, content={"status": "failed", "reason": "recipient_unverified"})

    # 6. Generate PDF
    try:
        report_data = scan_row["report_data"]
        pdf_bytes = generate_pdf(report_data, scan_created_at=scan_row.get("created_at"))
        if len(pdf_bytes) > MAX_EMAIL_PDF_BYTES:
            requests.patch(f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}", headers=db_headers, json={"email_status": "failed", "email_error_code": "pdf_too_large", "email_lease_until": None})
            return JSONResponse(status_code=200, content={"status": "failed", "reason": "pdf_too_large"})
    except Exception as e:
        logger.error(f"PDF generation failed: {type(e).__name__}")
        requests.patch(f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}", headers=db_headers, json={"email_status": "failed", "email_error_code": "pdf_generation_failed", "email_lease_until": None})
        return JSONResponse(status_code=200, content={"status": "failed", "reason": "pdf_generation_failed"})

    # 7. Safe Attachment & Content
    import base64
    import re

    target_url = scan_row.get("target_url") or "unknown"
    safe_target = re.sub(r'[^a-zA-Z0-9.\-]', '_', target_url).strip('_')
    if not safe_target:
        safe_target = "report"
    filename = f"urlscanonline-report-{safe_target}.pdf"

    encoded_pdf = base64.b64encode(pdf_bytes).decode('utf-8')
    attachments = [{"filename": filename, "content": encoded_pdf, "content_type": "application/pdf"}]

    scan_mode_display = "Advanced" if report_data.get("scan_mode") == "active" else "Basic"
    subject = f"Your scheduled security report is ready - {target_url}"

    html = f"""
    <p>Your {scan_mode_display} scheduled security scan for <strong>{target_url}</strong> has completed.</p>
    <p>The PDF report is attached to this email.</p>
    <p>You can view your full scan history anytime in URLScanOnline.</p>
    """

    idempotency_key = f"scheduled-report-{run_id}"

    # 8. Send Email
    result: EmailResult = send_email(
        to=recipient_email,
        subject=subject,
        html=html,
        from_email="URLScanOnline Reports <contact@urlscanonline.com>",
        attachments=attachments,
        idempotency_key=idempotency_key
    )

    # 9. Handle Result
    if result.success:
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}",
            headers=db_headers,
            json={
                "email_status": "sent",
                "email_sent_at": datetime.now(timezone.utc).isoformat(),
                "email_error_code": None,
                "email_lease_until": None
            }
        )
        return JSONResponse(status_code=200, content={"status": "sent"})
    else:
        if result.is_transient:
            requests.patch(
                f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}",
                headers=db_headers,
                json={
                    "email_status": "pending",
                    "email_lease_until": None,
                    "email_error_code": result.error_category
                }
            )
            # Return 503 so QStash retries
            return JSONResponse(status_code=503, content={"status": "retry", "reason": result.error_category})
        else:
            requests.patch(
                f"{SUPABASE_URL}/rest/v1/scheduled_scan_runs?id=eq.{run_id}",
                headers=db_headers,
                json={
                    "email_status": "failed",
                    "email_lease_until": None,
                    "email_error_code": result.error_category
                }
            )
            return JSONResponse(status_code=200, content={"status": "failed", "reason": result.error_category})











