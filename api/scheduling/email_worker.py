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
    import urllib.parse
    from xml.sax.saxutils import escape

    target_url = scan_row.get("target_url") or report_data.get("target_url") or "unknown"
    parsed_url = urllib.parse.urlparse(target_url)
    hostname = parsed_url.hostname or target_url
    safe_host = re.sub(r'[^a-zA-Z0-9.\-]', '_', hostname).strip('_').lower()
    if not safe_host:
        safe_host = "report"

    dt_str = "undated"
    if scan_row.get("created_at"):
        dt_str = scan_row["created_at"][:10]
    elif report_data.get("scan_start"):
        dt_str = report_data["scan_start"][:10]

    scan_mode_raw = report_data.get("scan_mode", "passive")
    scan_mode_display = "Advanced" if scan_mode_raw == "active" else "Basic"
    scan_mode_lower = scan_mode_display.lower()

    filename = f"{safe_host}-{scan_mode_lower}-security-report-{dt_str}.pdf"

    encoded_pdf = base64.b64encode(pdf_bytes).decode('utf-8')
    attachments = [{"filename": filename, "content": encoded_pdf, "content_type": "application/pdf"}]

    score_val = report_data.get("score", "N/A")
    # subject must be safe from CRLF injection
    safe_hostname = hostname.replace('\n', '').replace('\r', '')
    safe_score_val = str(score_val).replace('\n', '').replace('\r', '')
    subject = f"URLScanOnline Report \u2014 {safe_hostname} \u2014 {safe_score_val}/100"

    # Severity counting
    severity_counts = {}
    actionable_severities = ["Critical", "High", "Medium", "Low"]
    informational_severities = ["Informational", "Info"]
    inconclusive_severities = ["Inconclusive", "Skipped"]
    all_known_severities = actionable_severities + informational_severities + inconclusive_severities + ["Passed"]

    for f in report_data.get("findings", []):
        raw_sev = str(f.get("severity", "Info")).strip()
        sev = raw_sev.title()
        if sev in ["Info", "Informational"]:
            sev = "Informational"
        elif sev in ["Skipped", "Inconclusive"]:
            sev = "Inconclusive"
        elif sev not in all_known_severities:
            sev = "Inconclusive"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    issues_count = sum(severity_counts.get(s, 0) for s in actionable_severities)
    passed_count = severity_counts.get("Passed", 0)
    info_count = sum(severity_counts.get(s, 0) for s in informational_severities)
    inconclusive_count = sum(severity_counts.get(s, 0) for s in inconclusive_severities)

    top_finding = None
    for sev in actionable_severities:
        if severity_counts.get(sev, 0) > 0 and not top_finding:
            for f in report_data.get("findings", []):
                raw_fsev = str(f.get("severity", "Info")).title()
                if raw_fsev == "Info": raw_fsev = "Informational"
                if raw_fsev == sev:
                    top_finding = f
                    break

    top_finding_html = ""
    if top_finding:
        fname = escape(str(top_finding.get("name", "Unknown")))
        fsev = escape(str(top_finding.get("severity", "Unknown")))
        top_finding_html = f"""
        <h3 style="color: #2c3e50; margin-top: 20px;">Top Finding</h3>
        <p><strong>{fname}</strong> &mdash; {fsev}</p>
        """

    from api.scheduling.router import APP_BASE_URL
    history_url = f"{APP_BASE_URL.rstrip('/')}/history"
    scan_id_val = run_row.get('scan_id')
    full_report_url = f"{history_url}/{scan_id_val}?from=history" if scan_id_val else history_url

    esc_hostname = escape(hostname)
    esc_scan_mode = escape(scan_mode_display)
    esc_score = escape(str(score_val))

    html = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; color: #333; line-height: 1.5;">
        <h2 style="color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 10px;">URLScannerOnline</h2>
        <p style="font-size: 16px;">Your scheduled security scan is complete.</p>

        <table style="width: 100%; text-align: left; margin: 20px 0; border-collapse: collapse;">
            <tr><th style="padding: 8px 0; border-bottom: 1px solid #eee; width: 40%;">Target</th><td style="padding: 8px 0; border-bottom: 1px solid #eee;">{esc_hostname}</td></tr>
            <tr><th style="padding: 8px 0; border-bottom: 1px solid #eee;">Scan Type</th><td style="padding: 8px 0; border-bottom: 1px solid #eee;">{esc_scan_mode}</td></tr>
            <tr><th style="padding: 8px 0;">Security Score</th><td style="padding: 8px 0;"><strong>{esc_score}/100</strong></td></tr>
        </table>

        <h3 style="color: #2c3e50; margin-top: 25px;">Summary</h3>
        <ul style="list-style: none; padding: 0;">
            <li><strong>Issues Found:</strong> {issues_count}</li>
            <li><strong>Informational:</strong> {info_count}</li>
            {f"<li><strong>Inconclusive:</strong> {inconclusive_count}</li>" if inconclusive_count > 0 else ""}
            <li><strong>Passed:</strong> {passed_count}</li>
        </ul>
        <table style="width: 100%; max-width: 300px; margin-bottom: 20px;">
            <tr><td style="color: #8b0000;">Critical:</td><td>{severity_counts.get('Critical', 0)}</td></tr>
            <tr><td style="color: #cc0000;">High:</td><td>{severity_counts.get('High', 0)}</td></tr>
            <tr><td style="color: #e68a00;">Medium:</td><td>{severity_counts.get('Medium', 0)}</td></tr>
            <tr><td style="color: #0000cc;">Low:</td><td>{severity_counts.get('Low', 0)}</td></tr>
        </table>

        {top_finding_html}

        <p style="margin-top: 25px;">The complete security assessment is attached as a PDF, including prioritized recommendations and technical details.</p>

        <div style="margin-top: 30px;">
            <a href="{full_report_url}" style="display: inline-block; padding: 10px 20px; background-color: #0f172a; color: white; text-decoration: none; border-radius: 6px; font-weight: 500; margin-right: 10px;">View Full Report</a>
            <a href="{history_url}" style="display: inline-block; padding: 10px 20px; background-color: #f8f9fa; color: #333; text-decoration: none; border-radius: 6px; border: 1px solid #ddd; font-weight: 500;">View Scan History</a>
        </div>

        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #64748b;">
            <strong>URLScannerOnline</strong><br />
            Automated security assessment
        </div>
    </div>
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











