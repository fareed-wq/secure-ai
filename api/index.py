import requests
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from typing import List
from urllib.parse import urlparse

from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, field_validator
import urllib3
# Disable insecure request warnings for passive SSL probing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from api.scanner.core import Config, IN_MEMORY_LIMITS, get_client_ip, check_rate_limit
from api.scanner.data.dictionaries import REMEDIATION_SNIPPETS, COMPLIANCE_MAP, IMPACT_MAP
from api.scanner.transport import (
    is_public_hostname,
    BlockAllCookies,
    get_http_session,
    safe_request,
    get_all_headers,
    get_header,
)
from api.scanner.base import ScannerModule
from api.scanner.modules.headers import TechFingerprintModule, CORSModule, PermissionsPolicyModule
from api.scanner.modules.discovery import (
    ExposedFilesModule,
    InformationDisclosureModule,
    RobotsTxtModule,
    SitemapModule,
    SecurityTxtModule,
)
from api.scanner.modules.dns import DNSCAAModule, DNSEmailSecurityModule
from api.scanner.modules.http_security import (
    AdvancedCookieModule,
    HTTPSRedirectModule,
    SecurityHeadersModule,
    AdvancedSecurityHeadersModule,
)
from api.scanner.modules.network_checks import (
    SubdomainProbingModule,
    SubdomainTakeoverModule,
    GraphQLIntrospectionModule,
    VerboseStackTraceModule,
)
from api.scanner.modules.tls import EnhancedTLSModule
from api.scanner.modules.content import (
    MixedContentModule,
)
from api.scanner.data.registry import DOMAIN_MAP, REGISTERED_MODULES
from api.scanner.fallback import get_waf_fallback_payload
from api.scanner.scoring import calculate_score
from api.scanner.orchestrator import scan_url as _scan_url
import api.scanner.orchestrator as orchestrator_module
from api.scanner.scoring import calculate_score
from api.scanner.metadata import (
    check_liveness,
    get_ip_location,
    _parse_whois_date,
    _get_whois_data,
    get_metadata,
)
from api.scanner.validation import CANONICAL_URL_REGEX, canonicalize_url, normalize_url







app = FastAPI(title="Website Security Posture Checker (Advanced Modular)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://www.urlscanonline.com",
        "https://urlscanonline.com",
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5176"
    ],
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health_check() -> dict:
    return {"status": "online"}





class ScanRequest(BaseModel):
    url: str
    probe_subdomains: bool = False
    scan_mode: str = "passive"
    report_mode: str = "simple"

    @field_validator("url")
    @classmethod
    def _normalize(cls, v: str) -> str:
        return normalize_url(v)

    @field_validator("report_mode")
    @classmethod
    def _validate_report_mode(cls, v: str) -> str:
        v = v.lower()
        if v not in ["simple", "technical"]:
            raise ValueError("report_mode must be 'simple' or 'technical'")
        return v





class BatchScanRequest(BaseModel):
    urls: List[str]

    @field_validator("urls")
    @classmethod
    def _normalize_all(cls, v: List[str]) -> List[str]:
        return [normalize_url(u) for u in v]





import os
import json

class ContactRequest(BaseModel):
    form_type: str = "unified"
    topic: str = ""
    email: str = ""
    message: str = ""
    url: str = ""

@app.post("/api/contact")
async def handle_contact(req: ContactRequest, request: Request):
    ip = get_client_ip(request)
    if not check_rate_limit(ip):
        return JSONResponse(status_code=429, content={"error": "Rate limit exceeded. Please try again later."})

    resend_key = os.environ.get("RESEND_API_KEY")
    if not resend_key:
        return JSONResponse(status_code=500, content={"error": "Email provider not configured."})

    subject = f"URLScannerOnline Contact: {req.topic}"

    html_content = f"""
    <p><strong>Topic:</strong> {req.topic}</p>
    <p><strong>Email:</strong> {req.email}</p>
    <p><strong>Website URL:</strong> {req.url or 'N/A'}</p>
    <p><strong>Message:</strong><br/>{req.message}</p>
    """

    try:
        http = urllib3.PoolManager()
        response = http.request(
            "POST",
            "https://api.resend.com/emails",
            body=json.dumps({
                "from": "URLScannerOnline Contact <contact@urlscanonline.com>",
                "to": ["contact@urlscanonline.com"],
                "subject": subject,
                "html": html_content
            }).encode('utf-8'),
            headers={
                "Authorization": f"Bearer {resend_key}",
                "Content-Type": "application/json"
            }
        )
        if response.status >= 400:
            logger.error(f"Resend API error: {response.data}")
            return JSONResponse(status_code=500, content={"error": "Failed to send email via provider."})

        return {"status": "success"}
    except Exception as e:
        logger.error(f"Email delivery error: {e}")
        return JSONResponse(status_code=500, content={"error": "Internal server error during email delivery."})

# --- PLUGIN ARCHITECTURE ---



# --- MODULES ---















# Engine Registry

def scan_url(url: str, probe_subdomains: bool = False, scan_mode: str = "passive") -> dict:
    """Compatibility wrapper to allow patching REGISTERED_MODULES via api.index"""
    original = orchestrator_module.REGISTERED_MODULES
    orchestrator_module.REGISTERED_MODULES = REGISTERED_MODULES
    try:
        return _scan_url(url, probe_subdomains, scan_mode)
    finally:
        orchestrator_module.REGISTERED_MODULES = original

from api.auth.entitlements import get_current_user, require_current_user, Entitlements, check_guest_quota, consume_guest_quota, check_free_quota, consume_free_quota
from api.scanner.core import acquire_scan_lease, release_scan_lease, acquire_guest_lease, release_guest_lease
from api.admin import admin_router

app.include_router(admin_router)

@app.post("/api/scan")
@app.post("/scan")
async def scan_single(req: ScanRequest, request: Request, user: dict = Depends(get_current_user)):
    ip = get_client_ip(request)
    entitlements = Entitlements(user)

    if entitlements.status == "suspended":
        return JSONResponse(status_code=403, content={"error": "Account suspended.", "status": 403})

    if req.scan_mode == "advanced" and not entitlements.can_advanced_scan:
        return JSONResponse(status_code=403, content={"error": "Advanced scanning is not available for your current plan.", "status": 403})

    if entitlements.is_admin == True:
        pass
    elif entitlements.plan == "guest":
        quota = check_guest_quota(ip)
        if quota["quota_remaining"] <= 0:
            return JSONResponse(status_code=429, content={"error": "You've used your 3 free Guest scans for this week.", "status": 429})
    elif entitlements.plan == "free":
        quota = check_free_quota(entitlements.user_id)
        if quota["quota_remaining"] <= 0:
            return JSONResponse(status_code=429, content={"error": "You've used your 5 free scans for this week.", "status": 429})

    if not check_rate_limit(ip):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded. Maximum 10 scans per minute allowed.", "status": 429},
            headers={"Retry-After": "60", "X-RateLimit-Limit": "10", "X-RateLimit-Remaining": "0"}
        )

    from api.scanner.orchestrator import validate_scan_target
    validation_error = validate_scan_target(req.url, req.scan_mode)
    if validation_error:
        # Return 200 with the error dict (as scanner originally did) without consuming quota
        return JSONResponse(status_code=200, content=validation_error)

    try:
        lease_id = acquire_scan_lease(is_admin=entitlements.is_admin)
    except RuntimeError as e:
        return JSONResponse(
            status_code=503,
            content={"error": "Scanner capacity status unknown. Please try again later.", "status": 503}
        )

    if not lease_id:
        return JSONResponse(
            status_code=429,
            content={"error": "Global scanner capacity is full. Please try again in a few seconds.", "status": 429}
        )

    has_guest_lease = False
    try:
        if entitlements.is_admin == True:
            pass
        elif entitlements.plan == "guest":
            has_guest_lease = acquire_guest_lease(ip)
            if not has_guest_lease:
                return JSONResponse(status_code=429, content={"error": "You already have a scan in progress.", "status": 429})

            # Consume quota only after all validation and leases are acquired
            if not consume_guest_quota(ip):
                return JSONResponse(status_code=429, content={"error": "You've used your 3 free Guest scans for this week.", "status": 429})
        elif entitlements.plan == "free":
            # Free user is constrained by global concurrency, not single-ip limit, but they still consume quota
            if not consume_free_quota(entitlements.user_id):
                return JSONResponse(status_code=429, content={"error": "You've used your 5 free scans for this week.", "status": 429})
        # Note: If plan == "professional" or is_admin == True, no quota restriction is applied here

        result = await asyncio.wait_for(asyncio.to_thread(scan_url, req.url, req.probe_subdomains, req.scan_mode), timeout=55.0)

        import datetime
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result["created_at"] = now_iso
        result["report_mode"] = req.report_mode

        # Automatic Scan History Persistence for authenticated users
        if entitlements.plan != "guest" and user and user.get("sub") and result.get("status") != "failed":
            from api.auth.entitlements import SUPABASE_URL, SUPABASE_SECRET_KEY
            if SUPABASE_URL and SUPABASE_SECRET_KEY:
                import requests
                import datetime
                import logging
                headers = {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
                    "Content-Type": "application/json",
                    "Prefer": "return=representation"
                }

                # Make sure the scan_mode is recorded in report_data so PDF generator works correctly
                if "scan_mode" not in result:
                    result["scan_mode"] = req.scan_mode

                payload = {
                    "user_id": user["sub"],
                    "target_url": result.get("url", req.url),
                    "score": result.get("score", 0),
                    "report_data": result,
                    "created_at": now_iso
                }
                try:
                    db_res = requests.post(f"{SUPABASE_URL}/rest/v1/scans", headers=headers, json=payload, timeout=10)
                    if db_res.status_code in (200, 201) and db_res.json():
                        result["id"] = db_res.json()[0].get("id")
                        result["history_saved"] = True
                    else:
                        logging.error(f"Failed to persist scan history. Status code: {db_res.status_code}")
                        result["history_saved"] = False
                except Exception as e:
                    logging.error("Exception occurred while persisting scan history.")
                    result["history_saved"] = False

        return result
    except Exception as e:
        return JSONResponse(status_code=200, content=get_waf_fallback_payload(req.url))
    finally:
        release_scan_lease(lease_id, is_admin=entitlements.is_admin)
        if has_guest_lease:
            release_guest_lease(ip)


@app.get("/api/quota")
def get_quota(request: Request, user: dict = Depends(get_current_user)):
    entitlements = Entitlements(user)
    if entitlements.is_admin == True:
        return {
            "plan": "free",
            "role": "admin",
            "is_unlimited": True,
            "quota_limit": None,
            "quota_used": None,
            "quota_remaining": None
        }
    if entitlements.plan == "guest":
        ip = get_client_ip(request)
        quota = check_guest_quota(ip)
        return {"plan": "guest", "quota": quota}
    elif entitlements.plan == "free":
        quota = check_free_quota(entitlements.user_id)
        return {"plan": "free", "quota": quota}
    return {"plan": entitlements.plan, "unlimited": entitlements.is_unlimited}


@app.post("/api/scan/batch")
@app.post("/scan/batch")
async def scan_batch(req: BatchScanRequest, request: Request, user: dict = Depends(get_current_user)):
    entitlements = Entitlements(user)

    if entitlements.status == "suspended":
        return JSONResponse(status_code=403, content={"error": "Account suspended.", "status": 403})

    if entitlements.plan == "guest":
        return JSONResponse(status_code=403, content={"error": "Batch scanning requires an account.", "status": 403})

    ip = get_client_ip(request)
    if not check_rate_limit(ip):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded. Maximum 10 scans per minute allowed.", "status": 429},
            headers={"Retry-After": "60", "X-RateLimit-Limit": "10", "X-RateLimit-Remaining": "0"}
        )
    workers = min(10, len(req.urls)) or 1

    def process_one_target(u):
        try:
            lease_id = acquire_scan_lease(is_admin=entitlements.is_admin)
        except RuntimeError:
            return {"error": "Scanner capacity status unknown. Please try again later.", "status": 503, "url": u}

        if not lease_id:
            return {"error": "Global scanner capacity is full. Please try again in a few seconds.", "status": 429, "url": u}

        try:
            return scan_url(u)
        finally:
            release_scan_lease(lease_id, is_admin=entitlements.is_admin)

    def process_batch():
        results = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(process_one_target, u): u for u in req.urls}
            for future in as_completed(futures):
                u = futures[future]
                try:
                    results.append(future.result())
                except Exception:
                    results.append(get_waf_fallback_payload(u))
        return results

    try:
        results = await asyncio.wait_for(asyncio.to_thread(process_batch), timeout=55.0)
        return {"results": results}
    except Exception:
        return JSONResponse(status_code=200, content={"results": [get_waf_fallback_payload(u) for u in req.urls]})






from api.scanner.compare import compare_reports

@app.get("/api/scans/compare")
def compare_user_scans(scan_id_1: str, scan_id_2: str, user: dict = Depends(require_current_user)):
    entitlements = Entitlements(user)

    # Restrict to Admin (and eventually Pro). Block Free/Guest.
    if not entitlements.is_admin and entitlements.plan != "professional":
        return JSONResponse(status_code=403, content={"error": "Scan comparison requires a Professional plan or Admin access."})

    import os
    import requests
    from fastapi import HTTPException

    supabase_url = os.environ.get('SUPABASE_URL', '').rstrip('/')
    supabase_key = os.environ.get('SUPABASE_SECRET_KEY', '')
    if not supabase_url or not supabase_key:
        raise HTTPException(status_code=500, detail="Supabase credentials not configured.")

    headers = {
        "apikey": supabase_key,
        "Authorization": f"Bearer {supabase_key}",
        "Content-Type": "application/json"
    }

    # Verify ownership of scan 1
    query_1 = f"{supabase_url}/rest/v1/scans?id=eq.{scan_id_1}&select=*"
    if not entitlements.is_admin:
        query_1 += f"&user_id=eq.{user['sub']}"
    resp1 = requests.get(query_1, headers=headers)
    if resp1.status_code != 200 or not resp1.json():
        raise HTTPException(status_code=404, detail="Scan 1 not found or unauthorized.")
    scan1 = resp1.json()[0]

    # Verify ownership of scan 2
    query_2 = f"{supabase_url}/rest/v1/scans?id=eq.{scan_id_2}&select=*"
    if not entitlements.is_admin:
        query_2 += f"&user_id=eq.{user['sub']}"
    resp2 = requests.get(query_2, headers=headers)
    if resp2.status_code != 200 or not resp2.json():
        raise HTTPException(status_code=404, detail="Scan 2 not found or unauthorized.")
    scan2 = resp2.json()[0]

    # Sort scans chronologically
    s1_time = scan1.get("created_at", "")
    s2_time = scan2.get("created_at", "")
    if s1_time and s2_time and s1_time > s2_time:
        scan1, scan2 = scan2, scan1

    try:
        result = compare_reports(scan1, scan2)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
