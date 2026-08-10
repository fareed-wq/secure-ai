import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from typing import List
from urllib.parse import urlparse

from fastapi import FastAPI, Request
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
    TLSCipherStrengthModule,
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
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health_check() -> dict:
    return {"status": "online"}





class ScanRequest(BaseModel):
    url: str
    probe_subdomains: bool = False

    @field_validator("url")
    @classmethod
    def _normalize(cls, v: str) -> str:
        return normalize_url(v)


class BatchScanRequest(BaseModel):
    urls: List[str]

    @field_validator("urls")
    @classmethod
    def _normalize_all(cls, v: List[str]) -> List[str]:
        return [normalize_url(u) for u in v]





# --- PLUGIN ARCHITECTURE ---



# --- MODULES ---















# Engine Registry

def scan_url(url: str, probe_subdomains: bool = False) -> dict:
    """Compatibility wrapper to allow patching REGISTERED_MODULES via api.index"""
    original = orchestrator_module.REGISTERED_MODULES
    orchestrator_module.REGISTERED_MODULES = REGISTERED_MODULES
    try:
        return _scan_url(url, probe_subdomains)
    finally:
        orchestrator_module.REGISTERED_MODULES = original




@app.post("/api/scan")
@app.post("/scan")
async def scan_single(req: ScanRequest, request: Request):
    ip = get_client_ip(request)
    if not check_rate_limit(ip):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded. Maximum 10 scans per minute allowed.", "status": 429},
            headers={"Retry-After": "60", "X-RateLimit-Limit": "10", "X-RateLimit-Remaining": "0"}
        )
    try:
        return await asyncio.wait_for(asyncio.to_thread(scan_url, req.url, req.probe_subdomains), timeout=45.0)
    except Exception as e:
        return JSONResponse(status_code=200, content=get_waf_fallback_payload(req.url))


@app.post("/api/scan/batch")
@app.post("/scan/batch")
async def scan_batch(req: BatchScanRequest, request: Request):
    ip = get_client_ip(request)
    if not check_rate_limit(ip):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded. Maximum 10 scans per minute allowed.", "status": 429},
            headers={"Retry-After": "60", "X-RateLimit-Limit": "10", "X-RateLimit-Remaining": "0"}
        )
    workers = min(10, len(req.urls)) or 1

    def process_batch():
        results = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(scan_url, u): u for u in req.urls}
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


