import os
import json
import logging
import urllib3
from dataclasses import dataclass
from typing import Optional, List

logger = logging.getLogger(__name__)

@dataclass
class EmailResult:
    success: bool
    status_code: Optional[int] = None
    is_transient: bool = False
    error_category: Optional[str] = None
    provider_error_type: Optional[str] = None

def send_email(to: str, subject: str, html: str, from_email: str = "URLScannerOnline Contact <contact@urlscanonline.com>", attachments: List[dict] = None, idempotency_key: str = None) -> EmailResult:
    resend_key = os.environ.get("RESEND_API_KEY")
    if not resend_key:
        logger.error("Email configuration missing.")
        return EmailResult(success=False, is_transient=False, error_category="configuration_missing")
        
    payload = {
        "from": from_email,
        "to": [to],
        "subject": subject,
        "html": html
    }
    
    if attachments:
        payload["attachments"] = attachments
        
    headers = {
        "Authorization": f"Bearer {resend_key}",
        "Content-Type": "application/json",
        "User-Agent": "URLScanOnline/1.0"
    }
    
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key

    try:
        http = urllib3.PoolManager(timeout=10.0)
        response = http.request(
            "POST",
            "https://api.resend.com/emails",
            body=json.dumps(payload).encode('utf-8'),
            headers=headers
        )
        status_code = response.status
        
        if not (200 <= status_code < 300):
            provider_error_type = None
            if response.data:
                try:
                    resp_json = json.loads(response.data.decode('utf-8'))
                    provider_error_type = resp_json.get("name") or resp_json.get("type")
                except Exception:
                    pass
            
            is_transient = False
            error_category = "provider_permanent"
            
            if 500 <= status_code < 600:
                is_transient = True
                error_category = "provider_transient"
            elif status_code == 429:
                if provider_error_type == "rate_limit_exceeded":
                    is_transient = True
                    error_category = "rate_limit_exceeded"
                elif provider_error_type in ["daily_quota_exceeded", "monthly_quota_exceeded"]:
                    is_transient = False
                    error_category = "quota_exceeded"
                else:
                    # Unknown 429 must be transient to prevent discarding otherwise deliverable reports
                    is_transient = True
                    error_category = "provider_transient"
            elif status_code == 409:
                if provider_error_type in ["concurrent_idempotent_requests", "resource_locked"]:
                    is_transient = True
                    error_category = "concurrent_transient"
                else:
                    error_category = "invalid_idempotent_request"
            elif provider_error_type in ["concurrent_idempotent_requests", "resource_locked", "rate_limit_exceeded"]:
                # Catch-all for transient provider types that might appear under other 4xx codes
                is_transient = True
                error_category = "provider_transient"

            logger.error(f"Email delivery failed. Status: {status_code} Category: {error_category} Type: {provider_error_type}")
            return EmailResult(success=False, status_code=status_code, is_transient=is_transient, error_category=error_category, provider_error_type=provider_error_type)
            
        logger.info("Email sent successfully.")
        return EmailResult(success=True, status_code=status_code)
        
    except urllib3.exceptions.TimeoutError:
        logger.error("Email delivery timeout.")
        return EmailResult(success=False, is_transient=True, error_category="network_timeout")
    except urllib3.exceptions.RequestError:
        logger.error("Email delivery network error.")
        return EmailResult(success=False, is_transient=True, error_category="network_error")
    except Exception:
        logger.error("Email delivery unexpected error.")
        return EmailResult(success=False, is_transient=False, error_category="internal_error")