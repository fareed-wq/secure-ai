import os
import time
import requests
import logging
from typing import Optional
from fastapi import Request, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt import PyJWKClient

logger = logging.getLogger(__name__)

SUPABASE_URL = os.environ.get("VITE_SUPABASE_URL") or os.environ.get("SUPABASE_URL")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY")

security = HTTPBearer(auto_error=False)

# Initialize PyJWKClient to fetch and cache public keys from Supabase JWKS endpoint
if SUPABASE_URL:
    jwks_url = f"{SUPABASE_URL.rstrip('/')}/auth/v1/.well-known/jwks.json"
    jwks_client = PyJWKClient(jwks_url, cache_keys=True, cache_jwk_set=True, lifespan=3600)
else:
    jwks_client = None

def verify_jwt(token: str) -> dict:
    if not SUPABASE_URL:
        raise HTTPException(status_code=500, detail="Missing SUPABASE_URL configuration.")
    if not jwks_client:
        raise HTTPException(status_code=500, detail="JWKS client not initialized.")

    try:
        # Extract the unverified header to check alg and kid
        unverified_header = jwt.get_unverified_header(token)
        alg = unverified_header.get("alg")
        
        # Enforce ES256 since project is confirmed to use asymmetric signing
        if alg != "ES256":
            raise HTTPException(status_code=401, detail="Unsupported signing algorithm.")

        # Dynamically fetch the signing key from the JWKS cache
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        
        payload = jwt.decode(
            token,
            key=signing_key.key,
            algorithms=["ES256"],
            audience="authenticated"
        )
        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except jwt.PyJWKClientError as e:
        logger.error(f"JWKS Error: {e}")
        raise HTTPException(status_code=401, detail="Unable to verify token signature.")
    except jwt.InvalidTokenError as e:
        logger.error(f"JWT Validation failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token.")
    except Exception as e:
        logger.error(f"Unexpected authentication error: {e}")
        raise HTTPException(status_code=500, detail="Authentication server error.")

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)) -> Optional[dict]:
    if not credentials:
        return None
    return verify_jwt(credentials.credentials)

def require_current_user(user: Optional[dict] = Security(get_current_user)) -> dict:
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user

def get_user_role(user_id: str) -> str:
    """Fetch user role securely using the Secret Key bypassing RLS."""
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        logger.warning("Missing Supabase Secret Key; defaulting to 'user'.")
        return "user"
    
    url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/user_roles?user_id=eq.{user_id}&select=role"
    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=2.0)
        if resp.status_code == 200:
            data = resp.json()
            if len(data) > 0:
                return data[0].get("role", "user")
    except Exception as e:
        logger.error(f"Failed to fetch user role: {e}")
    return "user"

def require_admin(user: dict = Security(require_current_user)) -> dict:
    user_id = user.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid user subject.")
        
    role = get_user_role(user_id)
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required.")
        
    user["role"] = "admin"
    return user

class Entitlements:
    def __init__(self, user: Optional[dict]):
        self.user_id = user.get("sub") if user else None
        self.role = get_user_role(self.user_id) if self.user_id else "guest"
        self.plan = "free" if self.user_id else "guest"

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def can_basic_scan(self) -> bool:
        return True
        
    @property
    def can_advanced_scan(self) -> bool:
        return self.is_admin or self.plan in ["free", "professional"]

    @property
    def can_save_scan(self) -> bool:
        return self.is_admin or self.plan in ["free", "professional"]

    @property
    def can_share_scan(self) -> bool:
        return self.is_admin or self.plan in ["free", "professional"]

    @property
    def can_export_report(self) -> bool:
        return self.is_admin or self.plan in ["free", "professional"]
        
    @property
    def can_download_pdf(self) -> bool:
        return self.is_admin or self.plan in ["free", "professional"]

    @property
    def can_view_scan_history(self) -> bool:
        return self.is_admin or self.plan in ["free", "professional"]

    @property
    def is_unlimited(self) -> bool:
        return self.is_admin

def get_entitlements(user: Optional[dict] = Security(get_current_user)) -> Entitlements:
    return Entitlements(user)

def get_monday_utc_boundaries() -> tuple[int, int]:
    """Returns (current_week_start_timestamp, next_week_start_timestamp) for Monday 00:00 UTC."""
    now = int(time.time())
    days_since_thursday = now // 86400
    current_week = (days_since_thursday - 3) // 7
    week_start = (current_week * 7 + 3) * 86400
    next_week_start = ((current_week + 1) * 7 + 3) * 86400
    return week_start, next_week_start

def check_guest_quota(ip: str) -> dict:
    """
    Fixed calendar week quota (Monday 00:00 UTC).
    Returns dict: quota_limit, quota_used, quota_remaining, reset_at
    """
    limit = 3
    week_start, next_week_start = get_monday_utc_boundaries()

    redis_url = os.environ.get("UPSTASH_REDIS_REST_URL")
    redis_token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    
    if not redis_url or not redis_token:
        return {"quota_limit": limit, "quota_used": limit, "quota_remaining": 0, "reset_at": next_week_start}

    key = f"guest_quota:{ip}:{week_start}"
    headers = {"Authorization": f"Bearer {redis_token}"}
    
    try:
        resp = requests.get(f"{redis_url}/get/{key}", headers=headers, timeout=1.0)
        if resp.status_code == 200:
            result = resp.json().get("result")
            used = int(result) if result else 0
        else:
            used = limit
    except Exception:
        used = limit

    remaining = max(0, limit - used)
    return {
        "quota_limit": limit,
        "quota_used": used,
        "quota_remaining": remaining,
        "reset_at": next_week_start
    }

def consume_guest_quota(ip: str) -> bool:
    """Atomic consume guest quota. Should be called ONLY after scan executes successfully."""
    limit = 3
    week_start, next_week_start = get_monday_utc_boundaries()
    ttl_seconds = next_week_start - int(time.time())
    if ttl_seconds <= 0:
        ttl_seconds = 604800 # Fallback

    key = f"guest_quota:{ip}:{week_start}"
    
    redis_url = os.environ.get("UPSTASH_REDIS_REST_URL")
    redis_token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    
    if not redis_url or not redis_token:
        return False 

    lua_script = """
    local current = redis.call('GET', KEYS[1])
    if current and tonumber(current) >= tonumber(ARGV[1]) then
        return -1
    end
    local new_val = redis.call('INCR', KEYS[1])
    if tonumber(new_val) == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[2])
    end
    return new_val
    """
    headers = {"Authorization": f"Bearer {redis_token}"}
    payload = ["EVAL", lua_script, 1, key, limit, ttl_seconds]
    try:
        resp = requests.post(redis_url, json=payload, headers=headers, timeout=1.5)
        if resp.status_code == 200:
            result = resp.json().get("result")
            if result == -1:
                return False
            return True
    except Exception as e:
        logger.error(f"Redis quota consume failed: {e}")
        return False
    return False

def check_free_quota(user_id: str) -> dict:
    """
    Fixed calendar week quota (Monday 00:00 UTC) for Free users.
    Returns dict: quota_limit, quota_used, quota_remaining, reset_at
    """
    limit = 5
    week_start, next_week_start = get_monday_utc_boundaries()

    redis_url = os.environ.get("UPSTASH_REDIS_REST_URL")
    redis_token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    
    if not redis_url or not redis_token:
        # FAIL CLOSED
        return {"quota_limit": limit, "quota_used": limit, "quota_remaining": 0, "reset_at": next_week_start}

    key = f"free_quota:{user_id}:{week_start}"
    headers = {"Authorization": f"Bearer {redis_token}"}
    
    try:
        resp = requests.get(f"{redis_url}/get/{key}", headers=headers, timeout=1.0)
        if resp.status_code == 200:
            result = resp.json().get("result")
            used = int(result) if result else 0
        else:
            used = limit
    except Exception:
        used = limit

    remaining = max(0, limit - used)
    return {
        "quota_limit": limit,
        "quota_used": used,
        "quota_remaining": remaining,
        "reset_at": next_week_start
    }

def consume_free_quota(user_id: str) -> bool:
    """Atomic consume free quota. Should be called ONLY after scan executes successfully."""
    limit = 5
    week_start, next_week_start = get_monday_utc_boundaries()
    ttl_seconds = next_week_start - int(time.time())
    if ttl_seconds <= 0:
        ttl_seconds = 604800 # Fallback

    key = f"free_quota:{user_id}:{week_start}"
    
    redis_url = os.environ.get("UPSTASH_REDIS_REST_URL")
    redis_token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    
    if not redis_url or not redis_token:
        return False 

    lua_script = """
    local current = redis.call('GET', KEYS[1])
    if current and tonumber(current) >= tonumber(ARGV[1]) then
        return -1
    end
    local new_val = redis.call('INCR', KEYS[1])
    if tonumber(new_val) == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[2])
    end
    return new_val
    """
    headers = {"Authorization": f"Bearer {redis_token}"}
    payload = ["EVAL", lua_script, 1, key, limit, ttl_seconds]
    try:
        resp = requests.post(redis_url, json=payload, headers=headers, timeout=1.5)
        if resp.status_code == 200:
            result = resp.json().get("result")
            if result == -1:
                return False
            return True
    except Exception as e:
        logger.error(f"Redis free quota consume failed: {e}")
        return False
    return False

def audit_log(admin_user_id: str, action: str, resource_type: str, resource_id: str = None, reason: str = None):
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        return
    url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/audit_logs"
    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "admin_user_id": admin_user_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "reason": reason
    }
    try:
        requests.post(url, json=payload, headers=headers, timeout=2.0)
    except Exception:
        pass
