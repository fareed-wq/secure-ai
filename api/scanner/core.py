import os
import time
import requests
import logging
import uuid
from collections import defaultdict
from fastapi import Request

logger = logging.getLogger(__name__)

# --- CENTRAL CONFIGURATION ---
class Config:
    REQUEST_TIMEOUT = (1.5, 2.5)
    MAX_REDIRECTS = 5
    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36"
    )
    THREAD_POOL_SIZE = 15
    COMMON_SUBDOMAINS = ["trcadmin", "console", "s3", "s3b", "beta", "api", "dev"]
    SEVERITY_WEIGHTS = {
        "Critical": -15,
        "High": -10,
        "Medium": -5,
        "Low": -2,
        "Informational": 0,
        "Passed": 0
    }
    SCORE_THRESHOLDS = {
        "A+": 95,
        "A": 90,
        "B": 80,
        "C": 70,
        "D": 60,
        "F": 0
    }

# --- RATE LIMITING STATE ---
IN_MEMORY_LIMITS = defaultdict(list)

def get_client_ip(request: Request) -> str:
    # 1. Prefer Vercel's immutable edge header
    vercel_ip = request.headers.get("x-vercel-forwarded-for")
    if vercel_ip:
        return vercel_ip.split(",")[0].strip()

    # 2. Local development fallback
    if getattr(request.client, "host", None):
        return request.client.host

    return "127.0.0.1"

def check_rate_limit(ip: str) -> bool:
    limit = 10
    window = 60

    redis_url = os.environ.get("UPSTASH_REDIS_REST_URL")
    redis_token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")

    if redis_url and redis_token:
        try:
            key = f"rate_limit:{ip}"
            headers = {"Authorization": f"Bearer {redis_token}"}
            payload = [
                ["INCR", key],
                ["EXPIRE", key, window]
            ]
            resp = requests.post(f"{redis_url}/pipeline", json=payload, headers=headers, timeout=1.0)
            if resp.status_code == 200:
                results = resp.json()
                count = results[0].get("result", 1)
                return count <= limit
        except Exception as e:
            logger.error(f"Redis rate limit failed, falling back to memory: {e}")
            pass

    now = time.time()
    history = [t for t in IN_MEMORY_LIMITS[ip] if now - t < window]
    if len(history) >= limit:
        return False
    history.append(now)
    IN_MEMORY_LIMITS[ip] = history
    return True

def acquire_scan_lease() -> str | None:
    """
    Acquires an atomic global scan lease using a Lua ZSET semaphore via Upstash REST.
    Returns:
        The UUID lease_id on success.
        None if global capacity is full.
    Raises:
        RuntimeError if Redis is unavailable or admission state cannot be determined.
    """
    redis_url = os.environ.get("UPSTASH_REDIS_REST_URL")
    redis_token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")

    if not redis_url or not redis_token:
        # We must fail closed if Redis admission state cannot be determined.
        raise RuntimeError("Redis configuration missing; cannot determine global active-scan capacity.")

    lease_id = str(uuid.uuid4())
    now = int(time.time())
    ttl = now + 65
    max_active = 10

    lua_script = """
    redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
    local count = redis.call('ZCARD', KEYS[1])
    if count >= tonumber(ARGV[2]) then
        return 0
    else
        redis.call('ZADD', KEYS[1], ARGV[3], ARGV[4])
        return 1
    end
    """

    headers = {"Authorization": f"Bearer {redis_token}"}
    payload = ["EVAL", lua_script, 1, "active_scans", now, max_active, ttl, lease_id]

    try:
        resp = requests.post(redis_url, json=payload, headers=headers, timeout=1.5)
        if resp.status_code == 200:
            result = resp.json().get("result")
            if result == 1:
                return lease_id
            return None
        else:
            raise RuntimeError(f"Upstash REST error: {resp.text}")
    except Exception as e:
        logger.error(f"Failed to acquire scan lease: {e}")
        raise RuntimeError("Failed to acquire global active-scan lease due to Redis error.")

def release_scan_lease(lease_id: str):
    """
    Idempotently releases a global scan lease via Upstash REST.
    """
    if not lease_id:
        return

    redis_url = os.environ.get("UPSTASH_REDIS_REST_URL")
    redis_token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")

    if not redis_url or not redis_token:
        return

    headers = {"Authorization": f"Bearer {redis_token}"}
    payload = ["ZREM", "active_scans", lease_id]

    try:
        # Fire and forget idempotently
        requests.post(redis_url, json=payload, headers=headers, timeout=1.5)
    except Exception as e:
        logger.error(f"Failed to release scan lease {lease_id}: {e}")

def acquire_guest_lease(ip: str) -> bool:
    """Ensure maximum guest scan concurrency = 1 per IP."""
    redis_url = os.environ.get("UPSTASH_REDIS_REST_URL")
    redis_token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    if not redis_url or not redis_token:
        raise RuntimeError("Redis missing; cannot determine guest concurrency.")
    key = f"guest_active:{ip}"
    headers = {"Authorization": f"Bearer {redis_token}"}
    payload = ["SET", key, "1", "NX", "EX", "65"]
    try:
        resp = requests.post(redis_url, json=payload, headers=headers, timeout=1.5)
        if resp.status_code == 200:
            result = resp.json().get("result")
            return result == "OK"
        raise RuntimeError(f"Upstash REST error: {resp.text}")
    except Exception as e:
        logger.error(f"Failed to acquire guest lease: {e}")
        raise RuntimeError("Failed to acquire guest lease due to Redis error.")

def release_guest_lease(ip: str):
    redis_url = os.environ.get("UPSTASH_REDIS_REST_URL")
    redis_token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    if not redis_url or not redis_token:
        return
    headers = {"Authorization": f"Bearer {redis_token}"}
    payload = ["DEL", f"guest_active:{ip}"]
    try:
        requests.post(redis_url, json=payload, headers=headers, timeout=1.5)
    except Exception:
        pass
