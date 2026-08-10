import os
import time
import requests
import logging
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
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.headers.get("X-Real-IP", "127.0.0.1")

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
