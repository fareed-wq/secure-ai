import os
import re
import logging
import requests
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, EmailStr
from api.scanner.core import get_client_ip
# Note: verify_turnstile is in api/index.py, but importing from index into a sub-module might cause circular dependencies if index imports this module.
# Let's move or duplicate verify_turnstile securely, or just import it locally.
logger = logging.getLogger(__name__)
register_router = APIRouter()
class RegistrationRequest(BaseModel):
    email: EmailStr
    password: str
    phone: str
    fullName: str
    company: str = ''
    turnstileToken: str
def verify_turnstile(token: str, ip: str = None) -> bool:
    if not token:
        return False
    secret = os.environ.get("TURNSTILE_SECRET_KEY")
    if not secret:
        raise ValueError("Turnstile server configuration missing")
    try:
        import urllib.parse
        import urllib3
        http = urllib3.PoolManager()
        data = {"secret": secret, "response": token}
        if ip:
            data["remoteip"] = ip
        encoded_data = urllib.parse.urlencode(data).encode("utf-8")
        resp = http.request(
            "POST",
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            body=encoded_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=5.0
        )
        if resp.status == 200:
            import json
            result = json.loads(resp.data.decode("utf-8"))
            return result.get("success", False)
        return False
    except Exception as e:
        logger.error(f"Turnstile verification error: {e}")
        return False
def validate_password(password: str) -> bool:
    if not (12 <= len(password) <= 72): return False
    if not re.search(r'[A-Z]', password): return False
    if not re.search(r'[a-z]', password): return False
    if not re.search(r'[0-9]', password): return False
    if not re.search(r'[^A-Za-z0-9]', password): return False
    return True
