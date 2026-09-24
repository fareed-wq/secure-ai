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

@register_router.post('/register')
def register_user(req: RegistrationRequest, request: Request):
    ip = get_client_ip(request)
    try:
        if not verify_turnstile(req.turnstileToken, ip):
            raise HTTPException(status_code=400, detail="Invalid CAPTCHA.")
    except ValueError as e:
        logger.error(f"Turnstile error: {e}")
        raise HTTPException(status_code=500, detail="CAPTCHA verification failed on server.")
    except Exception as e:
        logger.error(f"Turnstile check failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid CAPTCHA.")

    if not re.fullmatch(r'^\+[1-9]\d{1,14}$', req.phone):
        raise HTTPException(status_code=400, detail="Invalid phone number.")

    if not validate_password(req.password):
        raise HTTPException(status_code=400, detail="Password does not meet the required security requirements.")

    supabase_url = os.environ.get('SUPABASE_URL', '').rstrip('/')
    supabase_key = os.environ.get('SUPABASE_SECRET_KEY', '')
    if not supabase_url or not supabase_key:
        raise HTTPException(status_code=500, detail="Server configuration error.")

    headers = {
        'apikey': supabase_key,
        'Authorization': f'Bearer {supabase_key}',
        'Content-Type': 'application/json'
    }
    
    if ip:
        headers['Sb-Forwarded-For'] = ip
    
    payload = {
        'email': req.email,
        'password': req.password,
        'phone': req.phone,
        'email_confirm': False,
        'phone_confirm': False,
        'user_metadata': {
            'full_name': req.fullName,
            'company': req.company
        }
    }

    try:
        resp = requests.post(f"{supabase_url}/auth/v1/admin/users", json=payload, headers=headers, timeout=10.0)
    except requests.RequestException as e:
        logger.error(f"Failed to communicate with Supabase: {e}")
        raise HTTPException(status_code=500, detail="Registration service unavailable.")

    if not resp.ok:
        msg = "Registration failed."
        try:
            err_data = resp.json()
            err_msg = err_data.get("message", "").lower()
            if "already exists" in err_msg or "duplicate" in err_msg:
                msg = "User already registered with this email or phone."
            elif "format" in err_msg or "invalid" in err_msg:
                msg = err_data.get("message")
        except:
            pass
        
        logger.warning(f"Supabase registration failed with status {resp.status_code}")
        raise HTTPException(status_code=400, detail=msg)

    data = resp.json()
    return {"status": "success", "user_id": data.get("id"), "email": data.get("email")}
