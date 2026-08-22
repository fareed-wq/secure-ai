from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional, List, Dict
import requests
import os
import json

from api.auth.entitlements import get_current_user, get_user_role, audit_log

admin_router = APIRouter(prefix="/api/admin", tags=["admin"])



def require_admin(user: Optional[dict] = Depends(get_current_user)) -> dict:
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    user_id = user.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid user subject.")
    role = get_user_role(user_id)
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required.")
    user["role"] = "admin"
    return user

@admin_router.get("/me")
def get_me(user: dict = Depends(require_admin)):
    return {
        "authenticated": True,
        "user_id": user.get("sub"),
        "role": "admin"
    }

@admin_router.get("/overview")
def get_overview(user: dict = Depends(require_admin)):
    # Mock operational counts as we might not have a reliable way to query everything without specific DB views
    # In a real app we would query Supabase for these counts.
    return {
        "total_users": 0,
        "free_users": 0,
        "professional_users": 0,
        "scans_today": 0,
        "scans_this_week": 0,
        "recent_failures": 0
    }

@admin_router.get("/users")
def get_users(limit: int = Query(50), offset: int = Query(0), user: dict = Depends(require_admin)):
    # Mock response or call Supabase Admin API
    if not os.environ.get('SUPABASE_URL') or not os.environ.get('SUPABASE_SECRET_KEY'):
        raise HTTPException(status_code=500, detail="Supabase credentials not configured.")
    
    url = f"{os.environ.get('SUPABASE_URL', '').rstrip('/')}/auth/v1/admin/users"
    headers = {
        "apikey": os.environ.get("SUPABASE_SECRET_KEY", ""),
        "Authorization": f"Bearer {os.environ.get('SUPABASE_SECRET_KEY', '')}",
        "Content-Type": "application/json"
    }
    
    try:
        resp = requests.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            users_data = resp.json().get("users", [])
            safe_users = []
            for u in users_data:
                safe_users.append({
                    "user_id": u.get("id"),
                    "email": u.get("email"),
                    "role": get_user_role(u.get("id")),
                    "plan": "free", # To be replaced when plan table is applied
                    "status": "active",
                    "created_at": u.get("created_at")
                })
            return safe_users[offset:offset+limit]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return []

@admin_router.get("/users/{user_id}")
def get_user_detail(user_id: str, user: dict = Depends(require_admin)):
    # Return mock or real data
    return {
        "user_id": user_id,
        "role": get_user_role(user_id),
        "plan": "free",
        "account_status": "active"
    }

@admin_router.post("/users/{user_id}/grant-professional")
def grant_professional(user_id: str, user: dict = Depends(require_admin)):
    if not os.environ.get('SUPABASE_URL') or not os.environ.get('SUPABASE_SECRET_KEY'):
        raise HTTPException(status_code=500, detail="Supabase credentials not configured.")
        
    url = f"{os.environ.get('SUPABASE_URL', '').rstrip('/')}/rest/v1/user_plans"
    headers = {
        "apikey": os.environ.get('SUPABASE_SECRET_KEY', ''),
        "Authorization": f"Bearer {os.environ.get('SUPABASE_SECRET_KEY', '')}",
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates"
    }
    payload = {
        "user_id": user_id,
        "plan": "professional"
    }
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=5.0)
        if resp.status_code not in [200, 201, 204]:
            raise HTTPException(status_code=500, detail=f"Failed to update plan: {resp.text}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
    audit_log(
        admin_user_id=user.get("sub"),
        action="grant_professional",
        resource_type="user",
        resource_id=user_id,
        reason="Admin grant professional"
    )
    return {"status": "success", "user_id": user_id, "plan": "professional"}

@admin_router.post("/users/{user_id}/remove-professional")
def remove_professional(user_id: str, user: dict = Depends(require_admin)):
    if not os.environ.get('SUPABASE_URL') or not os.environ.get('SUPABASE_SECRET_KEY'):
        raise HTTPException(status_code=500, detail="Supabase credentials not configured.")
        
    url = f"{os.environ.get('SUPABASE_URL', '').rstrip('/')}/rest/v1/user_plans"
    headers = {
        "apikey": os.environ.get('SUPABASE_SECRET_KEY', ''),
        "Authorization": f"Bearer {os.environ.get('SUPABASE_SECRET_KEY', '')}",
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates"
    }
    payload = {
        "user_id": user_id,
        "plan": "free"
    }
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=5.0)
        if resp.status_code not in [200, 201, 204]:
            raise HTTPException(status_code=500, detail=f"Failed to update plan: {resp.text}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
    audit_log(
        admin_user_id=user.get("sub"),
        action="remove_professional",
        resource_type="user",
        resource_id=user_id,
        reason="Admin remove professional"
    )
    return {"status": "success", "user_id": user_id, "plan": "free"}

@admin_router.post("/users/{user_id}/suspend")
def suspend_user(user_id: str, user: dict = Depends(require_admin)):
    raise HTTPException(status_code=501, detail="Suspension requires database migration.")

@admin_router.post("/users/{user_id}/reactivate")
def reactivate_user(user_id: str, user: dict = Depends(require_admin)):
    raise HTTPException(status_code=501, detail="Reactivation requires database migration.")

@admin_router.get("/scans")
def get_scans(limit: int = Query(50), offset: int = Query(0), user: dict = Depends(require_admin)):
    if not os.environ.get('SUPABASE_URL') or not os.environ.get('SUPABASE_SECRET_KEY'):
        raise HTTPException(status_code=500, detail="Supabase credentials not configured.")
        
    url = f"{os.environ.get('SUPABASE_URL', '').rstrip('/')}/rest/v1/scans?select=id,user_id,url,scan_mode,score,status,created_at&limit={limit}&offset={offset}"
    headers = {
        "apikey": os.environ.get('SUPABASE_SECRET_KEY', ''),
        "Authorization": f"Bearer {os.environ.get('SUPABASE_SECRET_KEY', '')}"
    }
    
    try:
        resp = requests.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return []

@admin_router.get("/audit-logs")
def get_audit_logs(limit: int = Query(50), offset: int = Query(0), user: dict = Depends(require_admin)):
    if not os.environ.get('SUPABASE_URL') or not os.environ.get('SUPABASE_SECRET_KEY'):
        raise HTTPException(status_code=500, detail="Supabase credentials not configured.")
        
    url = f"{os.environ.get('SUPABASE_URL', '').rstrip('/')}/rest/v1/audit_logs?select=*&limit={limit}&offset={offset}&order=created_at.desc"
    headers = {
        "apikey": os.environ.get('SUPABASE_SECRET_KEY', ''),
        "Authorization": f"Bearer {os.environ.get('SUPABASE_SECRET_KEY', '')}"
    }
    
    try:
        resp = requests.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return []
