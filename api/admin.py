from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional, List, Dict
import requests
import os
import json
from pydantic import BaseModel, Field

class AdminMutationRequest(BaseModel):
    reason: Optional[str] = Field(None, max_length=500)

from api.auth.entitlements import get_current_user, get_user_role, get_user_plan_and_status, audit_log

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
    supabase_url = os.environ.get('SUPABASE_URL', '').rstrip('/')
    supabase_key = os.environ.get('SUPABASE_SECRET_KEY', '')
    if not supabase_url or not supabase_key:
        raise HTTPException(status_code=500, detail="Supabase credentials not configured.")
    
    headers = {
        "apikey": supabase_key,
        "Authorization": f"Bearer {supabase_key}"
    }

    try:
        resp_users = requests.get(f"{supabase_url}/auth/v1/admin/users", headers=headers, timeout=5.0)
        total_users = len(resp_users.json().get("users", [])) if resp_users.status_code == 200 else 0
        
        resp_pro = requests.head(f"{supabase_url}/rest/v1/user_plans?plan=eq.professional&select=*", headers={'Prefer': 'count=exact', **headers}, timeout=5.0)
        professional_users = 0
        if resp_pro.status_code == 200:
            cr = resp_pro.headers.get("Content-Range", "0-0/0")
            try:
                professional_users = int(cr.split("/")[-1])
            except:
                pass
                
        free_users = total_users - professional_users
        
        return {
            "total_users": total_users,
            "free_users": free_users,
            "professional_users": professional_users,
            "scans_today": None,
            "scans_this_week": None,
            "recent_failures": None
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@admin_router.get("/users")
def get_users(limit: int = Query(50), offset: int = Query(0), user: dict = Depends(require_admin)):
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
            
            plans_resp = requests.get(f"{os.environ.get('SUPABASE_URL', '').rstrip('/')}/rest/v1/user_plans?select=user_id,plan,status", headers=headers, timeout=5.0)
            plans_map = {}
            if plans_resp.status_code == 200:
                for row in plans_resp.json():
                    plans_map[row.get("user_id")] = row
            
            roles_resp = requests.get(f"{os.environ.get('SUPABASE_URL', '').rstrip('/')}/rest/v1/user_roles?select=user_id,role", headers=headers, timeout=5.0)
            roles_map = {}
            if roles_resp.status_code == 200:
                for row in roles_resp.json():
                    roles_map[row.get("user_id")] = row.get("role")
                    
            safe_users = []
            for u in users_data:
                uid = u.get("id")
                plan_info = plans_map.get(uid, {})
                safe_users.append({
                    "user_id": uid,
                    "email": u.get("email"),
                    "role": roles_map.get(uid, "user"),
                    "plan": plan_info.get("plan", "free"),
                    "status": plan_info.get("status", "active"),
                    "created_at": u.get("created_at")
                })
            return safe_users[offset:offset+limit]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return []

@admin_router.get("/users/{user_id}")
def get_user_detail(user_id: str, user: dict = Depends(require_admin)):
    if not os.environ.get('SUPABASE_URL') or not os.environ.get('SUPABASE_SECRET_KEY'):
        raise HTTPException(status_code=500, detail="Supabase credentials not configured.")
        
    url = f"{os.environ.get('SUPABASE_URL', '').rstrip('/')}/auth/v1/admin/users/{user_id}"
    headers = {
        "apikey": os.environ.get("SUPABASE_SECRET_KEY", ""),
        "Authorization": f"Bearer {os.environ.get('SUPABASE_SECRET_KEY', '')}",
        "Content-Type": "application/json"
    }
    
    plan, status = get_user_plan_and_status(user_id)
    
    try:
        resp = requests.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            u = resp.json()
            return {
                "user_id": u.get("id"),
                "email": u.get("email"),
                "role": get_user_role(user_id),
                "plan": plan,
                "status": status,
                "created_at": u.get("created_at")
            }
    except Exception as e:
        pass

    return {
        "user_id": user_id,
        "role": get_user_role(user_id),
        "plan": plan,
        "status": status
    }

def upsert_user_plan(user_id: str, new_plan: str, new_status: str):
    url = f"{os.environ.get('SUPABASE_URL', '').rstrip('/')}/rest/v1/user_plans"
    headers = {
        "apikey": os.environ.get("SUPABASE_SECRET_KEY", ""),
        "Authorization": f"Bearer {os.environ.get('SUPABASE_SECRET_KEY', '')}",
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates"
    }
    payload = {
        "user_id": user_id,
        "plan": new_plan,
        "status": new_status
    }
    resp = requests.post(url, json=payload, headers=headers, timeout=5.0)
    if resp.status_code not in (200, 201, 204):
        raise HTTPException(status_code=500, detail="Failed to update user_plans")

def verify_user_exists(user_id: str):
    if not os.environ.get('SUPABASE_URL') or not os.environ.get('SUPABASE_SECRET_KEY'):
        return
    url = f"{os.environ.get('SUPABASE_URL', '').rstrip('/')}/auth/v1/admin/users/{user_id}"
    headers = {
        "apikey": os.environ.get("SUPABASE_SECRET_KEY", ""),
        "Authorization": f"Bearer {os.environ.get('SUPABASE_SECRET_KEY', '')}"
    }
    resp = requests.get(url, headers=headers, timeout=5.0)
    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail="User not found.")
    elif resp.status_code != 200:
        raise HTTPException(status_code=500, detail="Error verifying user existence.")

@admin_router.post("/users/{user_id}/grant-professional")
def grant_professional(user_id: str, payload: Optional[AdminMutationRequest] = None, user: dict = Depends(require_admin)):
    verify_user_exists(user_id)
    current_role = get_user_role(user_id)
    current_plan, current_status = get_user_plan_and_status(user_id)
    before_state = {"role": current_role, "plan": current_plan, "status": current_status}
    
    upsert_user_plan(user_id, "professional", current_status)
    
    after_state = {"role": current_role, "plan": "professional", "status": current_status}
    audit_log(user.get("sub"), "grant_professional", "user", user_id, payload.reason if payload else None, before_state, after_state)
    return {"user_id": user_id, "plan": "professional", "status": current_status}

@admin_router.post("/users/{user_id}/remove-professional")
def remove_professional(user_id: str, payload: Optional[AdminMutationRequest] = None, user: dict = Depends(require_admin)):
    verify_user_exists(user_id)
    current_role = get_user_role(user_id)
    current_plan, current_status = get_user_plan_and_status(user_id)
    before_state = {"role": current_role, "plan": current_plan, "status": current_status}
    
    upsert_user_plan(user_id, "free", current_status)
    
    after_state = {"role": current_role, "plan": "free", "status": current_status}
    audit_log(user.get("sub"), "remove_professional", "user", user_id, payload.reason if payload else None, before_state, after_state)
    return {"user_id": user_id, "plan": "free", "status": current_status}

@admin_router.post("/users/{user_id}/suspend")
def suspend_user(user_id: str, payload: Optional[AdminMutationRequest] = None, user: dict = Depends(require_admin)):
    verify_user_exists(user_id)
    if user.get("sub") == user_id:
        raise HTTPException(status_code=400, detail="You cannot suspend your own Admin account.")
        
    current_role = get_user_role(user_id)
    current_plan, current_status = get_user_plan_and_status(user_id)
    before_state = {"role": current_role, "plan": current_plan, "status": current_status}
    
    upsert_user_plan(user_id, current_plan, "suspended")
    
    after_state = {"role": current_role, "plan": current_plan, "status": "suspended"}
    audit_log(user.get("sub"), "suspend_user", "user", user_id, payload.reason if payload else None, before_state, after_state)
    return {"user_id": user_id, "plan": current_plan, "status": "suspended"}

@admin_router.post("/users/{user_id}/reactivate")
def reactivate_user(user_id: str, payload: Optional[AdminMutationRequest] = None, user: dict = Depends(require_admin)):
    verify_user_exists(user_id)
    current_role = get_user_role(user_id)
    current_plan, current_status = get_user_plan_and_status(user_id)
    before_state = {"role": current_role, "plan": current_plan, "status": current_status}
    
    upsert_user_plan(user_id, current_plan, "active")
    
    after_state = {"role": current_role, "plan": current_plan, "status": "active"}
    audit_log(user.get("sub"), "reactivate_user", "user", user_id, payload.reason if payload else None, before_state, after_state)
    return {"user_id": user_id, "plan": current_plan, "status": "active"}

@admin_router.get("/scans")
def get_scans(limit: int = Query(50), offset: int = Query(0), user: dict = Depends(require_admin)):
    if not os.environ.get('SUPABASE_URL') or not os.environ.get('SUPABASE_SECRET_KEY'):
        raise HTTPException(status_code=500, detail="Supabase credentials not configured.")
        
    url = f"{os.environ.get('SUPABASE_URL', '').rstrip('/')}/rest/v1/scans?select=id,user_id,target_url,score,report_data,created_at&limit={limit}&offset={offset}&order=created_at.desc"
    headers = {
        "apikey": os.environ.get('SUPABASE_SECRET_KEY', ''),
        "Authorization": f"Bearer {os.environ.get('SUPABASE_SECRET_KEY', '')}"
    }
    
    try:
        resp = requests.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            safe_scans = []
            for row in data:
                report = row.get("report_data") or {}
                raw_mode = report.get("scan_mode")
                
                product_mode = "Unknown"
                if raw_mode == "active":
                    product_mode = "Advanced"
                elif raw_mode in ("passive", "basic"):
                    product_mode = "Basic"
                    
                safe_scans.append({
                    "id": row.get("id"),
                    "user_id": row.get("user_id"),
                    "url": row.get("target_url"),
                    "scan_mode": product_mode,
                    "score": row.get("score"),
                    "status": "completed",
                    "created_at": row.get("created_at")
                })
            return safe_scans
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
