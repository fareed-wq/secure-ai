import os
import uuid
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, HttpUrl, field_validator
import logging
import requests

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import JSONResponse

from api.auth.entitlements import require_scheduled_scans_access
from api.scanner.orchestrator import validate_scan_target, canonicalize_url
from api.scheduling.time_utils import get_next_run_at, is_valid_timezone

# Only import QStash if package is installed (may not be present locally)
try:
    from qstash import QStash as QStashClient
except ImportError:
    QStashClient = None

logger = logging.getLogger(__name__)

router = APIRouter()

SUPABASE_URL = os.environ.get("VITE_SUPABASE_URL") or os.environ.get("SUPABASE_URL")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY")
QSTASH_TOKEN = os.environ.get("QSTASH_TOKEN")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "https://urlscanonline.com")

def get_db_headers():
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Supabase credentials not configured.")
    return {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Content-Type": "application/json"
    }

class ScheduleCreateRequest(BaseModel):
    target_url: str
    frequency: str
    time_of_day: str # "HH:MM:SS"
    timezone: str
    day_of_week: Optional[int] = None
    day_of_month: Optional[int] = None
    authorization_acknowledged: bool

    @field_validator('frequency')
    def validate_frequency(cls, v):
        if v not in ('daily', 'weekly', 'monthly'):
            raise ValueError('Invalid frequency')
        return v
        
    @field_validator('timezone')
    def validate_timezone(cls, v):
        if not is_valid_timezone(v):
            raise ValueError('Invalid IANA timezone')
        return v

def _get_qstash_cron(frequency: str, time_of_day: str, day_of_week: int = None, day_of_month: int = None) -> str:
    parts = time_of_day.split(':')
    h = int(parts[0])
    m = int(parts[1])
    if frequency == 'daily':
        return f"{m} {h} * * *"
    elif frequency == 'weekly':
        return f"{m} {h} * * {day_of_week}"
    elif frequency == 'monthly':
        return f"{m} {h} {day_of_month} * *"
    return ""

@router.get("")
async def list_schedules(user: dict = Depends(require_scheduled_scans_access)):
        
    url = f"{SUPABASE_URL}/rest/v1/scan_schedules?user_id=eq.{user['sub']}&select=*"
    resp = requests.get(url, headers=get_db_headers())
    if resp.status_code != 200:
        return JSONResponse(status_code=500, content={"error": "Failed to fetch schedules"})
    return resp.json()

@router.post("")
async def create_schedule(req: ScheduleCreateRequest, user: dict = Depends(require_scheduled_scans_access)):
        
    if not req.authorization_acknowledged:
        return JSONResponse(status_code=400, content={"error": "Must acknowledge authorization"})

    validation_error = validate_scan_target(req.target_url, "passive")
    if validation_error:
        return JSONResponse(status_code=400, content=validation_error)
        
    normalized = canonicalize_url(req.target_url)

    # Check limit of 3
    url = f"{SUPABASE_URL}/rest/v1/scan_schedules?user_id=eq.{user['sub']}&select=id"
    resp = requests.get(url, headers=get_db_headers())
    if resp.status_code == 200 and len(resp.json()) >= 3:
        return JSONResponse(status_code=403, content={"error": "Maximum of 3 scheduled scans reached."})

    # Check duplicate
    # Exact duplicate check
    dup_check_url = f"{SUPABASE_URL}/rest/v1/scan_schedules?user_id=eq.{user['sub']}&normalized_target=eq.{normalized}&frequency=eq.{req.frequency}&time_of_day=eq.{req.time_of_day}&timezone=eq.{req.timezone}"
    if req.frequency == 'weekly':
        dup_check_url += f"&day_of_week=eq.{req.day_of_week}"
    elif req.frequency == 'monthly':
        dup_check_url += f"&day_of_month=eq.{req.day_of_month}"
        
    dup_resp = requests.get(dup_check_url, headers=get_db_headers())
    if dup_resp.status_code == 200 and len(dup_resp.json()) > 0:
        return JSONResponse(status_code=409, content={"error": "Duplicate schedule exists"})

    new_id = str(uuid.uuid4())
    qstash_schedule_id = f"urlscan-{new_id}"
    
    # Create QStash schedule if client is available
    if QStashClient and QSTASH_TOKEN:
        try:
            client = QStashClient(QSTASH_TOKEN)
            cron_expr = _get_qstash_cron(req.frequency, req.time_of_day, req.day_of_week, req.day_of_month)
            destination = f"{APP_BASE_URL.rstrip('/')}/api/internal/scheduled-scan"
            
            res_id = client.schedule.create(
                destination=destination,
                cron=cron_expr,
                body=json.dumps({"schedule_id": new_id}),
                headers={
                    "Upstash-Cron-Tz": req.timezone,
                    "Content-Type": "application/json"
                },
                retries=0,
                schedule_id=qstash_schedule_id
            )
            # The returned ID should match our provided one
        except Exception as e:
            logger.error(f"Failed to create QStash schedule: {e}")
            return JSONResponse(status_code=500, content={"error": "Failed to create scheduling infrastructure."})

    from datetime import time as dt_time
    t_parts = req.time_of_day.split(':')
    tod = dt_time(int(t_parts[0]), int(t_parts[1]), int(t_parts[2]) if len(t_parts)>2 else 0)
    next_run = get_next_run_at(req.frequency, tod, req.timezone, req.day_of_week, req.day_of_month)

    payload = {
        "id": new_id,
        "user_id": user['sub'],
        "target_url": req.target_url,
        "normalized_target": normalized,
        "scan_mode": "passive",
        "frequency": req.frequency,
        "time_of_day": req.time_of_day,
        "timezone": req.timezone,
        
        "is_enabled": True,
        "qstash_schedule_id": qstash_schedule_id,
        "authorization_acknowledged_at": datetime.now(timezone.utc).isoformat(),
        "next_run_at": next_run.isoformat()
    }

    db_res = requests.post(
        f"{SUPABASE_URL}/rest/v1/scan_schedules", 
        headers={**get_db_headers(), "Prefer": "return=representation"}, 
        json=payload
    )
    
    if db_res.status_code not in (200, 201):
        if QStashClient and QSTASH_TOKEN and qstash_schedule_id:
            try:
                client.schedule.delete(qstash_schedule_id)
            except Exception:
                pass
        return JSONResponse(status_code=500, content={"error": "Failed to save schedule to database"})
        
    return db_res.json()[0]

@router.post("/{schedule_id}/pause")
async def pause_schedule(schedule_id: str, user: dict = Depends(require_scheduled_scans_access)):
        
    url = f"{SUPABASE_URL}/rest/v1/scan_schedules?id=eq.{schedule_id}&user_id=eq.{user['sub']}&select=*"
    resp = requests.get(url, headers=get_db_headers())
    if resp.status_code != 200 or len(resp.json()) == 0:
        return JSONResponse(status_code=404, content={"error": "Not found"})
        
    sched = resp.json()[0]
    
    if QStashClient and QSTASH_TOKEN and sched.get('qstash_schedule_id'):
        client = QStashClient(QSTASH_TOKEN)
        try:
            client.schedule.pause(sched['qstash_schedule_id'])
        except Exception as e:
            logger.error(f"Failed to pause QStash schedule: {e}")
            return JSONResponse(status_code=500, content={"error": "Failed to pause schedule"})
            
    update_payload = {"is_enabled": False, "next_run_at": None}
    patch_url = f"{SUPABASE_URL}/rest/v1/scan_schedules?id=eq.{schedule_id}"
    requests.patch(patch_url, headers=get_db_headers(), json=update_payload)
    
    return {"status": "paused"}

@router.post("/{schedule_id}/resume")
async def resume_schedule(schedule_id: str, user: dict = Depends(require_scheduled_scans_access)):
        
    url = f"{SUPABASE_URL}/rest/v1/scan_schedules?id=eq.{schedule_id}&user_id=eq.{user['sub']}&select=*"
    resp = requests.get(url, headers=get_db_headers())
    if resp.status_code != 200 or len(resp.json()) == 0:
        return JSONResponse(status_code=404, content={"error": "Not found"})
        
    sched = resp.json()[0]
    
    validation_error = validate_scan_target(sched['target_url'], "passive")
    if validation_error:
        return JSONResponse(status_code=400, content={"error": "Target no longer valid for scanning"})
        
    if QStashClient and QSTASH_TOKEN and sched.get('qstash_schedule_id'):
        client = QStashClient(QSTASH_TOKEN)
        try:
            client.schedule.resume(sched['qstash_schedule_id'])
        except Exception as e:
            logger.error(f"Failed to resume QStash schedule: {e}")
            return JSONResponse(status_code=500, content={"error": "Failed to resume schedule"})
            
    # Recalculate next run
    from datetime import time as dt_time
    t_parts = sched['time_of_day'].split(':')
    tod = dt_time(int(t_parts[0]), int(t_parts[1]), int(t_parts[2]) if len(t_parts)>2 else 0)
    next_run = get_next_run_at(sched['frequency'], tod, sched['timezone'], sched.get('day_of_week'), sched.get('day_of_month'))
    
    update_payload = {"is_enabled": True, "next_run_at": next_run.isoformat()}
    requests.patch(f"{SUPABASE_URL}/rest/v1/scan_schedules?id=eq.{schedule_id}", headers=get_db_headers(), json=update_payload)
    
    return {"status": "resumed"}

@router.delete("/{schedule_id}")
async def delete_schedule(schedule_id: str, user: dict = Depends(require_scheduled_scans_access)):
        
    url = f"{SUPABASE_URL}/rest/v1/scan_schedules?id=eq.{schedule_id}&user_id=eq.{user['sub']}&select=*"
    resp = requests.get(url, headers=get_db_headers())
    if resp.status_code != 200 or len(resp.json()) == 0:
        return JSONResponse(status_code=404, content={"error": "Not found"})
        
    sched = resp.json()[0]
    
    if QStashClient and QSTASH_TOKEN and sched.get('qstash_schedule_id'):
        client = QStashClient(QSTASH_TOKEN)
        try:
            client.schedule.delete(sched['qstash_schedule_id'])
        except Exception as e:
            err_str = str(e).lower()
            if "404" not in err_str and "not found" not in err_str:
                logger.error(f"QStash schedule delete failed: {e}")
                return JSONResponse(status_code=500, content={"error": "Failed to delete remote schedule"})
            
    del_url = f"{SUPABASE_URL}/rest/v1/scan_schedules?id=eq.{schedule_id}"
    requests.delete(del_url, headers=get_db_headers())
    
    return {"status": "deleted"}
