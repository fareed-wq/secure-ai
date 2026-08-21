import requests
import secrets

def patch_file():
    with open('api/index.py', 'r') as f:
        content = f.read()

    addition = """
class ShareCreateRequest(BaseModel):
    scan_id: str

class ShareRevokeRequest(BaseModel):
    share_token: str

@app.post("/api/share/create")
async def create_share(req: ShareCreateRequest, user: dict = Depends(get_current_user)):
    entitlements = Entitlements(user)
    if not entitlements.can_share_scan or not user.get("sub"):
        return JSONResponse(status_code=403, content={"error": "Not authorized to share scans."})

    from api.auth.entitlements import SUPABASE_URL, SUPABASE_SECRET_KEY
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        return JSONResponse(status_code=500, content={"error": "Database configuration missing."})

    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

    # Verify scan belongs to user
    res = requests.get(f"{SUPABASE_URL}/rest/v1/scans?id=eq.{req.scan_id}&user_id=eq.{user['sub']}&select=id", headers=headers)
    if res.status_code != 200 or not res.json():
        return JSONResponse(status_code=404, content={"error": "Scan not found or access denied."})

    # Check if active share already exists
    res = requests.get(f"{SUPABASE_URL}/rest/v1/scan_shares?scan_id=eq.{req.scan_id}&revoked_at=is.null&select=share_token,created_at", headers=headers)
    if res.status_code == 200 and res.json():
        return {"share_token": res.json()[0]["share_token"], "created_at": res.json()[0]["created_at"]}

    import secrets
    import datetime
    token = secrets.token_urlsafe(32)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    payload = {
        "scan_id": req.scan_id,
        "owner_user_id": user["sub"],
        "share_token": token,
        "created_at": now
    }
    
    res = requests.post(f"{SUPABASE_URL}/rest/v1/scan_shares", headers=headers, json=payload)
    if res.status_code not in (200, 201):
        return JSONResponse(status_code=500, content={"error": "Failed to create share link."})
        
    data = res.json()[0]
    return {"share_token": data["share_token"], "created_at": data["created_at"]}

@app.post("/api/share/revoke")
async def revoke_share(req: ShareRevokeRequest, user: dict = Depends(get_current_user)):
    entitlements = Entitlements(user)
    if not user.get("sub"):
        return JSONResponse(status_code=403, content={"error": "Not authorized."})

    from api.auth.entitlements import SUPABASE_URL, SUPABASE_SECRET_KEY
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        return JSONResponse(status_code=500, content={"error": "Database configuration missing."})

    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

    import datetime
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    payload = {
        "revoked_at": now
    }
    
    res = requests.patch(f"{SUPABASE_URL}/rest/v1/scan_shares?share_token=eq.{req.share_token}&owner_user_id=eq.{user['sub']}", headers=headers, json=payload)
    if res.status_code not in (200, 204) and (res.status_code != 200 or not res.json()):
        return JSONResponse(status_code=500, content={"error": "Failed to revoke share link."})
        
    return {"status": "success", "revoked_at": now}

@app.get("/api/share/{token}")
async def get_shared_report(token: str):
    from api.auth.entitlements import SUPABASE_URL, SUPABASE_SECRET_KEY
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        return JSONResponse(status_code=500, content={"error": "Database configuration missing."})

    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Content-Type": "application/json"
    }

    res = requests.get(f"{SUPABASE_URL}/rest/v1/scan_shares?share_token=eq.{token}&revoked_at=is.null&select=scan_id", headers=headers)
    if res.status_code != 200 or not res.json():
        return JSONResponse(status_code=404, content={"error": "Share link unavailable or revoked."})
        
    scan_id = res.json()[0]["scan_id"]
    
    res = requests.get(f"{SUPABASE_URL}/rest/v1/scans?id=eq.{scan_id}&select=target_url,score,report_data,created_at", headers=headers)
    if res.status_code != 200 or not res.json():
        return JSONResponse(status_code=404, content={"error": "Scan not found."})
        
    scan = res.json()[0]
    
    # Return constrained public projection
    return {
        "target_url": scan.get("target_url"),
        "score": scan.get("score"),
        "report_data": scan.get("report_data"),
        "created_at": scan.get("created_at")
    }

"""

    content = content.replace("class BatchScanRequest(BaseModel):", addition + "\nclass BatchScanRequest(BaseModel):")
    with open('api/index.py', 'w') as f:
        f.write(content)

patch_file()
