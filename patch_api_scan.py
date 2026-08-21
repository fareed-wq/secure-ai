def patch_file():
    with open('api/index.py', 'r') as f:
        content = f.read()
        
    old_block = """        result = await asyncio.wait_for(asyncio.to_thread(scan_url, req.url, req.probe_subdomains, req.scan_mode), timeout=55.0)
        result["report_mode"] = req.report_mode
        return result
    except Exception as e:"""
    
    new_block = """        result = await asyncio.wait_for(asyncio.to_thread(scan_url, req.url, req.probe_subdomains, req.scan_mode), timeout=55.0)
        result["report_mode"] = req.report_mode
        
        # Automatic Scan History Persistence for authenticated users
        if entitlements.plan != "guest" and user and user.get("sub"):
            from api.auth.entitlements import SUPABASE_URL, SUPABASE_SECRET_KEY
            if SUPABASE_URL and SUPABASE_SECRET_KEY:
                import requests
                import datetime
                headers = {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
                    "Content-Type": "application/json",
                    "Prefer": "return=representation"
                }
                payload = {
                    "user_id": user["sub"],
                    "target_url": result.get("url", req.url),
                    "score": result.get("score", 0),
                    "report_data": result,
                    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
                }
                try:
                    db_res = requests.post(f"{SUPABASE_URL}/rest/v1/scans", headers=headers, json=payload)
                    if db_res.status_code in (200, 201) and db_res.json():
                        result["id"] = db_res.json()[0].get("id")
                except Exception as e:
                    pass
                    
        return result
    except Exception as e:"""
    
    content = content.replace(old_block, new_block)
    
    with open('api/index.py', 'w') as f:
        f.write(content)

patch_file()
