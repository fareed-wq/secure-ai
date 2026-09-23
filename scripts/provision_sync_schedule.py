import os
import sys
import json
from api.scheduling.router import _get_qstash_client

def provision_sync_schedule():
    client = _get_qstash_client()
    if not client:
        print("QStashClient not available or token missing.")
        sys.exit(1)
    
    app_url = os.environ.get("APP_BASE_URL", "http://localhost:3000")
    destination = f"{app_url.rstrip('/')}/api/internal/worker/sync-intelligence"
    
    try:
        # Check if already exists by listing schedules and looking for our destination?
        # QStash SDK might not have list_schedules directly accessible, so we just create it with a known schedule_id
        schedule_id = "global-cve-sync-worker"
        
        # We can try to delete it first to ensure it's fresh
        try:
            client.schedule.delete(schedule_id)
        except Exception:
            pass
            
        print(f"Creating QStash schedule for {destination} every 5 minutes...")
        res_id = client.schedule.create(
            destination=destination,
            cron="*/5 * * * *",
            headers={
                "Content-Type": "application/json"
            },
            retries=3,
            schedule_id=schedule_id
        )
        print(f"Successfully provisioned schedule: {schedule_id} / {res_id}")
    except Exception as e:
        print(f"Failed to create schedule: {e}")
        sys.exit(1)

if __name__ == "__main__":
    provision_sync_schedule()
