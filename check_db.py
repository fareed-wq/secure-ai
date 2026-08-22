import os
import requests

url = ''
key = ''
with open('.env.admin.local') as f:
    for line in f:
        if line.startswith('SUPABASE_URL='):
            url = line.strip().split('=', 1)[1]
        elif line.startswith('SUPABASE_SECRET_KEY='):
            key = line.strip().split('=', 1)[1]

headers = {
    'apikey': key,
    'Authorization': f'Bearer {key}'
}

# Total Auth Users
resp = requests.get(f'{url}/auth/v1/admin/users', headers=headers)
users = resp.json().get('users', [])
print(f"Actual Auth users count: {len(users)}")

# Scans schema
resp3 = requests.get(f'{url}/rest/v1/scans?select=count', headers={'Prefer': 'count=exact', **headers})
print(f"Scans count: {resp3.headers.get('Content-Range')}")

resp3_1 = requests.get(f'{url}/rest/v1/scans?limit=1', headers=headers)
if resp3_1.status_code == 200:
    if resp3_1.json():
        print(f"Scans row keys: {list(resp3_1.json()[0].keys())}")
    else:
        print("Scans table is empty.")

# Audit logs count
resp4 = requests.head(f'{url}/rest/v1/audit_logs?select=*', headers={'Prefer': 'count=exact', **headers})
print(f"Actual audit_logs count: {resp4.headers.get('Content-Range')}")
