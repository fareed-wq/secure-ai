import os
import sys
import json
import secrets
import string
import requests
import argparse

def generate_secure_password(length=24):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password) >= 3):
            return password

def main():
    parser = argparse.ArgumentParser(description="Create or promote an Admin user.")
    parser.add_argument("--email", required=True, help="Email address of the Admin")
    args = parser.parse_args()

    supabase_url = os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_SECRET_KEY")

    if not supabase_url or not supabase_key:
        print("ERROR: SUPABASE_URL and SUPABASE_SECRET_KEY must be set.")
        sys.exit(1)

    url = f"{supabase_url.rstrip('/')}/auth/v1/admin/users"
    headers = {
        "apikey": supabase_key,
        "Authorization": f"Bearer {supabase_key}",
        "Content-Type": "application/json"
    }

    print(f"Checking for existing user with email: {args.email}")
    
    # We must list users and find by email. Admin API doesn't have a direct email filter, but it might.
    # Actually, GET /admin/users can be paginated, but for this bootstrap script we'll fetch first few pages or search.
    # Let's try direct lookup or fetching the list.
    users_url = f"{supabase_url.rstrip('/')}/auth/v1/admin/users"
    
    resp = requests.get(users_url, headers=headers, timeout=5.0)
    if resp.status_code != 200:
        print(f"Failed to list users: {resp.status_code} {resp.text}")
        sys.exit(1)

    users_data = resp.json().get("users", [])
    user_id = None
    for u in users_data:
        if u.get("email") == args.email:
            user_id = u.get("id")
            break

    temp_password = None
    is_new = False

    if not user_id:
        print("User not found. Creating new user...")
        temp_password = generate_secure_password()
        payload = {
            "email": args.email,
            "password": temp_password,
            "email_confirm": True
        }
        create_resp = requests.post(users_url, headers=headers, json=payload, timeout=5.0)
        if create_resp.status_code != 200:
            print(f"Failed to create user: {create_resp.status_code} {create_resp.text}")
            sys.exit(1)
        created_user = create_resp.json()
        user_id = created_user.get("id")
        is_new = True
        print(f"User created successfully. ID: {user_id}")
    else:
        print(f"Found existing user. ID: {user_id}")
        print("Promoting without changing password...")

    # Now assign admin role in public.user_roles
    roles_url = f"{supabase_url.rstrip('/')}/rest/v1/user_roles"
    roles_headers = {
        "apikey": supabase_key,
        "Authorization": f"Bearer {supabase_key}",
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates"
    }
    role_payload = {
        "user_id": user_id,
        "role": "admin"
    }
    role_resp = requests.post(roles_url, headers=roles_headers, json=role_payload, timeout=5.0)
    if role_resp.status_code not in [200, 201, 204]:
        print(f"Failed to assign admin role: {role_resp.status_code} {role_resp.text}")
        sys.exit(1)

    print("Admin role successfully assigned in public.user_roles.")

    # Ensure user_plans row exists (preserve existing, or create default free/active)
    plans_url = f"{supabase_url.rstrip('/')}/rest/v1/user_plans"
    plans_headers = {
        "apikey": supabase_key,
        "Authorization": f"Bearer {supabase_key}",
        "Content-Type": "application/json",
        "Prefer": "resolution=ignore-duplicates"
    }
    plan_payload = {
        "user_id": user_id,
        "plan": "free",
        "status": "active"
    }
    plan_resp = requests.post(plans_url, headers=plans_headers, json=plan_payload, timeout=5.0)
    if plan_resp.status_code not in [200, 201, 204]:
        print(f"Failed to ensure user_plans row: {plan_resp.status_code} {plan_resp.text}")
        sys.exit(1)
        
    print("User plans row safely verified/created.")

    if is_new:
        print("\n========================================================")
        print("TEMPORARY CREDENTIALS (STORE SECURELY):")
        print(f"Email:    {args.email}")
        print(f"Password: {temp_password}")
        print("========================================================\n")

if __name__ == "__main__":
    main()
