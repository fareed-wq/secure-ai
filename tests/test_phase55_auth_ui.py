import os
import re
import pytest

def test_register_no_otp_flow():
    with open(os.path.join('src', 'pages', 'Register.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()

    assert "verifyOtp" not in src, "verifyOtp must be removed from Register"
    assert "signInWithOtp" not in src, "signInWithOtp must be removed from Register"
    assert "otpCode" not in src, "OTP input field must be removed"
    assert "supabase.auth.resend(" in src, "Must use resend for signup confirmation"
    assert "type: 'signup'" in src, "Resend must use type: signup"
    assert "captchaPromiseRef" not in src, "captchaPromiseRef should be removed"

def test_login_no_otp_flow():
    with open(os.path.join('src', 'pages', 'Login.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()

    assert "verifyOtp" not in src, "verifyOtp must be removed from Login"
    assert "signInWithOtp" not in src, "signInWithOtp must be removed from Login"
    assert "otpToken" not in src, "OTP input field must be removed"
    assert "supabase.auth.resend(" in src, "Must use resend for unconfirmed email fallback"
    assert "type: 'signup'" in src, "Resend must use type: signup"

def test_backend_phone_architecture():
    with open(os.path.join('api', 'auth', 'register.py'), 'r', encoding='utf-8') as f:
        src = f.read()

    assert "'phone': req.phone" not in src, "Phone must NOT be sent to admin.create_user to avoid Auth uniqueness constraints"
    assert "requests.patch" in src and "/rest/v1/profiles" in src, "Must store phone in public.profiles"

def test_admin_phone_source():
    with open(os.path.join('api', 'admin.py'), 'r', encoding='utf-8') as f:
        src = f.read()

    assert "profiles_map" in src, "Admin fetch must include profiles data"
    assert 'phone": profiles_map.get' in src, "Phone must be mapped from profiles, not auth.users"
    assert "verification = \"Provided\"" in src, "Verification status should simply be Provided/Not provided"

def test_settings_phone_source():
    with open(os.path.join('src', 'pages', 'Settings.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()

    assert "supabase.from('profiles').select('phone')" in src, "Settings must load phone from profiles"

def test_settings_delete_session_clear():
    with open(os.path.join('src', 'pages', 'Settings.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()

    assert "supabase.auth.signOut({ scope: 'local' })" in src, "Must use scope local to avoid phantom session"
