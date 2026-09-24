import os
import re
import pytest

def test_register_otp_fresh_captcha():
    with open(os.path.join('src', 'pages', 'Register.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()

    # Must wait for fresh token using promise before signInWithOtp
    assert "freshToken = await new Promise" in src, "Must await fresh Turnstile token"
    assert "captchaPromiseRef.current = resolve" in src, "Must assign promise resolver"
    assert "captchaToken: freshToken" in src, "Must pass fresh token to signInWithOtp"
    assert "turnstileRef.current?.reset()" in src, "Must reset turnstile before waiting"
    assert "shouldCreateUser: false" in src, "Must retain shouldCreateUser: false"

def test_login_otp_fresh_captcha():
    with open(os.path.join('src', 'pages', 'Login.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()

    # Unconfirmed email fallback must wait for fresh token
    assert "freshToken = await new Promise" in src, "Must await fresh Turnstile token"
    assert "captchaToken: freshToken" in src, "Must pass fresh token to signInWithOtp"
    assert "shouldCreateUser: false" in src, "Must retain shouldCreateUser: false"

def test_settings_delete_session_clear():
    with open(os.path.join('src', 'pages', 'Settings.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()

    # Must clear local session properly
    assert "supabase.auth.signOut({ scope: 'local' })" in src, "Must use scope local to avoid phantom session"
