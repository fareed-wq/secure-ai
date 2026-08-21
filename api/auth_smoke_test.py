from fastapi import APIRouter, Security
from api.auth.entitlements import get_current_user, require_admin

router = APIRouter()

@router.get("/api/auth-smoke-test")
def auth_smoke_test(user: dict = Security(get_current_user)):
    if not user:
        return {"status": "success", "message": "Guest route working (no auth).", "user": None}
    return {"status": "success", "message": "Authenticated route working.", "user": user.get("sub")}

@router.get("/api/auth-smoke-test-protected")
def auth_smoke_test_protected(user: dict = Security(require_admin)):
    return {"status": "success", "message": "Admin route working.", "user": user.get("sub")}
