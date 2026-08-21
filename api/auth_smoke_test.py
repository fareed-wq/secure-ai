from fastapi import APIRouter, Security
from api.auth.entitlements import require_current_user, require_admin

router = APIRouter()

@router.get("/api/auth-smoke-test")
def auth_smoke_test(user: dict = Security(require_current_user)):
    return {"status": "success", "message": "Authenticated route working.", "user": user.get("sub")}

@router.get("/api/auth-smoke-test-protected")
def auth_smoke_test_protected(user: dict = Security(require_admin)):
    return {"status": "success", "message": "Admin route working.", "user": user.get("sub")}
