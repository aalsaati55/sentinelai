"""
routers/auth.py

POST /api/auth/register  — create a new user account
POST /api/auth/login     — authenticate and receive JWT token
GET  /api/auth/me        — return current logged-in user info
GET  /api/auth/users     — list all users (admin only)
"""

import re
import logging
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional

from auth import (
    create_user, authenticate_user, create_access_token,
    get_current_user, get_all_users, get_user_by_id,
    get_user_by_username, update_user_role, delete_user, count_users,
    generate_totp_secret, get_totp_uri, verify_totp,
    save_totp_secret, enable_mfa, disable_mfa,
    verify_password, change_password,
)
from storage import (
    add_audit_log,
    add_user_notification, get_user_notifications,
    mark_user_notifications_read, clear_user_notifications,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])

# ── Validation helpers ────────────────────────────────────────

REQUIRED_DOMAIN = "sentinelai.com"

# local part: letters/numbers/dots, must contain at least one digit
_LOCAL_RE   = re.compile(r'^[a-zA-Z][a-zA-Z0-9.]+[0-9]+$')
# At least one special character
_SPECIAL_CHAR_RE = re.compile(r'[!@#$%^&*()_+\-=\[\]{};\'\\:"|,.<>\/?`~]')
# At least one digit
_DIGIT_RE = re.compile(r'\d')
# At least one uppercase letter
_UPPER_RE = re.compile(r'[A-Z]')


def validate_email(email: str) -> str:
    email = email.strip().lower()
    if '@' not in email:
        raise HTTPException(status_code=400, detail=f"Email must be a @{REQUIRED_DOMAIN} address")
    local, domain = email.split('@', 1)
    if domain != REQUIRED_DOMAIN:
        raise HTTPException(
            status_code=400,
            detail=f"Only @{REQUIRED_DOMAIN} email addresses are accepted"
        )
    if not _LOCAL_RE.match(local):
        raise HTTPException(
            status_code=400,
            detail=f"Email local part must start with a letter, contain only letters/numbers/dots, and include at least one number (e.g. john.doe1@{REQUIRED_DOMAIN})"
        )
    return email


def validate_password(password: str) -> None:
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not _UPPER_RE.search(password):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter")
    if not _DIGIT_RE.search(password):
        raise HTTPException(status_code=400, detail="Password must contain at least one number")
    if not _SPECIAL_CHAR_RE.search(password):
        raise HTTPException(status_code=400, detail="Password must contain at least one special character (!@#$%^&* etc.)")


# ── Schemas ───────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str
    mfa_required: bool = False
    mfa_token: Optional[str] = None

class MfaConfirmRequest(BaseModel):
    mfa_token: str
    code: str

class MfaVerifyRequest(BaseModel):
    code: str

class MfaDisableRequest(BaseModel):
    code: str

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_at: str


# ── Endpoints ─────────────────────────────────────────────────

@router.post("/register", response_model=UserOut, status_code=201)
def register(body: RegisterRequest):
    if len(body.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if not re.match(r'^[a-zA-Z0-9_\-]+$', body.username):
        raise HTTPException(status_code=400, detail="Username may only contain letters, numbers, _ and -")
    clean_email = validate_email(body.email)
    validate_password(body.password)

    if get_user_by_username(body.username):
        raise HTTPException(status_code=409, detail="Username already taken")

    # First user ever becomes admin, everyone else is analyst
    role = "admin" if count_users() == 0 else "analyst"

    try:
        user = create_user(
            username=body.username,
            email=clean_email,
            password=body.password,
            role=role,
        )
    except Exception as e:
        if "UNIQUE" in str(e):
            raise HTTPException(status_code=409, detail="Username or email already exists")
        raise HTTPException(status_code=500, detail="Could not create user")
    logger.info(f"New user registered: {user['username']} ({user['role']})")
    return user


@router.post("/login", response_model=TokenResponse)
def login(form: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form.username, form.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # If MFA is enabled, return a short-lived MFA challenge token instead of a full session token
    if user.get("mfa_enabled"):
        mfa_token = create_access_token(
            {"sub": user["username"], "role": user["role"], "mfa_pending": True},
            expires_delta=__import__('datetime').timedelta(minutes=5),
        )
        logger.info(f"MFA challenge issued for: {user['username']}")
        return {
            "access_token": "",
            "token_type":   "bearer",
            "username":     user["username"],
            "role":         user["role"],
            "mfa_required": True,
            "mfa_token":    mfa_token,
        }

    token = create_access_token({"sub": user["username"], "role": user["role"]})
    logger.info(f"User logged in: {user['username']}")
    return {
        "access_token": token,
        "token_type":   "bearer",
        "username":     user["username"],
        "role":         user["role"],
    }


@router.get("/me", response_model=UserOut)
def me(current_user: dict = Depends(get_current_user)):
    return current_user


@router.get("/users", response_model=list[UserOut])
def list_users(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return get_all_users()


class UpdateRoleRequest(BaseModel):
    role: str


@router.patch("/users/{user_id}/role", response_model=UserOut)
def change_role(user_id: int, body: UpdateRoleRequest, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    if body.role not in ("admin", "analyst"):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'analyst'")
    if current_user["id"] == user_id:
        raise HTTPException(status_code=400, detail="You cannot change your own role")
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    updated = update_user_role(user_id, body.role)
    add_audit_log(current_user["username"], "role_change", "user", user_id, f"{user['username']} role → {body.role}")
    logger.info(f"Admin {current_user['username']} changed user {user_id} role to {body.role}")
    return updated


# ── MFA Endpoints ─────────────────────────────────────────────

@router.post("/mfa/confirm", response_model=TokenResponse)
def mfa_confirm(body: MfaConfirmRequest):
    """Exchange MFA challenge token + TOTP code for a full session token."""
    from auth import decode_token
    try:
        payload = decode_token(body.mfa_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA token")
    if not payload.get("mfa_pending"):
        raise HTTPException(status_code=400, detail="Not an MFA challenge token")
    username = payload.get("sub")
    user = get_user_by_username(username)
    if not user or not user.get("totp_secret"):
        raise HTTPException(status_code=401, detail="MFA not configured")
    if not verify_totp(user["totp_secret"], body.code.strip()):
        raise HTTPException(status_code=401, detail="Invalid authenticator code")
    token = create_access_token({"sub": user["username"], "role": user["role"]})
    logger.info(f"MFA verified, user logged in: {user['username']}")
    return {
        "access_token": token,
        "token_type":   "bearer",
        "username":     user["username"],
        "role":         user["role"],
    }


@router.post("/mfa/setup")
def mfa_setup(current_user: dict = Depends(get_current_user)):
    """Generate a new TOTP secret and return the QR provisioning URI."""
    if current_user.get("mfa_enabled"):
        raise HTTPException(status_code=400, detail="MFA is already enabled")
    secret = generate_totp_secret()
    save_totp_secret(current_user["id"], secret)
    uri = get_totp_uri(secret, current_user["username"])
    return {"secret": secret, "uri": uri}


@router.post("/mfa/enable")
def mfa_enable(body: MfaVerifyRequest, current_user: dict = Depends(get_current_user)):
    """Confirm TOTP code to activate MFA on the account."""
    user = get_user_by_username(current_user["username"])
    if not user or not user.get("totp_secret"):
        raise HTTPException(status_code=400, detail="Run /mfa/setup first")
    if user.get("mfa_enabled"):
        raise HTTPException(status_code=400, detail="MFA already enabled")
    if not verify_totp(user["totp_secret"], body.code.strip()):
        raise HTTPException(status_code=401, detail="Invalid authenticator code")
    enable_mfa(current_user["id"])
    add_audit_log(current_user["username"], "mfa_enabled", "user", current_user["id"], "MFA enabled")
    logger.info(f"MFA enabled for {current_user['username']}")
    return {"detail": "MFA enabled successfully"}


@router.post("/mfa/disable")
def mfa_disable(body: MfaDisableRequest, current_user: dict = Depends(get_current_user)):
    """Disable MFA — requires current TOTP code to confirm."""
    user = get_user_by_username(current_user["username"])
    if not user or not user.get("mfa_enabled"):
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    if not verify_totp(user["totp_secret"], body.code.strip()):
        raise HTTPException(status_code=401, detail="Invalid authenticator code")
    disable_mfa(current_user["id"])
    add_audit_log(current_user["username"], "mfa_disabled", "user", current_user["id"], "MFA disabled")
    logger.info(f"MFA disabled for {current_user['username']}")
    return {"detail": "MFA disabled"}


@router.get("/mfa/status")
def mfa_status(current_user: dict = Depends(get_current_user)):
    """Return current MFA status for the logged-in user."""
    user = get_user_by_username(current_user["username"])
    return {"mfa_enabled": bool(user.get("mfa_enabled")), "username": user["username"]}


# ── Password Change ───────────────────────────────────────────

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

@router.post("/change-password", status_code=200)
def change_password_endpoint(body: ChangePasswordRequest, current_user: dict = Depends(get_current_user)):
    if not verify_password(body.current_password, current_user["hashed_pw"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    validate_password(body.new_password)
    if body.current_password == body.new_password:
        raise HTTPException(status_code=400, detail="New password must differ from current password")
    change_password(current_user["id"], body.new_password)
    add_audit_log(current_user["username"], "password_changed", "user", current_user["id"], "Password changed")
    logger.info(f"Password changed for {current_user['username']}")
    return {"detail": "Password changed successfully"}


# ── User Notifications ────────────────────────────────────────

@router.get("/notifications")
def list_notifications(since: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    """Poll for user-targeted in-app notifications (assignment, @mention)."""
    return get_user_notifications(current_user["username"], since_iso=since, limit=30)


@router.post("/notifications/read", status_code=204)
def mark_read(current_user: dict = Depends(get_current_user)):
    mark_user_notifications_read(current_user["username"])


@router.delete("/notifications", status_code=204)
def clear_notifications(current_user: dict = Depends(get_current_user)):
    clear_user_notifications(current_user["username"])


class AdminResetPasswordRequest(BaseModel):
    new_password: str

@router.post("/users/{user_id}/reset-password", status_code=200)
def admin_reset_password(user_id: int, body: AdminResetPasswordRequest, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    validate_password(body.new_password)
    change_password(user_id, body.new_password)
    add_audit_log(current_user["username"], "password_reset", "user", user_id, f"Admin reset password for {user['username']}")
    logger.info(f"Admin {current_user['username']} reset password for user {user_id}")
    return {"detail": "Password reset successfully"}


@router.delete("/users/{user_id}", status_code=204)
def remove_user(user_id: int, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    if current_user["id"] == user_id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    add_audit_log(current_user["username"], "user_deleted", "user", user_id, f"Deleted user: {user['username']}")
    delete_user(user_id)
    logger.info(f"Admin {current_user['username']} deleted user {user_id}")
