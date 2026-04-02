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
    get_current_user, get_all_users, get_user_by_username, count_users,
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
