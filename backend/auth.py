"""
auth.py

Authentication helpers:
  - Password hashing / verification via bcrypt (passlib)
  - JWT access token creation / decoding via python-jose
  - users table schema + CRUD
  - FastAPI dependency: get_current_user
"""

import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from storage import get_connection
from utils import now_iso

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────
SECRET_KEY  = os.environ.get("SENTINEL_SECRET", "sentinel-dev-secret-change-in-prod")
ALGORITHM   = "HS256"
TOKEN_EXPIRE_MINUTES = 60 * 8   # 8 hours

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# ── Users table ───────────────────────────────────────────────
USERS_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    hashed_pw     TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'analyst',
    created_at    TEXT    NOT NULL
);
"""

def init_users_table() -> None:
    with get_connection() as conn:
        conn.executescript(USERS_SCHEMA)
    logger.info("Users table ready.")


# ── Password helpers ──────────────────────────────────────────
def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


# ── User CRUD ─────────────────────────────────────────────────
def create_user(username: str, email: str, password: str, role: str = "analyst") -> dict:
    hashed = hash_password(password)
    sql = """
        INSERT INTO users (username, email, hashed_pw, role, created_at)
        VALUES (?, ?, ?, ?, ?)
    """
    with get_connection() as conn:
        cursor = conn.execute(sql, (username, email, hashed, role, now_iso()))
        row_id = cursor.lastrowid
    return get_user_by_id(row_id)


def get_user_by_username(username: str) -> Optional[dict]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[dict]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    return dict(row) if row else None


def count_users() -> int:
    with get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
    return row[0] if row else 0


def get_all_users() -> list:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, username, email, role, created_at FROM users ORDER BY id"
        ).fetchall()
    return [dict(r) for r in rows]


def update_user_role(user_id: int, role: str) -> Optional[dict]:
    with get_connection() as conn:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    return get_user_by_id(user_id)


def delete_user(user_id: int) -> bool:
    with get_connection() as conn:
        cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return cursor.rowcount > 0


def authenticate_user(username: str, password: str) -> Optional[dict]:
    user = get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_pw"]):
        return None
    return user


# ── JWT ───────────────────────────────────────────────────────
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    payload = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=TOKEN_EXPIRE_MINUTES))
    payload.update({"exp": expire})
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── FastAPI dependency ────────────────────────────────────────
def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    payload = decode_token(token)
    username: str = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user
