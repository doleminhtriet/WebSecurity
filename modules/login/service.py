"""
Simple authentication module using MongoDB-backed users.

Endpoints:
- POST /auth/register : create user (email + password)
- POST /auth/login    : authenticate and return JWT
- GET  /auth/me       : validate token and return user info

Notes:
- Expects a Mongo collection "users" with documents containing:
  { email, password_hash } (bcrypt) or legacy { email, password } (plaintext fallback)
- Set SECRET_KEY in environment for JWT signing; a dev default is used otherwise.
"""
from __future__ import annotations

import os
import secrets
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pymongo.errors import InvalidOperation

from core.config import load_config
from core.db.mongodb import get_db

router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer(auto_error=False)

_cfg: Dict[str, Any] = {}
_db = None
_dev_secret: str | None = None

# Load configuration and initialize database connection
def _load_db():
    global _cfg, _db
    _cfg = load_config()
    try:
        _db = get_db(_cfg)
    except Exception:
        _db = None

# Get the users collection
def _users_col():
    if _db is None:
        return None
    try:
        return _db["users"]
    except Exception:
        return None

# Get the secret key for JWT
def _get_secret() -> str:
    """
    Use SECRET_KEY env when provided; otherwise generate a per-process secret
    so tokens are invalidated on app restart (forces re-login in dev).
    """
    global _dev_secret
    env_secret = os.getenv("SECRET_KEY")
    if env_secret:
        return env_secret
    if _dev_secret is None:
        _dev_secret = secrets.token_urlsafe(32)
    return _dev_secret

# Hash a password using bcrypt
def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

# Verify a password against a stored hash
def _verify_password(password: str, stored: str) -> bool:
    if not stored:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored.encode("utf-8"))
    except ValueError:
        # fallback: plain text match
        return password == stored

# Create a JWT token for the given email
def _make_token(email: str, expires_minutes: int = 60 * 24) -> str:
    exp = datetime.utcnow() + timedelta(minutes=expires_minutes)
    payload = {"sub": email, "exp": exp, "iat": datetime.utcnow()}
    return jwt.encode(payload, _get_secret(), algorithm="HS256")

# Decode and validate a JWT token, returning the email
def _decode_token(token: str) -> str:
    try:
        data = jwt.decode(token, _get_secret(), algorithms=["HS256"])
        return data["sub"]
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# Get the current user from the token
def _get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Dict[str, Any]:
    if creds is None:
        raise HTTPException(status_code=401, detail="Missing credentials")
    email = _decode_token(creds.credentials)
    col = _users_col()

    # Fetch user from database
    if col is None:
        raise HTTPException(status_code=503, detail="Auth database unavailable")
    
    # Handle potential InvalidOperation if the DB connection was closed
    try:
        user = col.find_one({"email": email})
    except InvalidOperation:
        # Mongo client was closed; reload and retry once
        _load_db()
        col = _users_col()
        if col is None:
            raise HTTPException(status_code=503, detail="Auth database unavailable")
        user = col.find_one({"email": email})

    # User not found
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    user["_id"] = str(user["_id"])
    user.pop("password_hash", None)
    user.pop("password", None)
    return user

# Register a new user
@router.post("/register")
def register(payload: Dict[str, str]) -> Dict[str, Any]:
    """
    Create a new user. Requires mongodb.enabled and a "users" collection.
    """
    col = _users_col()
    if col is None:
        raise HTTPException(status_code=503, detail="Auth database unavailable")

    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")

    if col.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="User already exists")

    col.insert_one({
        "email": email,
        "password_hash": _hash_password(password),
        "created_at": datetime.utcnow(),
    })
    return {"ok": True, "message": "Registered"}

# User login
@router.post("/login")
def login(payload: Dict[str, str]) -> Dict[str, Any]:
    col = _users_col()

    # Fetch user from database
    if col is None:
        raise HTTPException(status_code=503, detail="Auth database unavailable")

    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""

    # Validate input
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")

    # Handle potential InvalidOperation if the DB connection was closed
    try:
        user = col.find_one({"email": email})
    except InvalidOperation:
        _load_db()
        col = _users_col()
        if col is None:
            raise HTTPException(status_code=503, detail="Auth database unavailable")
        user = col.find_one({"email": email})

    # User not found
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    stored = user.get("password_hash") or user.get("password")

    # Verify password
    if not _verify_password(password, stored):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = _make_token(email)
    return {"token": token, "user": {"email": email}}

# Get current user info
@router.get("/me")
def me(user=Depends(_get_current_user)) -> Dict[str, Any]:
    return {"user": user}


# Initialize on import
_load_db()
