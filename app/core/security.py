import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from datetime import datetime, timedelta, timezone

from app.core.config import settings

# Password hasing
_ph = PasswordHasher()

def hash_password(plain_password: str) -> str:
    return _ph.hash(plain_password)

def verify_password(plain_password: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, plain_password)
    except VerifyMismatchError:
        return False

# JWT
def _create_token(payload: dict, ttl: timedelta) -> str:
    """Internal: create a signed JWT with an expiry"""
    to_encode = payload.copy()
    to_encode["exp"] = datetime.now(timezone.utc) + ttl
    return jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )

def create_access_token(subject: str, role: str) -> str:
    """Create a JWT access token with expiration and role claims."""
    return _create_token(
        payload={"sub": subject, "role": role, "type": "access"},
        ttl= timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )

def create_refresh_token(subject: str) -> str:
    """Create a long-lived refresh token (7 days, ADR-006)."""
    return _create_token(
        payload={"sub": subject, "type": "refresh"},
        ttl= timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

def decode_token(token: str) -> dict:
    """Verify and decode JWT token. Raises JWTError if invalid."""
    return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])