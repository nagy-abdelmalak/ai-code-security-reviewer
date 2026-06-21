from datetime import datetime, timedelta, timezone
import jwt
from jwt.exceptions import PyJWTError
import pytest

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password
)

# ------ Password hashing --------
def test_hash_password_different_hash():
    pw="password_123"
    h1=hash_password(pw)
    h2=hash_password(pw)

    assert h1 != h2
    assert verify_password(pw, h1)
    assert verify_password(pw, h2)

def test_verify_password_wrong_password():
    h = hash_password("correct_password")
    assert verify_password("Wrong_password", h) is False

def test_plain_not_in_hash():
    pw = "password_123"
    h = hash_password(pw)
    assert pw not in h

# ----- JWT tokens -------
def test_create_access_token_payload_content():
    token = create_access_token(subject="user-111", role="developer")
    payload = decode_token(token)

    assert payload["sub"] == "user-111"
    assert payload["role"] == "developer"
    assert payload["type"] == "access"
    assert "exp" in payload

def test_create_refresh_token_payload_content():
    token = create_refresh_token(subject="user-112")
    payload = decode_token(token)
    
    assert payload["sub"] == "user-112"
    assert payload["type"] == "refresh"
    assert "role" not in payload

def test_access_and_refresh_tokens_are_distinct():
    a_token = create_access_token(subject="user-100", role="admin")
    r_token = create_refresh_token(subject="user-100")
    assert a_token != r_token

def test_decode_token_rejects_tampered_token():
    token = create_access_token(subject="user-119", role="developer")
    tampered = token[:-2] + ("AA" if not token.endswith("AA") else "BB")
    print(token)
    print(token[:-2])
    print(tampered)

    with pytest.raises(PyJWTError):
        decode_token(tampered)

def test_decode_expired_token():
    expired_payload = {
        "sub": "user-222",
        "role": "developer",
        "type": "access",
        "exp": datetime.now(timezone.utc) - timedelta(seconds=1)
    }
    expired_token = jwt.encode(
        expired_payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    
    with pytest.raises(PyJWTError):
        decode_token(expired_token)

def test_decode_token_rejects_wrong_secret():
    foreign_token = jwt.encode(
        {"sub": "u"},
        "wrong-secret-that-is-also-at-least-32-bytes-long!!",
        algorithm=settings.jwt_algorithm,
    )
    with pytest.raises(PyJWTError):
        decode_token(foreign_token)