from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from passlib.context import CryptContext

PASSWORD_CTX = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto"
)

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    return PASSWORD_CTX.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return PASSWORD_CTX.verify(password, hashed)


def create_access_token(subject: str, secret: str, expires_minutes: int = 7 * 24 * 60) -> str:
    payload = {
        "sub": subject,
        "iat": int(now_utc().timestamp()),
        "exp": int((now_utc() + timedelta(minutes=expires_minutes)).timestamp()),
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_access_token(token: str, secret: str) -> Optional[dict]:
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except Exception:
        return None


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def random_id(prefix: str = "") -> str:
    return prefix + secrets.token_urlsafe(18).replace("-", "").replace("_", "")
