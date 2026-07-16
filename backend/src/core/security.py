from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional
import hashlib
import hmac
import secrets
from .config import get_settings

settings = get_settings()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def get_api_key_hash(api_key: str) -> str:
    return pwd_context.hash(api_key)


def verify_api_key(api_key: str, api_key_hash: str) -> bool:
    return pwd_context.verify(api_key, api_key_hash)


def generate_api_key(prefix: str = "src") -> str:
    return f"{prefix}_{secrets.token_urlsafe(24)}"


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None, jti: Optional[str] = None):
    to_encode = data.copy()
    issued_at = datetime.now(timezone.utc)
    if expires_delta:
        expire = issued_at + expires_delta
    else:
        expire = issued_at + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({
        "exp": expire,
        "iat": issued_at,
        "iss": settings.JWT_ISSUER,
        "typ": "access",
        "jti": jti or secrets.token_urlsafe(16),
    })
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def generate_refresh_token() -> str:
    """Generate an opaque refresh token suitable for browser storage."""
    return f"rt_{secrets.token_urlsafe(48)}"


def hash_refresh_token(token: str) -> str:
    """Hash refresh tokens before storage; plaintext tokens are never persisted."""
    return hmac.new(
        settings.REFRESH_TOKEN_SECRET.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def get_collector_token_lookup_hash(token: str) -> str:
    return hmac.new(
        settings.COLLECTOR_TOKEN_SECRET.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def generate_collector_token() -> str:
    """Generate a new collector token"""
    return f"ct_{secrets.token_urlsafe(32)}"


def get_collector_token_hash(token: str) -> str:
    """Hash a collector token for storage"""
    return pwd_context.hash(token)


def verify_collector_token(token: str, stored_value: str) -> tuple[bool, bool]:
    """
    Verify a collector token, with backward compatibility.
    Returns (is_valid, needs_migration)
    """
    import secrets
    
    # First try to verify as bcrypt hash
    try:
        if pwd_context.verify(token, stored_value):
            return (True, False)
    except Exception:
        # Not a valid bcrypt hash, try plaintext comparison
        pass
    
    # If that fails, check if stored_value is plaintext token (backward compatibility)
    if secrets.compare_digest(token, stored_value):
        # It's valid but needs migration to hash
        return (True, True)
    
    # Invalid token
    return (False, False)
