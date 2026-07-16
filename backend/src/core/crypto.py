from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from cryptography.fernet import Fernet

from src.core.config import get_settings


def _fernet_key() -> bytes:
    settings = get_settings()
    material = f"{settings.SECRET_KEY}:{settings.REFRESH_TOKEN_SECRET}".encode("utf-8")
    digest = hashlib.sha256(material).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_json_secret(secret: dict[str, Any]) -> str:
    payload = json.dumps(secret, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return Fernet(_fernet_key()).encrypt(payload).decode("utf-8")


def decrypt_json_secret(encrypted_secret: str) -> dict[str, Any]:
    payload = Fernet(_fernet_key()).decrypt(encrypted_secret.encode("utf-8"))
    data = json.loads(payload.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Credential secret must decrypt to an object")
    return data


def fingerprint_secret(secret: dict[str, Any]) -> str:
    settings = get_settings()
    payload = json.dumps(secret, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(settings.REFRESH_TOKEN_SECRET.encode("utf-8"), payload, hashlib.sha256).hexdigest()
