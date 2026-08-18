from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from src.core.config import get_settings


class DecryptionError(ValueError):
    pass


def _key_material(version: int) -> str:
    settings = get_settings()
    if settings.ENCRYPTION_KEYS_JSON:
        keys = json.loads(settings.ENCRYPTION_KEYS_JSON)
        material = keys.get(str(version))
        if not material:
            raise DecryptionError("DECRYPTION_FAILED")
        return material
    if version != 1:
        raise DecryptionError("DECRYPTION_FAILED")
    return f"{settings.SECRET_KEY}:{settings.REFRESH_TOKEN_SECRET}"


def _fernet_key(version: int) -> bytes:
    material = _key_material(version).encode("utf-8")
    digest = hashlib.sha256(material).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_json_secret(secret: dict[str, Any], *, key_version: int | None = None) -> str:
    settings = get_settings()
    version = key_version or settings.ENCRYPTION_CURRENT_KEY_VERSION
    payload = json.dumps(secret, sort_keys=True, separators=(",", ":")).encode("utf-8")
    token = Fernet(_fernet_key(version)).encrypt(payload).decode("utf-8")
    return f"v{version}:{token}"


def encrypt_bytes(payload: bytes, *, key_version: int | None = None) -> bytes:
    settings = get_settings()
    version = key_version or settings.ENCRYPTION_CURRENT_KEY_VERSION
    return f"v{version}:".encode() + Fernet(_fernet_key(version)).encrypt(payload)


def encrypted_key_version(encrypted_secret: str) -> int:
    if encrypted_secret.startswith("v") and ":" in encrypted_secret:
        prefix = encrypted_secret.split(":", 1)[0]
        if prefix[1:].isdigit():
            return int(prefix[1:])
    return 1


def decrypt_json_secret(encrypted_secret: str, *, key_version: int | None = None) -> dict[str, Any]:
    embedded_version = encrypted_key_version(encrypted_secret)
    version = key_version or embedded_version
    token = encrypted_secret.split(":", 1)[1] if encrypted_secret.startswith(f"v{embedded_version}:") else encrypted_secret
    try:
        payload = Fernet(_fernet_key(version)).decrypt(token.encode("utf-8"))
        data = json.loads(payload.decode("utf-8"))
    except (InvalidToken, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise DecryptionError("DECRYPTION_FAILED") from exc
    if not isinstance(data, dict):
        raise DecryptionError("DECRYPTION_FAILED")
    return data


def decrypt_bytes(payload: bytes) -> bytes:
    try:
        prefix, token = payload.split(b":", 1)
        if not prefix.startswith(b"v") or not prefix[1:].isdigit():
            raise DecryptionError("DECRYPTION_FAILED")
        return Fernet(_fernet_key(int(prefix[1:]))).decrypt(token)
    except (InvalidToken, ValueError, TypeError) as exc:
        raise DecryptionError("DECRYPTION_FAILED") from exc


def fingerprint_secret(secret: dict[str, Any]) -> str:
    settings = get_settings()
    payload = json.dumps(secret, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(settings.REFRESH_TOKEN_SECRET.encode("utf-8"), payload, hashlib.sha256).hexdigest()
