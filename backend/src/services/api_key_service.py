from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy.orm import Session

from src.core.config import get_settings
from src.core.permissions import Permission
from src.models.sqlalchemy import OrganizationAPIKey, User
from src.utils.datetime_utils import ensure_utc, get_utc_now


settings = get_settings()
SAFE_API_KEY_SCOPES = frozenset({
    Permission.ALERTS_VIEW.value,
    Permission.ALERTS_CREATE.value,
    Permission.INCIDENTS_VIEW.value,
    Permission.DETECTIONS_VIEW.value,
    Permission.THREAT_INTELLIGENCE_VIEW.value,
    Permission.ASSETS_VIEW.value,
    Permission.REPORTS_VIEW.value,
})


class APIKeyService:
    def hash(self, raw: str) -> str:
        return hmac.new(settings.REFRESH_TOKEN_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()

    def validate_scopes(self, scopes: list[str]) -> list[str]:
        normalized = sorted(set(scopes))
        if not normalized or any(scope not in SAFE_API_KEY_SCOPES for scope in normalized):
            raise HTTPException(
                status_code=422,
                detail={"error_code": "API_KEY_SCOPE_INVALID", "message": "API key contains an unsupported scope"},
            )
        return normalized

    def create(self, db: Session, user: User, name: str, scopes: list[str], expires_in_days: int):
        raw = f"tok_{secrets.token_urlsafe(40)}"
        record = OrganizationAPIKey(
            tenant_id=user.tenant_id,
            created_by_id=user.id,
            name=name.strip(),
            key_prefix=raw[:16],
            key_hash=self.hash(raw),
            scopes=self.validate_scopes(scopes),
            expires_at=get_utc_now() + timedelta(days=expires_in_days),
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record, raw

    def authenticate(self, db: Session, raw: str, required_scope: str) -> OrganizationAPIKey:
        record = db.query(OrganizationAPIKey).filter_by(key_hash=self.hash(raw)).first()
        if (
            not record
            or record.revoked_at
            or ensure_utc(record.expires_at) <= get_utc_now()
            or required_scope not in (record.scopes or [])
        ):
            raise HTTPException(
                status_code=403,
                detail={"error_code": "API_KEY_SCOPE_DENIED", "message": "API key is invalid or lacks the required scope"},
            )
        record.last_used_at = get_utc_now()
        db.commit()
        return record


api_key_service = APIKeyService()
