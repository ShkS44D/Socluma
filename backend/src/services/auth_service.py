from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from src.core.config import get_settings
from src.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_refresh_token,
    verify_password,
)
from src.models.sqlalchemy import RefreshToken, User
from src.utils.datetime_utils import ensure_utc, get_utc_now


settings = get_settings()


class AuthService:
    def is_locked(self, user: User, now: Optional[datetime] = None) -> bool:
        if not user.locked_until:
            return False
        now = now or get_utc_now()
        return ensure_utc(user.locked_until) > ensure_utc(now)

    def record_failed_login(self, db: Session, user: User) -> bool:
        now = get_utc_now()
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        user.last_failed_login_at = now
        locked = False

        if user.failed_login_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=settings.ACCOUNT_LOCKOUT_MINUTES)
            locked = True

        db.commit()
        db.refresh(user)
        return locked

    def record_successful_login(self, db: Session, user: User) -> None:
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_failed_login_at = None
        user.last_login_at = get_utc_now()
        db.commit()
        db.refresh(user)

    def verify_login_password(self, db: Session, user: User, password: str) -> bool:
        if self.is_locked(user):
            return False
        if verify_password(password, user.hashed_password):
            return True
        self.record_failed_login(db, user)
        return False

    def create_token_pair(
        self,
        db: Session,
        user: User,
        *,
        request: Optional[Request] = None,
        family_id: Optional[str] = None,
    ) -> dict[str, str | int]:
        refresh_token_value = generate_refresh_token()
        refresh_record = RefreshToken(
            user_id=user.id,
            tenant_id=user.tenant_id,
            token_hash=hash_refresh_token(refresh_token_value),
            jti=secrets.token_urlsafe(24),
            family_id=family_id or str(uuid.uuid4()),
            expires_at=get_utc_now() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            user_agent=request.headers.get("user-agent")[:512] if request and request.headers.get("user-agent") else None,
            ip_address=self.client_ip(request),
        )
        db.add(refresh_record)
        db.commit()

        access_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        return {
            "access_token": create_access_token(
                data=self.access_token_subject(user),
                expires_delta=access_expires,
            ),
            "refresh_token": refresh_token_value,
            "token_type": "bearer",
            "expires_in": int(access_expires.total_seconds()),
        }

    def rotate_refresh_token(
        self,
        db: Session,
        refresh_token_value: str,
        *,
        request: Optional[Request] = None,
    ) -> tuple[User, dict[str, str | int]]:
        token_record = self._get_refresh_token_record(db, refresh_token_value)
        now = get_utc_now()

        if token_record.revoked_at:
            self.revoke_family(db, token_record.family_id, now=now)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked",
            )

        if ensure_utc(token_record.expires_at) <= now:
            token_record.revoked_at = now
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired",
            )

        user = token_record.user
        if not user or not user.is_active or not user.tenant or not user.tenant.is_active or self.is_locked(user):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is not authorized",
            )

        new_refresh_token_value = generate_refresh_token()
        replacement = RefreshToken(
            user_id=user.id,
            tenant_id=user.tenant_id,
            token_hash=hash_refresh_token(new_refresh_token_value),
            jti=secrets.token_urlsafe(24),
            family_id=token_record.family_id,
            expires_at=now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            user_agent=request.headers.get("user-agent")[:512] if request and request.headers.get("user-agent") else None,
            ip_address=self.client_ip(request),
        )
        db.add(replacement)
        db.flush()

        token_record.revoked_at = now
        token_record.last_used_at = now
        token_record.replaced_by_token_id = replacement.id
        db.commit()
        db.refresh(user)

        access_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        return user, {
            "access_token": create_access_token(
                data=self.access_token_subject(user),
                expires_delta=access_expires,
            ),
            "refresh_token": new_refresh_token_value,
            "token_type": "bearer",
            "expires_in": int(access_expires.total_seconds()),
        }

    def revoke_refresh_token(self, db: Session, refresh_token_value: str) -> Optional[RefreshToken]:
        token_record = (
            db.query(RefreshToken)
            .filter(RefreshToken.token_hash == hash_refresh_token(refresh_token_value))
            .first()
        )
        if not token_record:
            return None
        if not token_record.revoked_at:
            token_record.revoked_at = get_utc_now()
            db.commit()
            db.refresh(token_record)
        return token_record

    def revoke_user_sessions(self, db: Session, user_id: str, *, except_token_id: Optional[str] = None) -> int:
        now = get_utc_now()
        query = db.query(RefreshToken).filter(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked_at.is_(None),
        )
        if except_token_id:
            query = query.filter(RefreshToken.id != except_token_id)

        count = 0
        for token_record in query.all():
            token_record.revoked_at = now
            count += 1
        db.commit()
        return count

    def revoke_family(self, db: Session, family_id: str, *, now: Optional[datetime] = None) -> int:
        now = now or get_utc_now()
        count = 0
        for token_record in db.query(RefreshToken).filter(
            RefreshToken.family_id == family_id,
            RefreshToken.revoked_at.is_(None),
        ).all():
            token_record.revoked_at = now
            count += 1
        db.commit()
        return count

    def _get_refresh_token_record(self, db: Session, refresh_token_value: str) -> RefreshToken:
        token_record = (
            db.query(RefreshToken)
            .filter(RefreshToken.token_hash == hash_refresh_token(refresh_token_value))
            .first()
        )
        if not token_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )
        return token_record

    def access_token_subject(self, user: User) -> dict[str, str | int]:
        data: dict[str, str | int] = {"sub": str(user.id)}
        if user.password_changed_at:
            data["pwd"] = int(ensure_utc(user.password_changed_at).timestamp())
        return data

    def client_ip(self, request: Optional[Request]) -> Optional[str]:
        if request is None:
            return None
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.client.host if request.client else None


auth_service = AuthService()
