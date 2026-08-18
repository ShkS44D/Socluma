from __future__ import annotations

import base64
import hashlib
import hmac
import io
import secrets
import struct
import time
from datetime import timedelta
from urllib.parse import quote

import jwt
from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from src.core.config import get_settings
from src.core.crypto import decrypt_json_secret, encrypt_json_secret
from src.core.security import get_password_hash, verify_password
from src.models.sqlalchemy import (
    AuthChallenge,
    AuthOneTimeToken,
    AuthSecurityEvent,
    KnownAuthDevice,
    MFARecoveryCode,
    User,
)
from src.services.auth_email_service import auth_email_service
from src.services.password_policy import validate_new_password
from src.utils.datetime_utils import ensure_utc, get_utc_now


settings = get_settings()


class AccountSecurityService:
    def token_hash(self, value: str) -> str:
        return hmac.new(
            settings.REFRESH_TOKEN_SECRET.encode(),
            value.encode(),
            hashlib.sha256,
        ).hexdigest()

    def client_ip(self, request: Request | None) -> str | None:
        if request is None:
            return None
        forwarded = request.headers.get("x-forwarded-for")
        return forwarded.split(",")[0].strip() if forwarded else request.client.host if request.client else None

    def user_agent(self, request: Request | None) -> str | None:
        value = request.headers.get("user-agent") if request else None
        return value[:512] if value else None

    def device_label(self, user_agent: str | None) -> str:
        if not user_agent:
            return "Unknown device"
        lowered = user_agent.lower()
        browser = next((name for key, name in (("edg", "Edge"), ("chrome", "Chrome"), ("firefox", "Firefox"), ("safari", "Safari")) if key in lowered), "Browser")
        os_name = next((name for key, name in (("windows", "Windows"), ("android", "Android"), ("iphone", "iPhone"), ("mac os", "macOS"), ("linux", "Linux")) if key in lowered), "Unknown OS")
        return f"{browser} on {os_name}"

    def record_event(
        self,
        db: Session,
        user: User,
        event_type: str,
        *,
        request: Request | None = None,
        result: str = "success",
        severity: str = "informational",
        reason_code: str | None = None,
        details: dict | None = None,
        commit: bool = True,
    ) -> AuthSecurityEvent:
        ua = self.user_agent(request)
        event = AuthSecurityEvent(
            user_id=user.id,
            tenant_id=user.tenant_id,
            event_type=event_type,
            result=result,
            severity=severity,
            reason_code=reason_code,
            ip_address=self.client_ip(request),
            user_agent=ua,
            device_label=self.device_label(ua),
            request_id=getattr(request.state, "request_id", None) if request else None,
            details=details or {},
        )
        db.add(event)
        if commit:
            db.commit()
        else:
            db.flush()
        return event

    def suspicious_login_reasons(self, db: Session, user: User, request: Request) -> list[str]:
        ip = self.client_ip(request) or ""
        ua = self.user_agent(request) or ""
        fingerprint = self.token_hash(f"{ip}\n{ua}")
        device = db.query(KnownAuthDevice).filter_by(user_id=user.id, fingerprint_hash=fingerprint).first()
        reasons = []
        if device is None:
            seen_ip = db.query(KnownAuthDevice).filter_by(user_id=user.id, ip_address=ip).first() if ip else None
            reasons.append("unseen_device" if seen_ip else "unseen_ip")
            db.add(
                KnownAuthDevice(
                    user_id=user.id,
                    fingerprint_hash=fingerprint,
                    ip_address=ip or None,
                    user_agent=ua or None,
                    device_label=self.device_label(ua),
                    last_seen_at=get_utc_now(),
                )
            )
        else:
            device.last_seen_at = get_utc_now()
        if user.failed_login_attempts and user.failed_login_attempts >= 2:
            reasons.append("failed_logins_before_success")
        recent = get_utc_now() - timedelta(minutes=10)
        recent_ips = {
            row[0]
            for row in db.query(AuthSecurityEvent.ip_address).filter(
                AuthSecurityEvent.user_id == user.id,
                AuthSecurityEvent.event_type == "session_created",
                AuthSecurityEvent.created_at >= recent,
                AuthSecurityEvent.ip_address.isnot(None),
            )
        }
        if ip and recent_ips and ip not in recent_ips:
            reasons.append("rapid_multi_ip_sessions")
        return reasons

    def _totp(self, secret: str, step: int) -> str:
        key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
        digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        number = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
        return f"{number:06d}"

    def verify_totp(self, secret: str, code: str, *, last_step: int | None = None, at_time: int | None = None) -> int | None:
        if not code.isdigit() or len(code) != 6:
            return None
        current = int((at_time or time.time()) // 30)
        for step in (current - 1, current, current + 1):
            if last_step is not None and step <= last_step:
                continue
            if secrets.compare_digest(self._totp(secret, step), code):
                return step
        return None

    def provisioning_uri(self, user: User, secret: str) -> str:
        label = quote(f"{settings.MFA_ISSUER}:{user.email}")
        return f"otpauth://totp/{label}?secret={secret}&issuer={quote(settings.MFA_ISSUER)}&algorithm=SHA1&digits=6&period=30"

    def qr_data_url(self, uri: str) -> str:
        import qrcode

        image = qrcode.make(uri)
        output = io.BytesIO()
        image.save(output, format="PNG")
        return "data:image/png;base64," + base64.b64encode(output.getvalue()).decode()

    def start_mfa(self, db: Session, user: User, password: str) -> dict:
        if user.mfa_enabled_at:
            raise HTTPException(status_code=409, detail={"error_code": "MFA_ALREADY_ENABLED", "message": "MFA is already enabled"})
        if not verify_password(password, user.hashed_password):
            raise HTTPException(status_code=400, detail={"error_code": "AUTHENTICATION_FAILED", "message": "Current password is incorrect"})
        secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        user.mfa_pending_secret_encrypted = encrypt_json_secret({"totp_secret": secret})
        user.mfa_pending_secret_key_version = settings.ENCRYPTION_CURRENT_KEY_VERSION
        user.mfa_pending_expires_at = get_utc_now() + timedelta(minutes=settings.MFA_ENROLLMENT_MINUTES)
        db.commit()
        uri = self.provisioning_uri(user, secret)
        return {"provisioning_uri": uri, "manual_key": secret, "qr_code_data_url": self.qr_data_url(uri), "expires_at": user.mfa_pending_expires_at}

    def _pending_secret(self, db: Session, user: User) -> str:
        if (
            not user.mfa_pending_secret_encrypted
            or not user.mfa_pending_expires_at
            or ensure_utc(user.mfa_pending_expires_at) <= get_utc_now()
        ):
            user.mfa_pending_secret_encrypted = None
            user.mfa_pending_secret_key_version = None
            user.mfa_pending_expires_at = None
            db.commit()
            raise HTTPException(status_code=400, detail={"error_code": "TOKEN_EXPIRED", "message": "MFA enrollment has expired"})
        return str(decrypt_json_secret(user.mfa_pending_secret_encrypted)["totp_secret"])

    def _new_recovery_codes(self, db: Session, user: User) -> list[str]:
        db.query(MFARecoveryCode).filter_by(user_id=user.id).delete(synchronize_session=False)
        codes = []
        for _ in range(10):
            value = base64.b32encode(secrets.token_bytes(8)).decode().rstrip("=")[:12]
            codes.append(f"{value[:4]}-{value[4:8]}-{value[8:12]}")
        db.add_all([MFARecoveryCode(user_id=user.id, code_hash=self.token_hash(code)) for code in codes])
        return codes

    def confirm_mfa(self, db: Session, user: User, code: str) -> list[str]:
        secret = self._pending_secret(db, user)
        step = self.verify_totp(secret, code)
        if step is None:
            raise HTTPException(status_code=400, detail={"error_code": "MFA_INVALID", "message": "Invalid authentication code"})
        user.mfa_secret_encrypted = user.mfa_pending_secret_encrypted
        user.mfa_secret_key_version = user.mfa_pending_secret_key_version
        user.mfa_pending_secret_encrypted = None
        user.mfa_pending_secret_key_version = None
        user.mfa_pending_expires_at = None
        user.mfa_enabled_at = get_utc_now()
        user.mfa_last_totp_step = step
        codes = self._new_recovery_codes(db, user)
        db.commit()
        return codes

    def active_secret(self, user: User) -> str:
        if not user.mfa_enabled_at or not user.mfa_secret_encrypted:
            raise HTTPException(status_code=409, detail={"error_code": "MFA_NOT_ENABLED", "message": "MFA is not enabled"})
        return str(decrypt_json_secret(user.mfa_secret_encrypted)["totp_secret"])

    def verify_user_totp(self, db: Session, user: User, code: str) -> bool:
        now = get_utc_now()
        if user.mfa_locked_until and ensure_utc(user.mfa_locked_until) > now:
            raise HTTPException(status_code=423, detail={"error_code": "MFA_LOCKED", "message": "MFA verification is temporarily locked"})
        step = self.verify_totp(self.active_secret(user), code, last_step=user.mfa_last_totp_step)
        if step is None:
            user.mfa_failed_attempts = (user.mfa_failed_attempts or 0) + 1
            if user.mfa_failed_attempts >= settings.MFA_FAILURE_LIMIT:
                user.mfa_locked_until = now + timedelta(minutes=settings.MFA_LOCKOUT_MINUTES)
                user.mfa_failed_attempts = 0
            db.commit()
            return False
        user.mfa_last_totp_step = step
        user.mfa_failed_attempts = 0
        user.mfa_locked_until = None
        db.commit()
        return True

    def disable_mfa(self, db: Session, user: User, password: str, code: str) -> None:
        if not verify_password(password, user.hashed_password):
            raise HTTPException(status_code=400, detail={"error_code": "AUTHENTICATION_FAILED", "message": "Current password is incorrect"})
        if not self.verify_user_totp(db, user, code):
            raise HTTPException(status_code=400, detail={"error_code": "MFA_INVALID", "message": "Invalid authentication code"})
        user.mfa_secret_encrypted = None
        user.mfa_secret_key_version = None
        user.mfa_enabled_at = None
        user.mfa_last_totp_step = None
        db.query(MFARecoveryCode).filter_by(user_id=user.id).delete(synchronize_session=False)
        db.commit()

    def regenerate_recovery(self, db: Session, user: User, password: str, code: str) -> list[str]:
        if not verify_password(password, user.hashed_password):
            raise HTTPException(status_code=400, detail={"error_code": "AUTHENTICATION_FAILED", "message": "Current password is incorrect"})
        if not self.verify_user_totp(db, user, code):
            raise HTTPException(status_code=400, detail={"error_code": "MFA_INVALID", "message": "Invalid authentication code"})
        codes = self._new_recovery_codes(db, user)
        db.commit()
        return codes

    def use_recovery_code(self, db: Session, user: User, code: str) -> bool:
        hashed = self.token_hash(code.strip().upper())
        record = db.query(MFARecoveryCode).filter_by(user_id=user.id, code_hash=hashed, used_at=None).first()
        if not record:
            return False
        record.used_at = get_utc_now()
        db.commit()
        return True

    def create_challenge(self, db: Session, user: User, request: Request) -> str:
        now = get_utc_now()
        jti = secrets.token_urlsafe(24)
        expires = now + timedelta(minutes=settings.MFA_CHALLENGE_MINUTES)
        db.add(AuthChallenge(user_id=user.id, jti=jti, expires_at=expires, ip_address=self.client_ip(request), user_agent=self.user_agent(request)))
        db.commit()
        return jwt.encode(
            {"sub": user.id, "jti": jti, "typ": "mfa", "iss": settings.JWT_ISSUER, "iat": now, "exp": expires},
            settings.JWT_SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )

    def consume_challenge(self, db: Session, challenge_token: str) -> tuple[AuthChallenge, User]:
        try:
            payload = jwt.decode(challenge_token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM], issuer=settings.JWT_ISSUER)
        except jwt.ExpiredSignatureError as exc:
            raise HTTPException(status_code=401, detail={"error_code": "TOKEN_EXPIRED", "message": "MFA challenge expired"}) from exc
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=401, detail={"error_code": "TOKEN_INVALID", "message": "Invalid MFA challenge"}) from exc
        if payload.get("typ") != "mfa":
            raise HTTPException(status_code=401, detail={"error_code": "TOKEN_INVALID", "message": "Invalid MFA challenge"})
        challenge = db.query(AuthChallenge).filter_by(jti=payload.get("jti"), user_id=payload.get("sub")).with_for_update().first()
        if not challenge or challenge.used_at:
            raise HTTPException(status_code=401, detail={"error_code": "TOKEN_INVALID", "message": "Invalid MFA challenge"})
        if ensure_utc(challenge.expires_at) <= get_utc_now():
            raise HTTPException(status_code=401, detail={"error_code": "TOKEN_EXPIRED", "message": "MFA challenge expired"})
        if challenge.locked_until and ensure_utc(challenge.locked_until) > get_utc_now():
            raise HTTPException(status_code=423, detail={"error_code": "MFA_LOCKED", "message": "MFA challenge is temporarily locked"})
        return challenge, db.get(User, challenge.user_id)

    def challenge_failed(self, db: Session, challenge: AuthChallenge) -> None:
        challenge.failed_attempts += 1
        if challenge.failed_attempts >= settings.MFA_FAILURE_LIMIT:
            challenge.locked_until = get_utc_now() + timedelta(minutes=settings.MFA_LOCKOUT_MINUTES)
        db.commit()

    def issue_one_time_token(self, db: Session, user: User, purpose: str, minutes: int, request: Request | None) -> str:
        token = secrets.token_urlsafe(40)
        db.query(AuthOneTimeToken).filter_by(user_id=user.id, purpose=purpose, used_at=None).update(
            {AuthOneTimeToken.used_at: get_utc_now()}, synchronize_session=False
        )
        db.add(
            AuthOneTimeToken(
                user_id=user.id,
                purpose=purpose,
                token_hash=self.token_hash(token),
                expires_at=get_utc_now() + timedelta(minutes=minutes),
                requested_ip=self.client_ip(request),
            )
        )
        db.commit()
        return token

    def consume_one_time_token(self, db: Session, token: str, purpose: str) -> tuple[AuthOneTimeToken, User]:
        record = db.query(AuthOneTimeToken).filter_by(token_hash=self.token_hash(token), purpose=purpose).with_for_update().first()
        if not record or record.used_at:
            raise HTTPException(status_code=400, detail={"error_code": "TOKEN_INVALID", "message": "Token is invalid or has already been used"})
        if ensure_utc(record.expires_at) <= get_utc_now():
            raise HTTPException(status_code=400, detail={"error_code": "TOKEN_EXPIRED", "message": "Token has expired"})
        return record, db.get(User, record.user_id)

    def reset_password(self, db: Session, token: str, new_password: str) -> User:
        record, user = self.consume_one_time_token(db, token, "password_reset")
        validate_new_password(new_password, email=user.email, full_name=user.full_name)
        user.hashed_password = get_password_hash(new_password)
        user.password_changed_at = get_utc_now()
        record.used_at = get_utc_now()
        db.commit()
        return user

    def cleanup(self, db: Session) -> int:
        now = get_utc_now()
        total = db.query(AuthChallenge).filter(AuthChallenge.expires_at < now).delete(synchronize_session=False)
        total += db.query(AuthOneTimeToken).filter(AuthOneTimeToken.expires_at < now).delete(synchronize_session=False)
        db.commit()
        return total


account_security_service = AccountSecurityService()
