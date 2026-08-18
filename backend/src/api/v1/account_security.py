from __future__ import annotations

from datetime import timedelta

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from limits import parse as parse_rate_limit
from slowapi import Limiter
from sqlalchemy.orm import Session

from src.api.deps import get_current_user, get_db, security
from src.core.config import get_settings
from src.core.security import verify_password
from src.models.pydantic import (
    AccountSecurityStatus,
    AuthSecurityEventListResponse,
    EmailAddressRequest,
    EmailTokenRequest,
    MFAChallengeRequest,
    MFAEnrollmentConfirmRequest,
    MFAEnrollmentStartRequest,
    MFASensitiveActionRequest,
    MessageResponse,
    PasswordResetCompleteRequest,
    RecoveryCodesResponse,
    SessionListResponse,
    SessionResponse,
    Token,
)
from src.models.sqlalchemy import AuthOneTimeToken, AuthSecurityEvent, MFARecoveryCode, User
from src.services.account_security_service import account_security_service
from src.services.audit_service import audit_service
from src.services.auth_email_service import auth_email_service
from src.services.auth_service import auth_service
from src.utils.datetime_utils import ensure_utc, get_utc_now


router = APIRouter(tags=["Account Security"])
settings = get_settings()
GENERIC_EMAIL_RESPONSE = "If the account can receive this message, an email has been sent."


def get_limiter():
    from src.main import limiter
    return limiter


def _limit(limiter: Limiter, request: Request, rule: str, scope: str, account: str = "") -> None:
    if request.client and request.client.host == "testclient":
        return
    ip = account_security_service.client_ip(request) or "unknown"
    key = f"{scope}:{ip}:{account.casefold().strip()}"
    if not limiter.limiter.hit(parse_rate_limit(rule), key):
        raise HTTPException(
            status_code=429,
            detail={"error_code": "RATE_LIMITED", "message": "Too many requests. Please try again later."},
            headers={"Retry-After": "60"},
        )


def _audit(db: Session, action: str, user: User, request: Request, **details) -> None:
    audit_service.record(
        db,
        action=action,
        user=user,
        resource_type="account_security",
        resource_id=user.id,
        ip_address=account_security_service.client_ip(request),
        user_agent=account_security_service.user_agent(request),
        request_id=getattr(request.state, "request_id", None),
        details=details,
    )


@router.post("/auth/mfa/complete", response_model=Token)
def complete_mfa(
    data: MFAChallengeRequest,
    request: Request,
    db: Session = Depends(get_db),
    limiter: Limiter = Depends(get_limiter),
):
    _limit(
        limiter,
        request,
        settings.AUTH_RATE_LIMIT_RECOVERY if data.recovery_code else settings.AUTH_RATE_LIMIT_MFA,
        "mfa_complete",
    )
    challenge, user = account_security_service.consume_challenge(db, data.challenge_token)
    valid = (
        account_security_service.use_recovery_code(db, user, data.code)
        if data.recovery_code
        else account_security_service.verify_user_totp(db, user, data.code)
    )
    if not valid:
        account_security_service.challenge_failed(db, challenge)
        account_security_service.record_event(
            db, user, "mfa_challenge", request=request, result="failure",
            severity="suspicious", reason_code="invalid_recovery_code" if data.recovery_code else "invalid_totp",
        )
        _audit(db, "mfa_verification_failure", user, request)
        code = "RECOVERY_CODE_INVALID" if data.recovery_code else "MFA_INVALID"
        raise HTTPException(status_code=401, detail={"error_code": code, "message": "Authentication verification failed"})

    challenge.used_at = get_utc_now()
    reasons = account_security_service.suspicious_login_reasons(db, user, request)
    auth_service.record_successful_login(db, user)
    tokens = auth_service.create_token_pair(db, user, request=request)
    event_type = "recovery_code_login" if data.recovery_code else "login_success"
    account_security_service.record_event(
        db, user, event_type, request=request,
        severity="suspicious" if reasons else "informational",
        reason_code=reasons[0] if reasons else None,
        details={"reason_codes": reasons},
    )
    account_security_service.record_event(db, user, "session_created", request=request)
    if reasons:
        auth_email_service.security_notice(
            user.email, "Suspicious sign-in", "A sign-in with unusual account-security signals was detected.",
        )
    _audit(db, "recovery_code_used" if data.recovery_code else "login", user, request)
    return tokens


@router.post("/account/security/mfa/start")
def start_mfa(
    data: MFAEnrollmentStartRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = account_security_service.start_mfa(db, user, data.current_password)
    account_security_service.record_event(db, user, "mfa_enrollment_started", request=request)
    _audit(db, "mfa_enrollment_started", user, request)
    return result


@router.post("/account/security/mfa/confirm", response_model=RecoveryCodesResponse)
def confirm_mfa(
    data: MFAEnrollmentConfirmRequest,
    request: Request,
    db: Session = Depends(get_db),
    limiter: Limiter = Depends(get_limiter),
    user: User = Depends(get_current_user),
):
    _limit(limiter, request, settings.AUTH_RATE_LIMIT_MFA, "mfa_enrollment", user.email)
    try:
        codes = account_security_service.confirm_mfa(db, user, data.code)
    except HTTPException:
        account_security_service.record_event(
            db, user, "mfa_enrollment_confirmation", request=request,
            result="failure", severity="suspicious", reason_code="invalid_totp",
        )
        raise
    account_security_service.record_event(db, user, "mfa_enabled", request=request)
    _audit(db, "mfa_enabled", user, request)
    return RecoveryCodesResponse(recovery_codes=codes)


@router.post("/account/security/mfa/disable", response_model=MessageResponse)
def disable_mfa(
    data: MFASensitiveActionRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    account_security_service.disable_mfa(db, user, data.current_password, data.code)
    account_security_service.record_event(db, user, "mfa_disabled", request=request)
    auth_email_service.security_notice(user.email, "MFA disabled", "Multi-factor authentication was disabled.")
    _audit(db, "mfa_disabled", user, request)
    return MessageResponse(detail="MFA disabled")


@router.post("/account/security/recovery-codes/regenerate", response_model=RecoveryCodesResponse)
def regenerate_recovery_codes(
    data: MFASensitiveActionRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    codes = account_security_service.regenerate_recovery(db, user, data.current_password, data.code)
    account_security_service.record_event(db, user, "recovery_codes_regenerated", request=request)
    _audit(db, "recovery_codes_regenerated", user, request)
    return RecoveryCodesResponse(recovery_codes=codes)


@router.get("/account/security/status", response_model=AccountSecurityStatus)
def security_status(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    remaining = db.query(MFARecoveryCode).filter(
        MFARecoveryCode.user_id == user.id, MFARecoveryCode.used_at.is_(None)
    ).count()
    return AccountSecurityStatus(
        mfa_enabled=bool(user.mfa_enabled_at),
        recovery_codes_remaining=remaining,
        email_verified=bool(user.email_verified_at or user.email_verification_exempt),
        email_verification_required=settings.EMAIL_VERIFICATION_REQUIRED,
    )


@router.get("/account/security/sessions", response_model=SessionListResponse)
def sessions(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    payload = jwt.decode(
        credentials.credentials, settings.JWT_SECRET_KEY,
        algorithms=[settings.ALGORITHM], issuer=settings.JWT_ISSUER,
    )
    rows, total = auth_service.list_sessions(db, user.id, offset=(page - 1) * page_size, limit=page_size)
    items = [
        SessionResponse.model_validate(row).model_copy(update={"current": row.id == payload.get("sid")})
        for row in rows
    ]
    return SessionListResponse(items=items, total=total, page=page, page_size=page_size)


@router.delete("/account/security/sessions/{session_id}", response_model=MessageResponse)
def revoke_session(
    session_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    session = auth_service.revoke_session(db, user.id, session_id)
    account_security_service.record_event(
        db, user, "session_revoked", request=request, details={"session_id": session.id},
    )
    _audit(db, "session_revoked", user, request, session_id=session.id)
    return MessageResponse(detail="Session revoked")


@router.get("/account/security/events", response_model=AuthSecurityEventListResponse)
def security_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(AuthSecurityEvent).filter(
        AuthSecurityEvent.user_id == user.id,
        AuthSecurityEvent.tenant_id == user.tenant_id,
    )
    total = query.count()
    items = query.order_by(AuthSecurityEvent.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return AuthSecurityEventListResponse(items=items, total=total, page=page, page_size=page_size)


@router.post("/auth/email-verification/request", response_model=MessageResponse)
def request_verification(
    data: EmailAddressRequest,
    request: Request,
    db: Session = Depends(get_db),
    limiter: Limiter = Depends(get_limiter),
):
    normalized = data.email.casefold().strip()
    _limit(limiter, request, settings.AUTH_RATE_LIMIT_VERIFICATION, "verification", normalized)
    user = db.query(User).filter(User.email == normalized).first()
    if user and not user.email_verified_at:
        recent = db.query(AuthOneTimeToken).filter(
            AuthOneTimeToken.user_id == user.id,
            AuthOneTimeToken.purpose == "email_verification",
            AuthOneTimeToken.created_at >= get_utc_now() - timedelta(seconds=settings.EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS),
        ).first()
        if not recent:
            token = account_security_service.issue_one_time_token(
                db, user, "email_verification", settings.EMAIL_VERIFICATION_TOKEN_MINUTES, request,
            )
            auth_email_service.verification(user.email, f"{settings.FRONTEND_PUBLIC_URL}/verify-email?token={token}")
            account_security_service.record_event(db, user, "verification_email_requested", request=request)
            _audit(db, "verification_email_requested", user, request)
    return MessageResponse(detail=GENERIC_EMAIL_RESPONSE)


@router.post("/auth/email-verification/confirm", response_model=MessageResponse)
def confirm_verification(data: EmailTokenRequest, request: Request, db: Session = Depends(get_db)):
    existing = db.query(AuthOneTimeToken).filter_by(
        token_hash=account_security_service.token_hash(data.token),
        purpose="email_verification",
    ).first()
    if existing and existing.used_at:
        existing_user = db.get(User, existing.user_id)
        if existing_user and existing_user.email_verified_at:
            return MessageResponse(detail="Email verified")
    record, user = account_security_service.consume_one_time_token(db, data.token, "email_verification")
    if not user.email_verified_at:
        user.email_verified_at = get_utc_now()
    record.used_at = get_utc_now()
    db.commit()
    account_security_service.record_event(db, user, "email_verified", request=request)
    _audit(db, "email_verified", user, request)
    return MessageResponse(detail="Email verified")


@router.post("/auth/password-reset/request", response_model=MessageResponse)
def request_password_reset(
    data: EmailAddressRequest,
    request: Request,
    db: Session = Depends(get_db),
    limiter: Limiter = Depends(get_limiter),
):
    normalized = data.email.casefold().strip()
    _limit(limiter, request, settings.AUTH_RATE_LIMIT_PASSWORD_RESET, "password_reset", normalized)
    user = db.query(User).filter(User.email == normalized).first()
    if user and user.is_active:
        token = account_security_service.issue_one_time_token(
            db, user, "password_reset", settings.PASSWORD_RESET_TOKEN_MINUTES, request,
        )
        auth_email_service.password_reset(user.email, f"{settings.FRONTEND_PUBLIC_URL}/reset-password?token={token}")
        account_security_service.record_event(db, user, "password_reset_requested", request=request)
        _audit(db, "password_reset_requested", user, request)
    return MessageResponse(detail=GENERIC_EMAIL_RESPONSE)


@router.post("/auth/password-reset/complete", response_model=MessageResponse)
def complete_password_reset(
    data: PasswordResetCompleteRequest,
    request: Request,
    db: Session = Depends(get_db),
    limiter: Limiter = Depends(get_limiter),
):
    _limit(limiter, request, settings.AUTH_RATE_LIMIT_PASSWORD_RESET, "password_reset_complete")
    try:
        user = account_security_service.reset_password(db, data.token, data.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error_code": "PASSWORD_POLICY", "message": str(exc)}) from exc
    revoked = auth_service.revoke_user_sessions(db, user.id)
    account_security_service.record_event(
        db, user, "password_reset", request=request, details={"revoked_sessions": revoked},
    )
    auth_email_service.security_notice(user.email, "Password changed", "Your password was reset successfully.")
    _audit(db, "password_reset_completed", user, request, revoked_sessions=revoked)
    return MessageResponse(detail="Password reset completed")
