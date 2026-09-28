from fastapi import APIRouter, Depends, HTTPException, Request, status
from limits import parse as parse_rate_limit
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address
from src.api.deps import get_current_user, get_db
from src.core.permissions import Permission, require_permission
from src.core.config import get_settings
from src.core.security import (
    verify_password,
    get_password_hash,
)
from src.core.logging import logger
from src.core.observability import AUTH_ATTEMPTS
from src.models.sqlalchemy import OrganizationMembership, OrganizationRole, User, Tenant, UserRole
from src.models.pydantic import (
    LogoutRequest,
    MessageResponse,
    PasswordChangeRequest,
    RefreshTokenRequest,
    UserCreate,
    UserLogin,
    UserUpdate,
    OrganizationMemberUpdate,
    User as UserResponse,
    Token
)
from src.services.audit_service import audit_service
from src.services.auth_service import auth_service
from src.services.account_security_service import account_security_service
from src.services.auth_email_service import auth_email_service
from src.services.password_policy import PasswordPolicyError, validate_new_password
from src.services.organization_service import organization_service
from src.utils.datetime_utils import get_utc_now

router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()

# Get limiter from app state
def get_limiter():
    from src.main import limiter
    return limiter

def _client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


def _check_rate_limit(limiter: Limiter, request: Request, limit: str, scope: str, account: str = "") -> None:
    if request.client and request.client.host == "testclient":
        return
    key = f"{scope}:{get_remote_address(request)}:{account.casefold().strip()}"
    if not limiter.limiter.hit(parse_rate_limit(limit), key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error_code": "RATE_LIMITED", "message": "Too many requests. Please try again later."},
            headers={"Retry-After": "60"},
        )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_data: UserCreate, request: Request, db: Session = Depends(get_db), limiter: Limiter = Depends(get_limiter)):
    # Apply rate limit (3 registrations/hour per IP)
    _check_rate_limit(limiter, request, "3/hour", "auth_register")
    
    logger.info(f"Registering user: {user_data.email}")
    
    # Validate password policy first
    try:
        validate_new_password(user_data.password, email=user_data.email, full_name=user_data.full_name)
    except PasswordPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error_code": "PASSWORD_POLICY", "message": str(exc)},
        ) from exc
    
    # Check if user already exists - but don't reveal it (fix user enumeration)
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        logger.warning(f"Email already registered: {user_data.email}")
        # Return generic success message to avoid enumeration
        return UserResponse(
            id=existing_user.id,
            email=existing_user.email,
            full_name=existing_user.full_name,
            role=existing_user.role,
            is_active=existing_user.is_active,
            tenant_id=existing_user.tenant_id,
            created_at=existing_user.created_at,
            updated_at=existing_user.updated_at
        )
    
    # Check if tenant slug already exists
    existing_tenant = db.query(Tenant).filter(Tenant.slug == user_data.tenant_slug).first()
    if existing_tenant:
        logger.warning(f"Tenant slug already taken: {user_data.tenant_slug}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tenant slug already taken"
        )
    
    # Create tenant
    tenant = Tenant(
        name=user_data.tenant_name,
        slug=user_data.tenant_slug
    )
    db.add(tenant)
    db.flush()
    db.refresh(tenant)
    logger.info(f"Created tenant: {tenant.id}")
    
    # Check if it's the first user of the tenant
    existing_tenant_users = db.query(User).filter(User.tenant_id == tenant.id).count()
    user_role = UserRole.ADMIN if existing_tenant_users == 0 else UserRole.ANALYST
    hashed_password = get_password_hash(user_data.password)
    user = User(
        email=user_data.email.casefold().strip(),
        full_name=user_data.full_name,
        hashed_password=hashed_password,
        tenant_id=tenant.id,
        role=user_role
    )
    db.add(user)
    db.flush()
    organization_service.ensure_primary_membership(db, user, OrganizationRole.OWNER, commit=False)
    db.commit()
    db.refresh(user)
    logger.info(f"Created user: {user.id}")

    audit_service.record(
        db,
        action="registration",
        user=user,
        tenant_id=tenant.id,
        resource_type="user",
        resource_id=user.id,
        ip_address=_client_ip(request),
        details={"email": user.email, "tenant_slug": tenant.slug},
    )
    if settings.EMAIL_VERIFICATION_REQUIRED:
        token = account_security_service.issue_one_time_token(
            db, user, "email_verification", settings.EMAIL_VERIFICATION_TOKEN_MINUTES, request,
        )
        auth_email_service.verification(
            user.email, f"{settings.FRONTEND_PUBLIC_URL}/verify-email?token={token}",
        )
    
    return user


@router.post("/login", response_model=Token)
def login(user_data: UserLogin, request: Request, db: Session = Depends(get_db), limiter: Limiter = Depends(get_limiter)):
    # Apply rate limit (5 requests/minute per IP)
    normalized_email = user_data.email.casefold().strip()
    _check_rate_limit(limiter, request, "5/minute", "auth_login", normalized_email)
    
    logger.info(f"Login attempt for: {user_data.email}")
    
    user = db.query(User).filter(User.email == normalized_email).first()
    
    if user and auth_service.is_locked(user):
        AUTH_ATTEMPTS.labels("locked").inc()
        audit_service.record(
            db,
            action="account_lockout",
            user=user,
            tenant_id=user.tenant_id,
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
            details={
                "email": user.email,
                "locked_until": user.locked_until.isoformat() if user.locked_until else None,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail={"error_code": "ACCOUNT_LOCKED", "message": "Account is temporarily locked. Please try again later."},
        )

    login_valid = (
        user
        and user.is_active
        and user.tenant
        and user.tenant.is_active
        and auth_service.verify_login_password(db, user, user_data.password)
    )

    if not login_valid:
        logger.warning(f"Login failed for: {user_data.email}")
        locked = bool(user and auth_service.is_locked(user))
        AUTH_ATTEMPTS.labels("locked" if locked else "failure").inc()
        audit_service.record(
            db,
            action="account_lockout" if locked else "login_failed",
            user=user if user else None,
            tenant_id=user.tenant_id if user else None,
            resource_type="user",
            resource_id=user.id if user else None,
            ip_address=_client_ip(request),
            details={"email": user_data.email, "locked": locked},
        )
        if user:
            account_security_service.record_event(
                db, user, "login_failed", request=request, result="failure",
                severity="suspicious" if locked else "informational",
                reason_code="account_locked" if locked else "invalid_credentials",
            )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED if locked else status.HTTP_401_UNAUTHORIZED,
            detail=(
                {"error_code": "ACCOUNT_LOCKED", "message": "Account is temporarily locked. Please try again later."}
                if locked else
                {"error_code": "AUTHENTICATION_FAILED", "message": "Incorrect email or password"}
            ),
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if (
        settings.EMAIL_VERIFICATION_REQUIRED
        and not user.email_verified_at
        and not user.email_verification_exempt
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "EMAIL_NOT_VERIFIED", "message": "Email verification is required"},
        )
    if user.mfa_enabled_at:
        challenge = account_security_service.create_challenge(db, user, request)
        return Token(mfa_required=True, challenge_token=challenge, expires_in=settings.MFA_CHALLENGE_MINUTES * 60)

    reasons = account_security_service.suspicious_login_reasons(db, user, request)
    auth_service.record_successful_login(db, user)
    token_pair = auth_service.create_token_pair(db, user, request=request)
    account_security_service.record_event(
        db, user, "login_success", request=request,
        severity="suspicious" if reasons else "informational",
        reason_code=reasons[0] if reasons else None,
        details={"reason_codes": reasons},
    )
    account_security_service.record_event(db, user, "session_created", request=request)
    if reasons:
        auth_email_service.security_notice(
            user.email, "Suspicious sign-in", "A sign-in with unusual account-security signals was detected.",
        )
    AUTH_ATTEMPTS.labels("success").inc()
    
    logger.info(f"Login successful for: {user_data.email}")
    audit_service.record(
        db,
        action="login",
        user=user,
        tenant_id=user.tenant_id,
        resource_type="user",
        resource_id=user.id,
        ip_address=_client_ip(request),
        details={"email": user.email},
    )
    return token_pair


@router.post("/refresh", response_model=Token)
def refresh_token(
    token_data: RefreshTokenRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    user, token_pair = auth_service.rotate_refresh_token(
        db,
        token_data.refresh_token,
        request=request,
    )
    audit_service.record(
        db,
        action="refresh_token_used",
        user=user,
        tenant_id=user.tenant_id,
        resource_type="user",
        resource_id=user.id,
        ip_address=_client_ip(request),
        details={"email": user.email},
    )
    return token_pair


@router.post("/logout", response_model=MessageResponse)
def logout(
    logout_data: LogoutRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    revoked = None
    if logout_data.refresh_token:
        revoked = auth_service.revoke_refresh_token(db, logout_data.refresh_token)
    audit_service.record(
        db,
        action="logout",
        user=current_user,
        tenant_id=current_user.tenant_id,
        resource_type="refresh_token" if revoked else "user",
        resource_id=revoked.id if revoked else current_user.id,
        ip_address=_client_ip(request),
        details={"revoked": bool(revoked)},
    )
    account_security_service.record_event(db, current_user, "logout", request=request)
    return MessageResponse(detail="Logged out successfully")


@router.post("/logout-all", response_model=MessageResponse)
def logout_all(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    revoked_count = auth_service.revoke_user_sessions(db, current_user.id)
    audit_service.record(
        db,
        action="session_revocation",
        user=current_user,
        tenant_id=current_user.tenant_id,
        resource_type="user",
        resource_id=current_user.id,
        ip_address=_client_ip(request),
        details={"revoked_count": revoked_count},
    )
    account_security_service.record_event(
        db, current_user, "logout_all", request=request,
        details={"revoked_sessions": revoked_count},
    )
    return MessageResponse(detail="All sessions have been revoked")


@router.post("/change-password", response_model=MessageResponse)
def change_password(
    password_data: PasswordChangeRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not verify_password(password_data.current_password, current_user.hashed_password):
        audit_service.record(
            db,
            action="password_change_failed",
            user=current_user,
            tenant_id=current_user.tenant_id,
            resource_type="user",
            resource_id=current_user.id,
            ip_address=_client_ip(request),
            details={"reason": "invalid_current_password"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    try:
        validate_new_password(
            password_data.new_password,
            email=current_user.email,
            full_name=current_user.full_name,
        )
    except PasswordPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error_code": "PASSWORD_POLICY", "message": str(exc)},
        ) from exc

    current_user.hashed_password = get_password_hash(password_data.new_password)
    current_user.password_changed_at = get_utc_now()
    db.commit()
    db.refresh(current_user)
    revoked_count = auth_service.revoke_user_sessions(db, current_user.id)
    audit_service.record(
        db,
        action="password_change",
        user=current_user,
        tenant_id=current_user.tenant_id,
        resource_type="user",
        resource_id=current_user.id,
        ip_address=_client_ip(request),
        details={"revoked_sessions": revoked_count},
    )
    account_security_service.record_event(
        db, current_user, "password_change", request=request,
        details={"revoked_sessions": revoked_count},
    )
    auth_email_service.security_notice(
        current_user.email, "Password changed", "Your VigilantAI password was changed.",
    )
    return MessageResponse(detail="Password changed successfully")


# Admin-only endpoints
@router.get("/users", response_model=list[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.USERS_VIEW)),
):
    return (
        db.query(User)
        .join(OrganizationMembership, OrganizationMembership.user_id == User.id)
        .filter(
            OrganizationMembership.tenant_id == current_user.tenant_id,
            OrganizationMembership.is_active.is_(True),
        )
        .order_by(User.full_name.asc(), User.email.asc())
        .all()
    )


@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.USERS_VIEW)),
):
    user = db.query(User).join(
        OrganizationMembership, OrganizationMembership.user_id == User.id
    ).filter(
        User.id == user_id,
        OrganizationMembership.tenant_id == current_user.tenant_id,
    ).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.put("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: str,
    user_data: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.USERS_UPDATE)),
):
    membership = db.query(OrganizationMembership).filter_by(
        user_id=user_id, tenant_id=current_user.tenant_id
    ).first()
    user = db.get(User, user_id) if membership else None
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    if user_data.role is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_code": "ROLE_ASSIGNMENT_DENIED",
                "message": "Use the organization membership role-assignment endpoint",
            },
        )

    # Account identity is global, while activation and authority are membership-scoped.
    if user.id == current_user.id:
        if user_data.is_active is not None and not user_data.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot deactivate your own administrator account"
            )
    
    if user_data.full_name is not None:
        user.full_name = user_data.full_name
    if user_data.is_active is not None:
        organization_service.update_member(
            db,
            current_user,
            current_user.tenant_id,
            membership.id,
            None,
            user_data.is_active,
        )
    
    db.commit()
    db.refresh(user)
    logger.info(f"Updated user: {user.id}")
    return user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.USERS_DISABLE)),
):
    membership = db.query(OrganizationMembership).filter_by(
        user_id=user_id, tenant_id=current_user.tenant_id
    ).first()
    if not membership:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot deactivate your own administrator account"
        )
    
    organization_service.update_member(
        db,
        current_user,
        current_user.tenant_id,
        membership.id,
        None,
        False,
    )
    logger.info(f"Deactivated organization membership: {membership.id}")


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user
