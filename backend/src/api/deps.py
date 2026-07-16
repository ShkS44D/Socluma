from typing import Callable, Generator, Optional
from fastapi import Depends, HTTPException, Request, status, WebSocket
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt import PyJWTError
from sqlalchemy.orm import Session
from src.core.database import SessionLocal
from src.core.config import get_settings
from src.models.sqlalchemy import OrganizationStatus, User, UserRole, Collector
from src.models.pydantic import TokenData
from src.core.security import verify_collector_token
from src.utils.datetime_utils import ensure_utc
from src.core.logging import collector_id_ctx, logger, tenant_id_ctx, user_id_ctx

settings = get_settings()

# Use HTTPBearer instead of OAuth2PasswordBearer for Swagger UI compatibility
security = HTTPBearer()
optional_security = HTTPBearer(auto_error=False)


def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        logger.exception("Database session rolled back after unhandled request error")
        raise
    finally:
        db.close()


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    user = _get_user_from_credentials(credentials, db)
    _set_request_identity(request, tenant_id=user.tenant_id, user_id=user.id)
    return user


def get_optional_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_security),
    db: Session = Depends(get_db),
) -> Optional[User]:
    if credentials is None:
        return None
    try:
        user = _get_user_from_credentials(credentials, db)
        _set_request_identity(request, tenant_id=user.tenant_id, user_id=user.id)
        return user
    except HTTPException:
        return None


def _set_request_identity(
    request: Request,
    tenant_id: str | None = None,
    user_id: str | None = None,
    collector_id: str | None = None,
) -> None:
    request.state.tenant_id = tenant_id
    request.state.user_id = user_id
    request.state.collector_id = collector_id


def _get_user_from_credentials(
    credentials: HTTPAuthorizationCredentials,
    db: Session,
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid JWT token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        token = credentials.credentials
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            issuer=settings.JWT_ISSUER,
        )
        if payload.get("typ") != "access":
            raise credentials_exception
        user_id: Optional[str] = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=user_id)
    except PyJWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.id == token_data.user_id).first()
    if (
        user is None
        or not user.is_active
        or not user.tenant
        or not user.tenant.is_active
        or user.tenant.status != OrganizationStatus.ACTIVE
    ):
        raise credentials_exception
    if user.password_changed_at:
        password_version = payload.get("pwd")
        expected_password_version = int(ensure_utc(user.password_changed_at).timestamp())
        if password_version != expected_password_version:
            raise credentials_exception
    tenant_id_ctx.set(user.tenant_id)
    user_id_ctx.set(user.id)
    from src.services.organization_service import organization_service
    organization_service.ensure_primary_membership(db, user)
    return user


def _get_collector_from_token(
    token: str,
    db: Session,
) -> Collector:
    """Get collector from token, raise appropriate exceptions, and migrate old tokens"""
    invalid_token_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid collector token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    from src.core.security import get_collector_token_hash, get_collector_token_lookup_hash

    lookup_hash = get_collector_token_lookup_hash(token)
    collector = db.query(Collector).filter(Collector.token_lookup_hash == lookup_hash).first()
    needs_migration = False

    if collector:
        is_valid, needs_migration = verify_collector_token(token, collector.token)
        if not is_valid:
            raise invalid_token_exception
    else:
        # Self-heal collectors created before lookup hashes, or after a
        # COLLECTOR_TOKEN_SECRET rotation that made stored lookup hashes stale.
        all_collectors = db.query(Collector).all()
        for c in all_collectors:
            is_valid, migrate_plaintext = verify_collector_token(token, c.token)
            if is_valid:
                collector = c
                needs_migration = migrate_plaintext or c.token_lookup_hash != lookup_hash
                break
    
    if not collector:
        raise invalid_token_exception
    
    if not collector.tenant or not collector.tenant.is_active or collector.tenant.status != OrganizationStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant is inactive",
        )
    
    # Migrate if needed
    if needs_migration:
        collector.token = get_collector_token_hash(token)
        collector.token_lookup_hash = lookup_hash
        db.commit()
        db.refresh(collector)
    tenant_id_ctx.set(collector.tenant_id)
    collector_id_ctx.set(collector.id)
    
    return collector


def get_current_collector(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> Collector:
    """Dependency to get current collector (for collector-only endpoints)"""
    token = credentials.credentials
    collector = _get_collector_from_token(token, db)
    _set_request_identity(request, tenant_id=collector.tenant_id, collector_id=collector.id)
    return collector


class AuthContext:
    """Context object that holds either a user or a collector"""
    def __init__(
        self,
        user: Optional[User] = None,
        collector: Optional[Collector] = None,
        tenant_id: Optional[str] = None,
    ):
        self.user = user
        self.collector = collector
        self.tenant_id = tenant_id


def get_current_auth_context(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_security),
    db: Session = Depends(get_db),
) -> AuthContext:
    """Dependency to get current auth context (user or collector)"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authentication provided",
        )
    
    token = credentials.credentials
    
    # Try JWT first
    try:
        user = _get_user_from_credentials(credentials, db)
        _set_request_identity(request, tenant_id=user.tenant_id, user_id=user.id)
        return AuthContext(user=user, tenant_id=user.tenant_id)
    except HTTPException:
        pass
    
    # Try collector token
    try:
        collector = _get_collector_from_token(token, db)
        _set_request_identity(request, tenant_id=collector.tenant_id, collector_id=collector.id)
        return AuthContext(collector=collector, tenant_id=collector.tenant_id)
    except HTTPException:
        pass
    
    # If neither worked, raise 401
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_roles(*allowed_roles: UserRole) -> Callable[[User], User]:
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return role_checker


async def get_current_user_ws(websocket: WebSocket) -> User:
    credentials_exception = Exception("Could not validate credentials")
    
    # Get token from query parameter
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        raise credentials_exception
    
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            issuer=settings.JWT_ISSUER,
        )
        if payload.get("typ") != "access":
            await websocket.close(code=1008)
            raise credentials_exception
        user_id: Optional[str] = payload.get("sub")
        if user_id is None:
            await websocket.close(code=1008)
            raise credentials_exception
        token_data = TokenData(user_id=user_id)
    except PyJWTError:
        await websocket.close(code=1008)
        raise credentials_exception
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == token_data.user_id).first()
        if (
            user is None
            or not user.is_active
            or not user.tenant
            or not user.tenant.is_active
            or user.tenant.status != OrganizationStatus.ACTIVE
        ):
            await websocket.close(code=1008)
            raise credentials_exception
        if user.password_changed_at:
            password_version = payload.get("pwd")
            expected_password_version = int(ensure_utc(user.password_changed_at).timestamp())
            if password_version != expected_password_version:
                await websocket.close(code=1008)
                raise credentials_exception
        tenant_id = user.tenant_id
        user_id = user.id
        db.expunge(user)
    except Exception:
        db.rollback()
        logger.exception("WebSocket authentication database session rolled back")
        raise
    finally:
        db.close()

    tenant_id_ctx.set(tenant_id)
    user_id_ctx.set(user_id)
    return user
