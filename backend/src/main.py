import time
import uuid
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.encoders import jsonable_encoder
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from src.core.config import get_settings
from src.core.errors import build_error_response
from src.core.logging import (
    collector_id_ctx,
    endpoint_ctx,
    execution_time_ms_ctx,
    logger,
    request_id_ctx,
    tenant_id_ctx,
    user_id_ctx,
)
from src.core.observability import (
    API_REQUEST_LATENCY,
    API_REQUESTS,
    DATABASE_LATENCY,
    DATABASE_STATUS,
    QUEUE_LATENCY,
    REDIS_STATUS,
    metrics_response,
)
from src.core.security import get_password_hash
from src.core.database import engine, create_tables, SessionLocal
from src.models.sqlalchemy import OrganizationRole, User, Tenant, UserRole, DetectionRule
import redis
from sqlalchemy import text
from swagger_ui_bundle import swagger_ui_path
from src.models.pydantic import HealthCheck, HealthComponent, HealthStatus
from src.utils.datetime_utils import get_utc_now
from src.api.v1 import auth, alerts, incidents, sources, iocs, detection_rules, notifications, assets, events, mitre_techniques, websockets, log_sources, collectors, playbooks, soar, organizations, ai
from src.services.default_detection_rules import DEFAULT_DETECTION_RULES
from src.services.organization_service import organization_service

settings = get_settings()
settings.validate_for_runtime()


def _rate_limit_storage_uri() -> str:
    if settings.RATE_LIMIT_STORAGE_URL:
        return settings.RATE_LIMIT_STORAGE_URL
    if settings.USE_REDIS_MOCK:
        return "memory://"
    try:
        redis.from_url(settings.REDIS_URL).ping()
        return settings.REDIS_URL
    except Exception:
        logger.exception("Redis unavailable for rate limiting, falling back to in-memory limiter")
        return "memory://"


def rate_limit_key(request: Request) -> str:
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        import jwt
        from jwt import PyJWTError
        try:
            payload = jwt.decode(
                auth_header.split(" ", 1)[1],
                settings.JWT_SECRET_KEY,
                algorithms=[settings.ALGORITHM],
                issuer=settings.JWT_ISSUER,
            )
            user_id = payload.get("sub")
            if user_id:
                return f"user:{user_id}"
        except PyJWTError:
            pass
    return f"ip:{get_remote_address(request)}"


def bootstrap_default_detection_rules():
    """Bootstrap default detection rules on application startup"""
    db = SessionLocal()
    try:
        # First verify we can query DetectionRule without errors
        try:
            # Simple check to see if the table schema is compatible
            db.query(DetectionRule).limit(1).first()
        except Exception:
            logger.exception("DetectionRule schema not compatible yet, skipping bootstrap")
            return
            
        # Get default tenant
        existing_tenant = db.query(Tenant).filter(Tenant.slug == "default").first()
        if not existing_tenant:
            logger.info("Default tenant not found, skipping default rules bootstrap")
            return

        created_rules = 0
        for rule_data in DEFAULT_DETECTION_RULES:
            existing_rule = db.query(DetectionRule).filter(
                DetectionRule.tenant_id == existing_tenant.id,
                DetectionRule.name == rule_data["name"],
            ).first()
            if existing_rule:
                continue
            # Set default empty strings for backward compatibility columns
            rule_data.setdefault("query", "")
            rule_data.setdefault("sigma_rule", "")
            rule = DetectionRule(
                tenant_id=existing_tenant.id,
                **rule_data
            )
            db.add(rule)
            created_rules += 1
        
        db.commit()
        logger.info("Default detection rule bootstrap complete: created %s missing rule(s)", created_rules)

    except Exception:
        logger.exception("Failed to bootstrap default detection rules")
        db.rollback()
    finally:
        db.close()


def bootstrap_admin():
    """Bootstrap the admin user on application startup"""
    if not settings.ADMIN_EMAIL or not settings.ADMIN_PASSWORD:
        logger.info("ADMIN_EMAIL and ADMIN_PASSWORD not set, skipping admin bootstrap")
        return

    db = SessionLocal()
    try:
        # Create default tenant (or reuse if exists)
        tenant_slug = "default"
        tenant_name = "Default Tenant"
        existing_tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
        
        if not existing_tenant:
            existing_tenant = Tenant(
                name=tenant_name,
                slug=tenant_slug
            )
            db.add(existing_tenant)
            db.flush()
            db.refresh(existing_tenant)
            logger.info(f"Created default tenant: {existing_tenant.id}")

        # Check if admin user already exists
        existing_user = db.query(User).filter(User.email == settings.ADMIN_EMAIL).first()
        if existing_user:
            logger.info(f"Admin user {settings.ADMIN_EMAIL} already exists, updating password and ensuring admin role")
            # Update password hash and ensure admin role
            hashed_password = get_password_hash(settings.ADMIN_PASSWORD)
            existing_user.hashed_password = hashed_password
            existing_user.role = UserRole.ADMIN  # Ensure role remains admin
            existing_user.tenant_id = existing_tenant.id  # Ensure tenant association is correct
            existing_user.is_active = True  # Ensure user is active
            organization_service.ensure_primary_membership(db, existing_user, OrganizationRole.OWNER, commit=False)
            db.commit()
            db.refresh(existing_user)
            logger.info(f"Updated admin user: {existing_user.id} ({existing_user.email})")
            return

        # Create admin user if not exists
        hashed_password = get_password_hash(settings.ADMIN_PASSWORD)
        admin_user = User(
            email=settings.ADMIN_EMAIL,
            full_name="Admin User",
            hashed_password=hashed_password,
            tenant_id=existing_tenant.id,
            role=UserRole.ADMIN,
            is_active=True
        )
        db.add(admin_user)
        db.flush()
        organization_service.ensure_primary_membership(db, admin_user, OrganizationRole.OWNER, commit=False)
        db.commit()
        db.refresh(admin_user)
        logger.info(f"Created admin user: {admin_user.id} ({admin_user.email})")

    except Exception:
        logger.exception("Failed to bootstrap admin user")
        db.rollback()
    finally:
        db.close()


app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url="/api/v1/openapi.json",
    docs_url=None,
    redoc_url="/redoc",
    swagger_ui_init_oauth={
        "usePkceWithAuthorizationCodeGrant": True,
    }
)
app.mount("/api/v1/docs/static", StaticFiles(directory=swagger_ui_path), name="swagger-ui-static")


@app.get("/docs", include_in_schema=False)
async def swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{settings.PROJECT_NAME} - Swagger UI",
        swagger_js_url="/api/v1/docs/static/swagger-ui-bundle.js",
        swagger_css_url="/api/v1/docs/static/swagger-ui.css",
        swagger_favicon_url="/api/v1/docs/static/favicon-32x32.png",
        swagger_ui_parameters={"persistAuthorization": True},
    )

# Initialize rate limiter
limiter = Limiter(
    key_func=rate_limit_key,
    storage_uri=_rate_limit_storage_uri(),
    default_limits=[settings.RATE_LIMIT_DEFAULT],
)
app.state.limiter = limiter

# Add security scheme to OpenAPI spec
from fastapi.openapi.utils import get_openapi


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=settings.PROJECT_NAME,
        version="1.0.0",
        openapi_version="3.0.3",
        description="TriageOps API",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "HTTPBearer": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    openapi_schema["components"]["schemas"]["APIErrorResponse"] = {
        "type": "object",
        "required": ["timestamp", "request_id", "status", "error_code", "message", "detail", "documentation_url"],
        "properties": {
            "timestamp": {"type": "string", "format": "date-time"},
            "request_id": {"type": "string", "nullable": True},
            "status": {"type": "integer"},
            "error_code": {"type": "string"},
            "message": {"type": "string"},
            "detail": {"type": "string"},
            "details": {"nullable": True},
            "documentation_url": {"type": "string"},
        },
    }
    # Add security to all routes that use get_current_user
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            if "security" not in openapi_schema["paths"][path][method]:
                # Check if endpoint uses get_current_user by looking at dependencies (though for simplicity, we'll just add it to all except auth)
                if "/auth" not in path and path not in {"/", "/health", "/health/live", "/health/ready", settings.METRICS_PATH}:
                    openapi_schema["paths"][path][method]["security"] = [{"HTTPBearer": []}]
            openapi_schema["paths"][path][method].setdefault("responses", {})
            for error_status in ("400", "401", "403", "404", "422", "429", "500"):
                openapi_schema["paths"][path][method]["responses"].setdefault(
                    error_status,
                    {
                        "description": "Standard API error",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/APIErrorResponse"}
                            }
                        },
                    },
                )
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# Security middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS,
)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# CORS
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Create tables on startup
if settings.USE_SQLITE:
    create_tables()

# Bootstrap admin user on startup
bootstrap_admin()

# Bootstrap default detection rules on startup
bootstrap_default_detection_rules()

# Include routers
app.include_router(auth.router, prefix="/api/v1")
app.include_router(alerts.router, prefix="/api/v1")
app.include_router(incidents.router, prefix="/api/v1")
app.include_router(sources.router, prefix="/api/v1")
app.include_router(iocs.router, prefix="/api/v1")
app.include_router(detection_rules.router, prefix="/api/v1")
app.include_router(notifications.router, prefix="/api/v1")
app.include_router(assets.router, prefix="/api/v1")
app.include_router(events.router, prefix="/api/v1")
app.include_router(mitre_techniques.router, prefix="/api/v1")
app.include_router(websockets.router, prefix="/api/v1")
app.include_router(log_sources.router, prefix="/api/v1")
app.include_router(collectors.router, prefix="/api/v1")
app.include_router(playbooks.router, prefix="/api/v1")
app.include_router(soar.router, prefix="/api/v1")
app.include_router(organizations.router, prefix="/api/v1")
app.include_router(ai.router, prefix="/api/v1")


# Request observability middleware
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    endpoint = request.scope.get("path", request.url.path)
    request.state.request_id = request_id
    start = time.perf_counter()
    request_token = request_id_ctx.set(request_id)
    tenant_token = tenant_id_ctx.set(None)
    user_token = user_id_ctx.set(None)
    collector_token = collector_id_ctx.set(None)
    endpoint_token = endpoint_ctx.set(endpoint)
    execution_token = execution_time_ms_ctx.set(None)
    status_code = 500
    observed = False
    try:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                body_size = int(content_length)
            except ValueError:
                body_size = -1
            if body_size < 0:
                response = JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content=build_error_response(
                        request,
                        status_code=status.HTTP_400_BAD_REQUEST,
                        message="Invalid Content-Length header",
                        details=None,
                        error_code="invalid_content_length",
                    ),
                )
            elif body_size > settings.MAX_REQUEST_BODY_BYTES:
                response = JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content=build_error_response(
                        request,
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        message="Request body is too large",
                        details={"max_bytes": settings.MAX_REQUEST_BODY_BYTES},
                        error_code="request_body_too_large",
                    ),
                )
            else:
                response = None
        else:
            response = None
        try:
            response = response or await call_next(request)
        except Exception:
            logger.exception("Unhandled request exception")
            response = JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content=build_error_response(
                    request,
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    message="Internal server error",
                    details=None,
                    error_code="internal_error",
                ),
            )
        status_code = response.status_code
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        execution_time_ms_ctx.set(elapsed_ms)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-ms"] = str(elapsed_ms)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss: http://localhost:* http://127.0.0.1:*; "
            "frame-ancestors 'none'"
        )
        if settings.is_production():
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        tenant_id_ctx.set(getattr(request.state, "tenant_id", None))
        user_id_ctx.set(getattr(request.state, "user_id", None))
        collector_id_ctx.set(getattr(request.state, "collector_id", None))
        API_REQUESTS.labels(request.method, endpoint, str(status_code)).inc()
        API_REQUEST_LATENCY.labels(request.method, endpoint, str(status_code)).observe(elapsed_ms / 1000)
        observed = True
        logger.info(
            "HTTP request completed",
            extra={"method": request.method, "status_code": status_code},
        )
        return response
    finally:
        if not observed:
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            API_REQUESTS.labels(request.method, endpoint, "500").inc()
            API_REQUEST_LATENCY.labels(request.method, endpoint, "500").observe(elapsed_ms / 1000)
        request_id_ctx.reset(request_token)
        tenant_id_ctx.reset(tenant_token)
        user_id_ctx.reset(user_token)
        collector_id_ctx.reset(collector_token)
        endpoint_ctx.reset(endpoint_token)
        execution_time_ms_ctx.reset(execution_token)


# Global Exception Handlers
@app.exception_handler(RateLimitExceeded)
async def rate_limit_exception_handler(request: Request, exc: RateLimitExceeded):
    logger.warning("Rate limit exceeded: %s", exc.detail)
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content=build_error_response(
            request,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            message="Rate limit exceeded",
            details={"limit": str(exc.detail)},
            error_code="rate_limit_exceeded",
        ),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning("Request validation failed: %s", exc.errors())
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=build_error_response(
            request,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            message="Request validation failed",
            details=jsonable_encoder(exc.errors()),
            error_code="validation_error",
        ),
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    log_message = f"HTTP {exc.status_code} {request.method} {request.url.path}: {exc.detail}"
    if exc.status_code >= 500:
        logger.error(log_message)
    else:
        logger.warning(log_message)
    message = exc.detail if isinstance(exc.detail, str) else "Request failed"
    return JSONResponse(
        status_code=exc.status_code,
        headers=exc.headers,
        content=build_error_response(
            request,
            status_code=exc.status_code,
            message=message,
            details=None if isinstance(exc.detail, str) else exc.detail,
        ),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception at {request.url}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=build_error_response(
            request,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            message="Internal server error",
            details=None,
            error_code="internal_error",
        ),
    )


def _component(status_value: str, started: float, detail: str | None = None) -> HealthComponent:
    return HealthComponent(
        status=status_value,
        latency_ms=round((time.perf_counter() - started) * 1000, 2),
        detail=detail,
    )


def _check_database() -> HealthComponent:
    started = time.perf_counter()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        DATABASE_STATUS.set(1)
        DATABASE_LATENCY.labels("readiness_probe").observe(time.perf_counter() - started)
        return _component("ok", started)
    except Exception:
        DATABASE_STATUS.set(0)
        logger.exception("Database health check failed")
        return _component("error", started, "Database is unavailable")


def _check_redis() -> HealthComponent:
    started = time.perf_counter()
    if settings.USE_REDIS_MOCK:
        REDIS_STATUS.set(1)
        return _component("ok", started, "Redis mock enabled for development")
    try:
        redis.from_url(settings.REDIS_URL).ping()
        REDIS_STATUS.set(1)
        return _component("ok", started)
    except Exception:
        REDIS_STATUS.set(0)
        logger.exception("Redis health check failed")
        return _component("error", started, "Redis is unavailable")


def _check_worker() -> HealthComponent:
    started = time.perf_counter()
    if settings.USE_REDIS_MOCK:
        return _component("ok", started, "Worker queue disabled in Redis mock mode")
    try:
        broker = redis.from_url(settings.REDIS_URL)
        broker.ping()
        QUEUE_LATENCY.labels("broker_ping").observe(time.perf_counter() - started)
        return _component("ok", started, "Broker reachable")
    except Exception:
        logger.exception("Worker queue health check failed")
        return _component("error", started, "Worker queue is unavailable")


def _check_ai_provider() -> HealthComponent:
    started = time.perf_counter()
    if not settings.GEMINI_API_KEY:
        return _component("degraded", started, "GEMINI_API_KEY is not configured; fallback analysis is active")
    return _component("ok", started, f"Configured model: {settings.GEMINI_MODEL}")


def _check_threat_intel_provider() -> HealthComponent:
    started = time.perf_counter()
    providers = []
    if settings.VIRUSTOTAL_API_KEY:
        providers.append("virustotal")
    if settings.ABUSEIPDB_API_KEY:
        providers.append("abuseipdb")
    if settings.OTX_API_KEY:
        providers.append("otx")
    if not providers:
        return _component("degraded", started, "External providers not configured; internal heuristic is active")
    return _component("ok", started, ", ".join(providers))


def _check_storage() -> HealthComponent:
    started = time.perf_counter()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return _component("ok", started, "Primary relational storage reachable")
    except Exception:
        logger.exception("Storage health check failed")
        return _component("error", started, "Storage is unavailable")


def _check_migration_status() -> HealthComponent:
    started = time.perf_counter()
    try:
        with engine.connect() as conn:
            version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        return _component("ok", started, f"Current revision: {version}")
    except Exception:
        logger.exception("Migration status health check failed")
        return _component("degraded", started, "Migration status unavailable")


def _build_health(include_degraded: bool = True) -> HealthCheck:
    checks = {
        "database": _check_database(),
        "redis": _check_redis(),
        "worker": _check_worker(),
        "threat_intel_provider": _check_threat_intel_provider(),
        "ai_provider": _check_ai_provider(),
        "storage": _check_storage(),
        "migration_status": _check_migration_status(),
    }
    failing = [name for name, check in checks.items() if check.status == "error"]
    degraded = [name for name, check in checks.items() if check.status == "degraded"]
    overall = "error" if failing else "degraded" if include_degraded and degraded else "ok"
    return HealthCheck(
        status=overall,
        database=checks["database"].status,
        redis=checks["redis"].status,
        request_id=request_id_ctx.get(),
        environment=settings.ENVIRONMENT,
        timestamp=get_utc_now(),
        checks=checks,
    )


# Health Check endpoints
@app.get("/health/live", response_model=HealthStatus, tags=["Health"])
async def liveness_check():
    """Liveness probe - just checks if the app is running"""
    return HealthStatus(status="ok", request_id=request_id_ctx.get(), timestamp=get_utc_now())


@app.get("/health/ready", response_model=HealthCheck, tags=["Health"])
async def readiness_check():
    """Readiness probe - checks if dependencies are available"""
    return _build_health(include_degraded=False)


@app.get("/health", response_model=HealthCheck, tags=["Health"])
async def health_check():
    return _build_health(include_degraded=True)


@app.get(settings.METRICS_PATH, tags=["Observability"])
async def prometheus_metrics():
    if not settings.METRICS_ENABLED:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Metrics endpoint is disabled")
    body, content_type = metrics_response()
    return Response(content=body, media_type=content_type)


@app.get("/", tags=["Root"])
async def root():
    return {"message": f"Welcome to {settings.PROJECT_NAME} API!"}
