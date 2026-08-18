from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import timedelta
import secrets
from typing import List
from src.api.deps import get_db, get_current_collector
from src.core.permissions import Permission, require_permission
from src.core.config import get_settings
from src.models.sqlalchemy import (
    User, Collector as CollectorModel, CollectorStatus, CollectorCredential,
    CollectorEnrollmentToken, CollectorHeartbeatRecord, CollectorCheckpoint,
    LogSource as LogSourceModel,
)
from src.models.pydantic import (
    Collector, CollectorCreate, CollectorRegistrationResponse, CollectorHeartbeat,
    EnrollmentTokenCreate, EnrollmentTokenResponse, CollectorEnrollRequest,
)
from src.services.audit_service import audit_service
from src.utils.datetime_utils import ensure_utc, get_utc_now
from src.core.security import generate_collector_token, get_collector_token_hash, get_collector_token_lookup_hash
from src.core.observability import COLLECTOR_HEARTBEATS
from src.services.organization_service import organization_service
from src.core.security import verify_collector_token

router = APIRouter(prefix="/collectors", tags=["Collectors"])


@router.get("", response_model=List[Collector])
def list_collectors(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COLLECTORS_VIEW))
):
    collectors = db.query(CollectorModel).filter(
        CollectorModel.tenant_id == current_user.tenant_id
    ).all()
    cutoff = get_utc_now() - timedelta(seconds=get_settings().COLLECTOR_OFFLINE_AFTER_SECONDS)
    changed = False
    for collector in collectors:
        last_seen = ensure_utc(collector.last_seen) if collector.last_seen else None
        if collector.status == CollectorStatus.ONLINE and (not last_seen or last_seen < cutoff):
            collector.status = CollectorStatus.OFFLINE
            db.add(collector)
            changed = True
    if changed:
        db.commit()
        for collector in collectors:
            db.refresh(collector)
    return collectors


@router.post("/register", response_model=CollectorRegistrationResponse, status_code=status.HTTP_201_CREATED)
def register_collector(
    collector: CollectorCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COLLECTORS_MANAGE))
):
    organization_service.enforce_limit(db, current_user.tenant_id, "collectors")
    log_source_id = collector.log_source_id
    if log_source_id:
        log_source = db.query(LogSourceModel).filter(
            LogSourceModel.id == log_source_id,
            LogSourceModel.tenant_id == current_user.tenant_id,
        ).first()
        if not log_source:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error_code": "LOG_SOURCE_NOT_FOUND",
                    "message": "The selected log source was not found in this organization.",
                },
            )
    # Generate token and hash it
    token = generate_collector_token()
    token_hash = get_collector_token_hash(token)
    expires_at = get_utc_now() + timedelta(days=get_settings().COLLECTOR_CREDENTIAL_LIFETIME_DAYS)
    
    db_collector = CollectorModel(
        tenant_id=current_user.tenant_id,
        name=collector.name,
        type=collector.type,
        hostname=collector.hostname,
        log_source_id=log_source_id,
        token=token_hash,
        token_lookup_hash=get_collector_token_lookup_hash(token),
        credential_expires_at=expires_at,
    )
    db.add(db_collector)
    db.flush()
    db.add(CollectorCredential(
        tenant_id=current_user.tenant_id, collector_id=db_collector.id,
        token_hash=token_hash, lookup_hash=get_collector_token_lookup_hash(token),
        expires_at=expires_at,
    ))
    db.commit()
    db.refresh(db_collector)

    audit_service.record(
        db,
        action="collector_registered",
        user=current_user,
        resource_type="collector",
        resource_id=db_collector.id,
        details={"name": db_collector.name}
    )
    return CollectorRegistrationResponse(id=db_collector.id, token=token)


@router.post("/enrollment-tokens", response_model=EnrollmentTokenResponse, status_code=status.HTTP_201_CREATED)
def create_enrollment_token(
    payload: EnrollmentTokenCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COLLECTORS_ENROLL)),
):
    raw = "enroll_" + secrets.token_urlsafe(32)
    expires_at = get_utc_now() + timedelta(minutes=payload.expires_minutes)
    record = CollectorEnrollmentToken(
        tenant_id=current_user.tenant_id, token_hash=get_collector_token_hash(raw),
        name=payload.name, platform=payload.platform, group_id=payload.group_id,
        max_uses=payload.max_uses, expires_at=expires_at, created_by_id=current_user.id,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    audit_service.record(
        db, action="collector_enrollment_token_created", user=current_user,
        resource_type="collector_enrollment_token", resource_id=record.id,
        details={"name": record.name, "expires_at": expires_at.isoformat(), "max_uses": record.max_uses},
    )
    return EnrollmentTokenResponse(id=record.id, token=raw, expires_at=expires_at)


@router.post("/enroll", response_model=CollectorRegistrationResponse, status_code=status.HTTP_201_CREATED)
def enroll_collector(payload: CollectorEnrollRequest, db: Session = Depends(get_db)):
    now = get_utc_now()
    candidates = db.query(CollectorEnrollmentToken).filter(
        CollectorEnrollmentToken.revoked_at.is_(None),
        CollectorEnrollmentToken.expires_at > now,
        CollectorEnrollmentToken.used_count < CollectorEnrollmentToken.max_uses,
    ).all()
    enrollment = next((item for item in candidates if verify_collector_token(payload.enrollment_token, item.token_hash)[0]), None)
    if not enrollment:
        raise HTTPException(status_code=401, detail={"error_code": "INVALID_ENROLLMENT_TOKEN", "message": "Enrollment token is invalid, expired, or already used"})
    organization_service.enforce_limit(db, enrollment.tenant_id, "collectors")
    token = generate_collector_token()
    token_hash = get_collector_token_hash(token)
    expires_at = now + timedelta(days=get_settings().COLLECTOR_CREDENTIAL_LIFETIME_DAYS)
    collector = CollectorModel(
        tenant_id=enrollment.tenant_id, name=payload.name, type=payload.type,
        hostname=payload.hostname, platform=payload.platform or enrollment.platform,
        os_version=payload.os_version, collector_version=payload.collector_version,
        architecture=payload.architecture, group_id=enrollment.group_id,
        token=token_hash, token_lookup_hash=get_collector_token_lookup_hash(token),
        credential_expires_at=expires_at,
    )
    db.add(collector)
    db.flush()
    db.add(CollectorCredential(
        tenant_id=enrollment.tenant_id, collector_id=collector.id, token_hash=token_hash,
        lookup_hash=get_collector_token_lookup_hash(token), expires_at=expires_at,
    ))
    enrollment.used_count += 1
    db.commit()
    audit_service.record(
        db, action="collector_enrolled", tenant_id=collector.tenant_id,
        resource_type="collector", resource_id=collector.id,
        details={"name": collector.name, "enrollment_token_id": enrollment.id},
    )
    return CollectorRegistrationResponse(id=collector.id, token=token)


@router.post("/{collector_id}/credentials/rotate", response_model=CollectorRegistrationResponse)
def rotate_collector_credential(
    collector_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COLLECTOR_CREDENTIALS_ROTATE)),
):
    collector = db.query(CollectorModel).filter(
        CollectorModel.id == collector_id, CollectorModel.tenant_id == current_user.tenant_id,
    ).first()
    if not collector:
        raise HTTPException(status_code=404, detail="Collector not found")
    now = get_utc_now()
    overlap = now + timedelta(minutes=get_settings().COLLECTOR_CREDENTIAL_OVERLAP_MINUTES)
    db.query(CollectorCredential).filter(
        CollectorCredential.collector_id == collector.id, CollectorCredential.revoked_at.is_(None),
    ).update({"overlap_until": overlap, "expires_at": overlap}, synchronize_session=False)
    token = generate_collector_token()
    token_hash = get_collector_token_hash(token)
    expires_at = now + timedelta(days=get_settings().COLLECTOR_CREDENTIAL_LIFETIME_DAYS)
    db.add(CollectorCredential(
        tenant_id=collector.tenant_id, collector_id=collector.id, token_hash=token_hash,
        lookup_hash=get_collector_token_lookup_hash(token), expires_at=expires_at,
    ))
    collector.token = token_hash
    collector.token_lookup_hash = get_collector_token_lookup_hash(token)
    collector.credential_rotated_at = now
    collector.credential_expires_at = expires_at
    db.commit()
    audit_service.record(
        db, action="collector_credential_rotated", user=current_user,
        resource_type="collector", resource_id=collector.id,
        details={"overlap_until": overlap.isoformat(), "expires_at": expires_at.isoformat()},
    )
    return CollectorRegistrationResponse(id=collector.id, token=token)


@router.post("/{collector_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
def revoke_collector(
    collector_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COLLECTORS_REVOKE)),
):
    collector = db.query(CollectorModel).filter(
        CollectorModel.id == collector_id, CollectorModel.tenant_id == current_user.tenant_id,
    ).first()
    if not collector:
        raise HTTPException(status_code=404, detail="Collector not found")
    now = get_utc_now()
    collector.revoked_at = now
    collector.status = CollectorStatus.OFFLINE
    db.query(CollectorCredential).filter(CollectorCredential.collector_id == collector.id).update(
        {"revoked_at": now}, synchronize_session=False,
    )
    db.commit()
    audit_service.record(db, action="collector_revoked", user=current_user, resource_type="collector", resource_id=collector.id, details={})


@router.post("/{collector_id}/heartbeat", response_model=Collector)
def collector_heartbeat(
    collector_id: str,
    payload: CollectorHeartbeat = Body(default=CollectorHeartbeat()),
    db: Session = Depends(get_db),
    current_collector: CollectorModel = Depends(get_current_collector)
):
    if current_collector.id != collector_id:
        COLLECTOR_HEARTBEATS.labels("forbidden").inc()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Not authorized for this collector"
        )
    
    current_collector.last_seen = get_utc_now()
    current_collector.status = "online"
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(current_collector, field, value)
    settings = get_settings()
    if current_collector.collector_version in settings.COLLECTOR_BLOCKED_VERSIONS:
        current_collector.health_status = "blocked_version"
    elif current_collector.collector_version not in settings.COLLECTOR_SUPPORTED_VERSIONS:
        current_collector.health_status = "upgrade_required"
    elif payload.service_status == "error" or payload.disk_percent and payload.disk_percent >= 95:
        current_collector.health_status = "degraded"
    else:
        current_collector.health_status = "healthy"
    db.add(CollectorHeartbeatRecord(
        tenant_id=current_collector.tenant_id, collector_id=current_collector.id,
        health_status=current_collector.health_status,
        safe_metrics=payload.model_dump(exclude_none=True),
    ))
    
    # Also update associated log source if exists
    if current_collector.log_source:
        from src.models.sqlalchemy import LogSource
        log_source = db.query(LogSource).filter(
            LogSource.id == current_collector.log_source_id
        ).first()
        if log_source:
            log_source.last_seen = get_utc_now()
            log_source.status = "active"
    db.commit()
    db.refresh(current_collector)
    
    # Record audit log
    audit_service.record(
        db,
        action="collector_heartbeat",
        tenant_id=current_collector.tenant_id,
        resource_type="collector",
        resource_id=current_collector.id,
        details={"name": current_collector.name}
    )
    COLLECTOR_HEARTBEATS.labels("success").inc()
    
    return current_collector


@router.get("/me/configuration")
def collector_configuration(current_collector: CollectorModel = Depends(get_current_collector)):
    settings = get_settings()
    return {
        "collector_id": current_collector.id,
        "policy_version": current_collector.applied_policy_version,
        "latest_version": settings.COLLECTOR_LATEST_VERSION,
        "supported_versions": settings.COLLECTOR_SUPPORTED_VERSIONS,
        "blocked": current_collector.collector_version in settings.COLLECTOR_BLOCKED_VERSIONS,
        "batch": {"max_events": settings.INGESTION_MAX_BATCH_EVENTS, "max_event_bytes": settings.INGESTION_MAX_EVENT_BYTES},
    }


@router.put("/me/checkpoints/{source_key}")
def update_checkpoint(
    source_key: str,
    safe_state: dict,
    db: Session = Depends(get_db),
    current_collector: CollectorModel = Depends(get_current_collector),
):
    record = db.query(CollectorCheckpoint).filter(
        CollectorCheckpoint.collector_id == current_collector.id,
        CollectorCheckpoint.source_key == source_key,
    ).first()
    if record:
        record.safe_state = safe_state
        record.checkpoint_version += 1
    else:
        record = CollectorCheckpoint(
            tenant_id=current_collector.tenant_id, collector_id=current_collector.id,
            source_key=source_key, safe_state=safe_state,
        )
        db.add(record)
    db.commit()
    return {"source_key": source_key, "checkpoint_version": record.checkpoint_version}
