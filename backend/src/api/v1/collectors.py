from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import timedelta
from typing import List
from src.api.deps import get_db, get_current_user, require_roles, get_current_collector
from src.core.config import get_settings
from src.models.sqlalchemy import User, UserRole, Collector as CollectorModel, CollectorStatus
from src.models.pydantic import (
    Collector, CollectorCreate, CollectorRegistrationResponse
)
from src.services.audit_service import audit_service
from src.utils.datetime_utils import ensure_utc, get_utc_now
from src.core.security import generate_collector_token, get_collector_token_hash, get_collector_token_lookup_hash
from src.core.observability import COLLECTOR_HEARTBEATS
from src.services.organization_service import organization_service

router = APIRouter(prefix="/collectors", tags=["Collectors"])


@router.get("", response_model=List[Collector])
def list_collectors(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
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
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))
):
    organization_service.enforce_limit(db, current_user.tenant_id, "collectors")
    # Generate token and hash it
    token = generate_collector_token()
    token_hash = get_collector_token_hash(token)
    
    db_collector = CollectorModel(
        tenant_id=current_user.tenant_id,
        name=collector.name,
        type=collector.type,
        hostname=collector.hostname,
        log_source_id=collector.log_source_id,
        token=token_hash,
        token_lookup_hash=get_collector_token_lookup_hash(token),
    )
    db.add(db_collector)
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


@router.post("/{collector_id}/heartbeat", response_model=Collector)
def collector_heartbeat(
    collector_id: str,
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
