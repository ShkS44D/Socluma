from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List
from src.api.deps import get_db
from src.core.permissions import Permission, require_permission
from src.models.sqlalchemy import User
from src.models.pydantic import (
    LogSource, LogSourceCreate, LogSourceUpdate
)
from src.services.audit_service import audit_service

router = APIRouter(prefix="/log-sources", tags=["Log Sources"])


@router.get("", response_model=List[LogSource])
def list_log_sources(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COLLECTORS_VIEW))
):
    from src.models.sqlalchemy import LogSource as LogSourceModel
    return db.query(LogSourceModel).filter(
        LogSourceModel.tenant_id == current_user.tenant_id
    ).all()


@router.post("", response_model=LogSource, status_code=status.HTTP_201_CREATED)
def create_log_source(
    log_source: LogSourceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COLLECTORS_MANAGE))
):
    from src.models.sqlalchemy import LogSource as LogSourceModel
    db_log_source = LogSourceModel(
        tenant_id=current_user.tenant_id,
        **log_source.model_dump()
    )
    db.add(db_log_source)
    db.commit()
    db.refresh(db_log_source)

    audit_service.record(
        db,
        action="log_source_created",
        user=current_user,
        resource_type="log_source",
        resource_id=db_log_source.id,
        details={"name": db_log_source.name}
    )
    return db_log_source


@router.patch("/{log_source_id}", response_model=LogSource)
def update_log_source(
    log_source_id: str,
    log_source_update: LogSourceUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COLLECTORS_MANAGE))
):
    from src.models.sqlalchemy import LogSource as LogSourceModel
    db_log_source = db.query(LogSourceModel).filter(
        LogSourceModel.id == log_source_id,
        LogSourceModel.tenant_id == current_user.tenant_id
    ).first()
    if not db_log_source:
        raise HTTPException(status_code=404, detail="Log source not found")
    
    update_data = log_source_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_log_source, key, value)
    
    db.commit()
    db.refresh(db_log_source)
    
    audit_service.record(
        db,
        action="log_source_updated",
        user=current_user,
        resource_type="log_source",
        resource_id=db_log_source.id
    )
    return db_log_source
