from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from src.api.deps import get_db
from src.core.permissions import Permission, require_permission
from src.models.pydantic import (
    AlertSource as AlertSourceResponse,
    AlertSourceCreate,
    AlertSourceCreateResponse,
    AlertSourceUpdate,
)
from src.models.sqlalchemy import User
from src.services.audit_service import audit_service
from src.services.source_service import source_service


router = APIRouter(prefix="/sources", tags=["Alert Sources"])


def _client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


def _handle_source_error(exc: ValueError) -> None:
    detail = str(exc)
    if detail == "Alert source not found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail) from exc
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc


@router.post("", response_model=AlertSourceCreateResponse, status_code=status.HTTP_201_CREATED)
def create_source(
    source_in: AlertSourceCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COLLECTORS_MANAGE)),
):
    try:
        source, generated_api_key = source_service.create_source(db, current_user.tenant_id, source_in)
        audit_service.record(
            db,
            action="alert_source_created",
            user=current_user,
            resource_type="alert_source",
            resource_id=source.id,
            ip_address=_client_ip(request),
            details={"name": source.name, "type": source.type.value, "enabled": source.enabled},
        )
        return AlertSourceCreateResponse.model_validate(
            {
                **AlertSourceResponse.model_validate(source).model_dump(),
                "generated_api_key": generated_api_key,
            }
        )
    except ValueError as exc:
        _handle_source_error(exc)


@router.get("", response_model=list[AlertSourceResponse])
def list_sources(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COLLECTORS_VIEW)),
):
    return [AlertSourceResponse.model_validate(source) for source in source_service.list_sources(db, current_user.tenant_id)]


@router.patch("/{source_id}", response_model=AlertSourceCreateResponse)
def update_source(
    source_id: str,
    source_in: AlertSourceUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COLLECTORS_MANAGE)),
):
    try:
        source, generated_api_key = source_service.update_source(
            db,
            current_user.tenant_id,
            source_id,
            source_in,
        )
        audit_service.record(
            db,
            action="alert_source_updated",
            user=current_user,
            resource_type="alert_source",
            resource_id=source.id,
            ip_address=_client_ip(request),
            details={"name": source.name, "type": source.type.value, "enabled": source.enabled},
        )
        return AlertSourceCreateResponse.model_validate(
            {
                **AlertSourceResponse.model_validate(source).model_dump(),
                "generated_api_key": generated_api_key,
            }
        )
    except ValueError as exc:
        _handle_source_error(exc)


@router.post("/{source_id}/deactivate", response_model=AlertSourceResponse)
def deactivate_source(
    source_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COLLECTORS_REVOKE)),
):
    try:
        source = source_service.get_source_by_id(db, current_user.tenant_id, source_id)
        source.enabled = False
        source.is_active = False
        db.add(source)
        db.commit()
        db.refresh(source)
        audit_service.record(
            db,
            action="alert_source_deactivated",
            user=current_user,
            resource_type="alert_source",
            resource_id=source.id,
            ip_address=_client_ip(request),
            details={"name": source.name},
        )
        return AlertSourceResponse.model_validate(source)
    except ValueError as exc:
        _handle_source_error(exc)
