from fastapi import APIRouter, Depends, HTTPException, Request, status, Query
from sqlalchemy.orm import Session
from typing import Optional

from src.api.deps import get_db, get_current_user, require_roles
from src.models.pydantic import IOC, IOCCreate, IOCUpdate, IOCListResponse
from src.models.sqlalchemy import IndicatorType, User, UserRole
from src.services.ioc_service import ioc_service
from src.services.threat_intel_service import threat_intel_service
from src.services.audit_service import audit_service


router = APIRouter(prefix="/iocs", tags=["IOCs"])


def _client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


@router.post("", response_model=IOC, status_code=status.HTTP_201_CREATED)
def create_ioc(
    ioc_data: IOCCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    try:
        ioc = ioc_service.create_ioc(
            db, current_user.tenant_id, current_user.id, ioc_data
        )
        audit_service.record(
            db,
            action="ioc_created",
            user=current_user,
            resource_type="ioc",
            resource_id=ioc.id,
            ip_address=_client_ip(request),
            details={"value": ioc.value, "type": ioc.type.value},
        )
        return IOC.model_validate(ioc)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.get("", response_model=IOCListResponse)
def list_iocs(
    ioc_type: Optional[IndicatorType] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    items, total = ioc_service.list_iocs(
        db, current_user.tenant_id, ioc_type=ioc_type, search=search, page=page, page_size=page_size
    )
    return IOCListResponse(
        items=[IOC.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/stats", response_model=dict)
def get_ioc_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return ioc_service.get_ioc_stats(db, current_user.tenant_id)


@router.get("/{ioc_id}", response_model=IOC)
def get_ioc(
    ioc_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        ioc = ioc_service.get_ioc_by_id(db, current_user.tenant_id, ioc_id)
        return IOC.model_validate(ioc)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e


@router.post("/{ioc_id}/enrich", response_model=list[dict])
def enrich_ioc(
    ioc_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    try:
        ioc = ioc_service.get_ioc_by_id(db, current_user.tenant_id, ioc_id)
        results = threat_intel_service.enrich_ioc(db, ioc)
        audit_service.record(
            db,
            action="ioc_enriched",
            user=current_user,
            resource_type="ioc",
            resource_id=ioc.id,
            ip_address=_client_ip(request),
        )
        return results
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e


@router.patch("/{ioc_id}", response_model=IOC)
def update_ioc(
    ioc_id: str,
    update_data: IOCUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    try:
        ioc = ioc_service.update_ioc(
            db, current_user.tenant_id, ioc_id, update_data
        )
        audit_service.record(
            db,
            action="ioc_updated",
            user=current_user,
            resource_type="ioc",
            resource_id=ioc.id,
            ip_address=_client_ip(request),
        )
        return IOC.model_validate(ioc)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e


@router.delete("/{ioc_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_ioc(
    ioc_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
):
    try:
        ioc_service.delete_ioc(db, current_user.tenant_id, ioc_id)
        audit_service.record(
            db,
            action="ioc_deleted",
            user=current_user,
            resource_type="ioc",
            resource_id=ioc_id,
            ip_address=_client_ip(request),
        )
        return None
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
