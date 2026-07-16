from fastapi import APIRouter, Depends, HTTPException, Request, status, Query
from sqlalchemy.orm import Session
from typing import Optional

from src.api.deps import get_db, get_current_user, require_roles
from src.models.pydantic import Asset, AssetCreate, AssetUpdate
from src.models.sqlalchemy import AssetCriticality, User, UserRole
from src.services.asset_service import asset_service
from src.services.audit_service import audit_service


router = APIRouter(prefix="/assets", tags=["Assets"])


def _client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


@router.post("", response_model=Asset, status_code=status.HTTP_201_CREATED)
def create_asset(
    asset_data: AssetCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    try:
        asset = asset_service.create_asset(db, current_user.tenant_id, asset_data)
        audit_service.record(
            db,
            action="asset_created",
            user=current_user,
            resource_type="asset",
            resource_id=asset.id,
            ip_address=_client_ip(request),
            details={"hostname": asset.hostname},
        )
        return Asset.model_validate(asset)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.get("", response_model=list[Asset])
def list_assets(
    criticality: Optional[AssetCriticality] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    assets = asset_service.list_assets(db, current_user.tenant_id, criticality=criticality, search=search)
    return [Asset.model_validate(asset) for asset in assets]


@router.get("/{asset_id}", response_model=Asset)
def get_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        asset = asset_service.get_asset_by_id(db, current_user.tenant_id, asset_id)
        return Asset.model_validate(asset)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e


@router.patch("/{asset_id}", response_model=Asset)
def update_asset(
    asset_id: str,
    update_data: AssetUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    try:
        asset = asset_service.update_asset(db, current_user.tenant_id, asset_id, update_data)
        audit_service.record(
            db,
            action="asset_updated",
            user=current_user,
            resource_type="asset",
            resource_id=asset.id,
            ip_address=_client_ip(request),
        )
        return Asset.model_validate(asset)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
):
    try:
        asset_service.delete_asset(db, current_user.tenant_id, asset_id)
        audit_service.record(
            db,
            action="asset_deleted",
            user=current_user,
            resource_type="asset",
            resource_id=asset_id,
            ip_address=_client_ip(request),
        )
        return None
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
