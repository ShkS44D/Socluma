from __future__ import annotations
from typing import Optional
from sqlalchemy.orm import Session

from src.models.sqlalchemy import Asset, AssetCriticality
from src.models.pydantic import AssetCreate, AssetUpdate


class AssetService:
    def list_assets(
        self,
        db: Session,
        tenant_id: str,
        criticality: Optional[AssetCriticality] = None,
        search: Optional[str] = None,
    ) -> list[Asset]:
        query = db.query(Asset).filter(Asset.tenant_id == tenant_id)
        if criticality:
            query = query.filter(Asset.criticality == criticality)
        if search:
            search_term = f"%{search.strip()}%"
            query = query.filter(
                Asset.hostname.ilike(search_term) | Asset.ip_address.ilike(search_term)
            )
        return query.order_by(Asset.created_at.desc()).all()

    def get_asset_by_id(self, db: Session, tenant_id: str, asset_id: str) -> Asset:
        asset = db.query(Asset).filter(Asset.id == asset_id, Asset.tenant_id == tenant_id).first()
        if not asset:
            raise ValueError("Asset not found")
        return asset

    def create_asset(
        self,
        db: Session,
        tenant_id: str,
        asset_data: AssetCreate,
    ) -> Asset:
        asset = Asset(
            tenant_id=tenant_id,
            hostname=asset_data.hostname,
            ip_address=asset_data.ip_address,
            operating_system=asset_data.operating_system,
            owner=asset_data.owner,
            criticality=asset_data.criticality,
            last_seen=asset_data.last_seen,
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)
        return asset

    def update_asset(
        self,
        db: Session,
        tenant_id: str,
        asset_id: str,
        update_data: AssetUpdate,
    ) -> Asset:
        asset = self.get_asset_by_id(db, tenant_id, asset_id)
        if update_data.hostname is not None:
            asset.hostname = update_data.hostname
        if update_data.ip_address is not None:
            asset.ip_address = update_data.ip_address
        if update_data.operating_system is not None:
            asset.operating_system = update_data.operating_system
        if update_data.owner is not None:
            asset.owner = update_data.owner
        if update_data.criticality is not None:
            asset.criticality = update_data.criticality
        if update_data.last_seen is not None:
            asset.last_seen = update_data.last_seen
        db.add(asset)
        db.commit()
        db.refresh(asset)
        return asset

    def delete_asset(self, db: Session, tenant_id: str, asset_id: str) -> None:
        asset = self.get_asset_by_id(db, tenant_id, asset_id)
        db.delete(asset)
        db.commit()


asset_service = AssetService()
