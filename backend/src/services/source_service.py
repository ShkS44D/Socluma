from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from src.core.security import generate_api_key, get_api_key_hash, verify_api_key
from src.models.pydantic import AlertSourceCreate, AlertSourceUpdate
from src.models.sqlalchemy import AlertSource, AlertSourceType


class SourceService:
    def list_sources(self, db: Session, tenant_id: str) -> list[AlertSource]:
        return (
            db.query(AlertSource)
            .filter(AlertSource.tenant_id == tenant_id)
            .order_by(AlertSource.created_at.desc())
            .all()
        )

    def create_source(
        self,
        db: Session,
        tenant_id: str,
        source_data: AlertSourceCreate,
    ) -> tuple[AlertSource, str]:
        existing = (
            db.query(AlertSource)
            .filter(AlertSource.tenant_id == tenant_id, AlertSource.name == source_data.name)
            .first()
        )
        if existing is not None:
            raise ValueError("Alert source already exists")

        generated_api_key = source_data.api_key or self._generate_api_key()
        source = AlertSource(
            tenant_id=tenant_id,
            name=source_data.name,
            type=source_data.type,
            api_key_hash=get_api_key_hash(generated_api_key),
            enabled=source_data.enabled,
            is_active=source_data.enabled,
            config=source_data.config,
        )
        db.add(source)
        db.commit()
        db.refresh(source)
        return source, generated_api_key

    def update_source(
        self,
        db: Session,
        tenant_id: str,
        source_id: str,
        source_data: AlertSourceUpdate,
    ) -> tuple[AlertSource, Optional[str]]:
        source = self.get_source_by_id(db, tenant_id, source_id)

        if source_data.name and source_data.name != source.name:
            existing = (
                db.query(AlertSource)
                .filter(
                    AlertSource.tenant_id == tenant_id,
                    AlertSource.name == source_data.name,
                    AlertSource.id != source_id,
                )
                .first()
            )
            if existing is not None:
                raise ValueError("Alert source already exists")
            source.name = source_data.name

        if source_data.type is not None:
            source.type = source_data.type
        if source_data.config is not None:
            source.config = source_data.config
        if source_data.enabled is not None:
            source.enabled = source_data.enabled
            source.is_active = source_data.enabled

        generated_api_key: Optional[str] = None
        if source_data.api_key:
            generated_api_key = source_data.api_key
            source.api_key_hash = get_api_key_hash(source_data.api_key)

        db.add(source)
        db.commit()
        db.refresh(source)
        return source, generated_api_key

    def get_source_by_id(self, db: Session, tenant_id: str, source_id: str) -> AlertSource:
        source = (
            db.query(AlertSource)
            .filter(AlertSource.id == source_id, AlertSource.tenant_id == tenant_id)
            .first()
        )
        if source is None:
            raise ValueError("Alert source not found")
        return source

    def get_source_by_name(self, db: Session, tenant_id: str, source_name: str) -> Optional[AlertSource]:
        return (
            db.query(AlertSource)
            .filter(AlertSource.tenant_id == tenant_id, AlertSource.name == source_name)
            .first()
        )

    def authenticate_source(
        self,
        db: Session,
        source_name: str,
        api_key: str,
    ) -> AlertSource:
        source = db.query(AlertSource).filter(AlertSource.name == source_name).first()
        if source is None:
            raise ValueError("Alert source not found")
        if not source.enabled or not source.is_active:
            raise ValueError("Alert source is disabled")
        if not source.api_key_hash or not verify_api_key(api_key, source.api_key_hash):
            raise ValueError("Invalid source API key")
        return source

    def get_or_create_internal_source(
        self,
        db: Session,
        tenant_id: str,
        source_name: str,
        source_type: AlertSourceType = AlertSourceType.API,
    ) -> AlertSource:
        source = self.get_source_by_name(db, tenant_id, source_name)
        if source is not None:
            if not source.enabled:
                raise ValueError("Alert source is disabled")
            return source

        generated_key = self._generate_api_key()
        source = AlertSource(
            tenant_id=tenant_id,
            name=source_name,
            type=source_type,
            api_key_hash=get_api_key_hash(generated_key),
            enabled=True,
            is_active=True,
        )
        db.add(source)
        db.commit()
        db.refresh(source)
        return source

    def _generate_api_key(self) -> str:
        return generate_api_key("src")


source_service = SourceService()
