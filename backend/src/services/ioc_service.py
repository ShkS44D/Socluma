from __future__ import annotations
from typing import Optional, List
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import or_, func

from src.models.sqlalchemy import IOC, IndicatorType, IOCEnrichment, IncidentIOC
from src.models.pydantic import IOCCreate, IOCUpdate
from src.services.websocket_service import broadcast_notification_sync, NotificationType
from src.utils.datetime_utils import utc_isoformat


class IOCService:
    def list_iocs(
        self,
        db: Session,
        tenant_id: str,
        ioc_type: Optional[IndicatorType] = None,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[IOC], int]:
        query = db.query(IOC).filter(IOC.tenant_id == tenant_id)
        if ioc_type:
            query = query.filter(IOC.type == ioc_type)
        if search:
            search_term = f"%{search.strip()}%"
            query = query.filter(
                or_(IOC.value.ilike(search_term), IOC.description.ilike(search_term))
            )
        total = query.count()
        items = (
            query.options(joinedload(IOC.enrichments))
            .order_by(IOC.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )
        return items, total

    def get_ioc_by_id(self, db: Session, tenant_id: str, ioc_id: str) -> IOC:
        ioc = (
            db.query(IOC)
            .options(joinedload(IOC.enrichments))
            .filter(IOC.id == ioc_id, IOC.tenant_id == tenant_id)
            .first()
        )
        if not ioc:
            raise ValueError("IOC not found")
        return ioc

    def create_ioc(
        self,
        db: Session,
        tenant_id: str,
        user_id: str,
        ioc_data: IOCCreate,
    ) -> IOC:
        ioc = IOC(
            tenant_id=tenant_id,
            type=ioc_data.type,
            value=ioc_data.value,
            description=ioc_data.description,
            source=ioc_data.source,
            severity=ioc_data.severity,
            confidence_score=ioc_data.confidence_score,
            tags=ioc_data.tags,
            is_active=ioc_data.is_active,
            created_by=user_id,
        )
        db.add(ioc)
        db.commit()
        db.refresh(ioc)
        
        # Broadcast new IOC
        broadcast_notification_sync(tenant_id, NotificationType.IOC_UPDATE, {
            "id": ioc.id,
            "type": ioc.type.value if hasattr(ioc.type, 'value') else str(ioc.type),
            "value": ioc.value,
            "severity": ioc.severity.value if hasattr(ioc.severity, 'value') else str(ioc.severity),
            "created_at": utc_isoformat(ioc.created_at)
        })
        
        return ioc

    def update_ioc(
        self,
        db: Session,
        tenant_id: str,
        ioc_id: str,
        update_data: IOCUpdate,
    ) -> IOC:
        ioc = self.get_ioc_by_id(db, tenant_id, ioc_id)
        if update_data.description is not None:
            ioc.description = update_data.description
        if update_data.source is not None:
            ioc.source = update_data.source
        if update_data.severity is not None:
            ioc.severity = update_data.severity
        if update_data.confidence_score is not None:
            ioc.confidence_score = update_data.confidence_score
        if update_data.tags is not None:
            ioc.tags = update_data.tags
        if update_data.is_active is not None:
            ioc.is_active = update_data.is_active
        db.add(ioc)
        db.commit()
        db.refresh(ioc)
        
        # Broadcast IOC update
        broadcast_notification_sync(tenant_id, NotificationType.IOC_UPDATE, {
            "id": ioc.id,
            "type": ioc.type.value if hasattr(ioc.type, 'value') else str(ioc.type),
            "value": ioc.value,
            "severity": ioc.severity.value if hasattr(ioc.severity, 'value') else str(ioc.severity),
            "updated_at": utc_isoformat(ioc.updated_at)
        })
        
        return ioc

    def delete_ioc(self, db: Session, tenant_id: str, ioc_id: str) -> None:
        ioc = self.get_ioc_by_id(db, tenant_id, ioc_id)
        db.delete(ioc)
        db.commit()

    def add_enrichment(
        self,
        db: Session,
        ioc_id: str,
        provider: str,
        reputation: Optional[str],
        malicious_count: int,
        total_reports: int,
        raw_response: Optional[dict] = None,
    ) -> IOCEnrichment:
        enrichment = IOCEnrichment(
            ioc_id=ioc_id,
            provider=provider,
            reputation=reputation,
            malicious_count=malicious_count,
            total_reports=total_reports,
            raw_response=raw_response,
        )
        db.add(enrichment)
        db.commit()
        db.refresh(enrichment)
        
        # Get the IOC to get tenant_id
        ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
        if ioc:
            # Broadcast IOC update with new enrichment
            broadcast_notification_sync(ioc.tenant_id, NotificationType.IOC_UPDATE, {
                "id": ioc.id,
                "type": ioc.type.value if hasattr(ioc.type, 'value') else str(ioc.type),
                "value": ioc.value,
                "severity": ioc.severity.value if hasattr(ioc.severity, 'value') else str(ioc.severity),
                "enrichment": {
                    "provider": provider,
                    "reputation": reputation,
                    "malicious_count": malicious_count,
                    "total_reports": total_reports
                },
                "updated_at": utc_isoformat(enrichment.created_at)
            })
        
        return enrichment

    def get_ioc_stats(self, db: Session, tenant_id: str) -> dict:
        total = db.query(func.count(IOC.id)).filter(IOC.tenant_id == tenant_id).scalar() or 0
        malicious = (
            db.query(func.count(IOC.id))
            .filter(IOC.tenant_id == tenant_id, IOC.severity.in_(["high", "critical"]))
            .scalar()
            or 0
        )
        high_confidence = (
            db.query(func.count(IOC.id))
            .filter(IOC.tenant_id == tenant_id, IOC.confidence_score >= 70)
            .scalar()
            or 0
        )
        # Recent IOCs (last 7 days)
        from datetime import datetime, timedelta, timezone
        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
        recent = (
            db.query(func.count(IOC.id))
            .filter(IOC.tenant_id == tenant_id, IOC.created_at >= seven_days_ago)
            .scalar()
            or 0
        )
        return {
            "total_iocs": total,
            "malicious_iocs": malicious,
            "high_confidence": high_confidence,
            "recent_iocs": recent,
        }

    def get_ioc_by_value_and_type(
        self, db: Session, tenant_id: str, value: str, ioc_type: IndicatorType
    ) -> Optional[IOC]:
        return (
            db.query(IOC)
            .filter(
                IOC.tenant_id == tenant_id,
                IOC.value == value,
                IOC.type == ioc_type
            )
            .first()
        )

    def associate_ioc_with_incident(
        self, db: Session, tenant_id: str, incident_id: str, ioc_id: str
    ) -> IncidentIOC:
        # Check if already associated
        existing = (
            db.query(IncidentIOC)
            .filter(
                IncidentIOC.tenant_id == tenant_id,
                IncidentIOC.incident_id == incident_id,
                IncidentIOC.ioc_id == ioc_id
            )
            .first()
        )
        if existing:
            return existing
        # Create new association
        assoc = IncidentIOC(
            tenant_id=tenant_id,
            incident_id=incident_id,
            ioc_id=ioc_id
        )
        db.add(assoc)
        db.commit()
        db.refresh(assoc)
        return assoc

    def get_iocs_for_incident(
        self, db: Session, tenant_id: str, incident_id: str
    ) -> List[IOC]:
        # Get all IOCs associated with incident
        incident_iocs = (
            db.query(IncidentIOC)
            .filter(
                IncidentIOC.tenant_id == tenant_id,
                IncidentIOC.incident_id == incident_id
            )
            .all()
        )
        ioc_ids = [a.ioc_id for a in incident_iocs]
        if not ioc_ids:
            return []
        return (
            db.query(IOC)
            .options(joinedload(IOC.enrichments))
            .filter(IOC.id.in_(ioc_ids))
            .all()
        )


ioc_service = IOCService()
