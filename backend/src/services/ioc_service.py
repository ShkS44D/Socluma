from __future__ import annotations
from typing import Optional, List
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import or_, func
from sqlalchemy.exc import IntegrityError

from src.models.sqlalchemy import (
    IOC,
    IndicatorType,
    IOCEnrichment,
    IOCScoreHistory,
    IOCSighting,
    IOCWatchlistMember,
    IncidentIOC,
)
from src.models.pydantic import IOCCreate, IOCUpdate
from src.services.websocket_service import broadcast_notification_sync, NotificationType
from src.utils.datetime_utils import utc_isoformat
from src.services.ioc_intelligence_service import (
    IOCDuplicateError,
    IOCValidationError,
    ioc_intelligence_service,
    normalize_ioc,
)


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
            description=ioc_data.description,
            source=ioc_data.source,
            severity=ioc_data.severity,
            confidence_score=ioc_data.confidence_score,
            source_reliability=ioc_data.source_reliability,
            lifecycle_status=ioc_data.lifecycle_status,
            review_status="pending",
            tlp=ioc_data.tlp,
            valid_from=ioc_data.valid_from,
            valid_until=ioc_data.valid_until,
            source_references=ioc_data.source_references,
            external_source_ids=ioc_data.external_source_ids,
            stix_id=ioc_data.stix_id,
            classification=ioc_data.classification,
            tags=ioc_data.tags,
            is_active=ioc_data.lifecycle_status in {"active", "monitoring"},
            created_by=user_id,
        )
        ioc_intelligence_service.apply_normalization(ioc, ioc_data.type, ioc_data.value)
        duplicate = db.query(IOC).filter(
            IOC.tenant_id == tenant_id,
            IOC.type == ioc.type,
            IOC.normalized_value == ioc.normalized_value,
        ).first()
        if duplicate:
            raise IOCDuplicateError(f"IOC already exists as {duplicate.id}")
        db.add(ioc)
        db.flush()
        ioc_intelligence_service.recalculate(db, ioc)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise IOCDuplicateError("IOC already exists") from exc
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
        if update_data.source_reliability is not None:
            ioc.source_reliability = update_data.source_reliability
        if update_data.lifecycle_status is not None:
            ioc_intelligence_service.transition(ioc, update_data.lifecycle_status, update_data.lifecycle_reason)
        if update_data.tlp is not None:
            if update_data.tlp not in {"TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"}:
                raise IOCValidationError("Unsupported TLP marking")
            ioc.tlp = update_data.tlp
        if update_data.valid_until is not None:
            ioc.valid_until = update_data.valid_until
        if update_data.classification is not None:
            ioc.classification = update_data.classification
        if update_data.tags is not None:
            ioc.tags = update_data.tags
        if update_data.is_active is not None:
            ioc.is_active = update_data.is_active
            if update_data.lifecycle_status is None:
                ioc.lifecycle_status = "active" if update_data.is_active else "monitoring"
        ioc_intelligence_service.recalculate(db, ioc)
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

    def merge_iocs(
        self,
        db: Session,
        tenant_id: str,
        target_id: str,
        source_id: str,
        reason: str,
    ) -> IOC:
        if not reason.strip():
            raise IOCValidationError("A merge reason is required")
        if target_id == source_id:
            raise IOCValidationError("An IOC cannot be merged into itself")
        target = db.query(IOC).filter(IOC.id == target_id, IOC.tenant_id == tenant_id).first()
        source = db.query(IOC).filter(IOC.id == source_id, IOC.tenant_id == tenant_id).first()
        if not target or not source:
            raise ValueError("IOC not found")
        if target.type != source.type:
            raise IOCValidationError("Only IOCs of the same type can be merged")

        target.tags = sorted(set((target.tags or []) + (source.tags or [])))
        target.source_references = sorted(
            set((target.source_references or []) + (source.source_references or []))
        )
        target.external_source_ids = {
            **(source.external_source_ids or {}),
            **(target.external_source_ids or {}),
        }
        target.merged_from_ids = sorted(
            set((target.merged_from_ids or []) + (source.merged_from_ids or []) + [source.id])
        )
        target.internal_sighting_count = (
            (target.internal_sighting_count or 0) + (source.internal_sighting_count or 0)
        )
        if source.first_internal_sighting and (
            not target.first_internal_sighting
            or source.first_internal_sighting < target.first_internal_sighting
        ):
            target.first_internal_sighting = source.first_internal_sighting
        if source.last_internal_sighting and (
            not target.last_internal_sighting
            or source.last_internal_sighting > target.last_internal_sighting
        ):
            target.last_internal_sighting = source.last_internal_sighting

        for link in db.query(IncidentIOC).filter(
            IncidentIOC.tenant_id == tenant_id, IncidentIOC.ioc_id == source.id
        ).all():
            duplicate = db.query(IncidentIOC.id).filter(
                IncidentIOC.tenant_id == tenant_id,
                IncidentIOC.incident_id == link.incident_id,
                IncidentIOC.ioc_id == target.id,
            ).first()
            if duplicate:
                db.delete(link)
            else:
                link.ioc_id = target.id

        for member in db.query(IOCWatchlistMember).filter(
            IOCWatchlistMember.tenant_id == tenant_id, IOCWatchlistMember.ioc_id == source.id
        ).all():
            duplicate = db.query(IOCWatchlistMember.id).filter(
                IOCWatchlistMember.tenant_id == tenant_id,
                IOCWatchlistMember.watchlist_id == member.watchlist_id,
                IOCWatchlistMember.ioc_id == target.id,
            ).first()
            if duplicate:
                db.delete(member)
            else:
                member.ioc_id = target.id

        for sighting in db.query(IOCSighting).filter(
            IOCSighting.tenant_id == tenant_id, IOCSighting.ioc_id == source.id
        ).all():
            duplicate = db.query(IOCSighting.id).filter(
                IOCSighting.tenant_id == tenant_id,
                IOCSighting.ioc_id == target.id,
                IOCSighting.event_id == sighting.event_id,
                IOCSighting.matched_field == sighting.matched_field,
            ).first()
            if duplicate:
                db.delete(sighting)
            else:
                sighting.ioc_id = target.id
                sighting.ioc_content_hash = target.content_hash

        db.query(IOCEnrichment).filter(IOCEnrichment.ioc_id == source.id).update(
            {"ioc_id": target.id}, synchronize_session=False
        )
        db.query(IOCScoreHistory).filter(
            IOCScoreHistory.tenant_id == tenant_id, IOCScoreHistory.ioc_id == source.id
        ).update({"ioc_id": target.id}, synchronize_session=False)

        source.lifecycle_status = "merged"
        source.review_status = "merged"
        source.is_active = False
        source.description = (
            f"{source.description or ''}\nMerged into {target.id}: {reason.strip()}"
        ).strip()
        self._refresh_merged_sighting_totals(db, target)
        ioc_intelligence_service.recalculate(db, target)
        db.commit()
        db.refresh(target)
        return target

    @staticmethod
    def _refresh_merged_sighting_totals(db: Session, target: IOC) -> None:
        db.flush()
        target.internal_sighting_count = db.query(func.count(IOCSighting.id)).filter(
            IOCSighting.tenant_id == target.tenant_id, IOCSighting.ioc_id == target.id
        ).scalar() or 0

    def add_enrichment(
        self,
        db: Session,
        tenant_id: str,
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
            # Provider payloads are normalized before reaching this service.
            # The legacy column remains for migration compatibility, but raw
            # provider bodies are never persisted or exposed.
            raw_response=None,
            provider_verdict=reputation,
            confidence=(raw_response or {}).get("confidence_score"),
            categories=(raw_response or {}).get("categories") or [],
            detection_counts={
                "malicious": malicious_count,
                "total": total_reports,
            },
            safe_result=raw_response or {},
            raw_response_hash=__import__("hashlib").sha256(
                __import__("json").dumps(raw_response or {}, sort_keys=True, default=str).encode()
            ).hexdigest(),
        )
        db.add(enrichment)
        db.commit()
        db.refresh(enrichment)
        
        ioc = db.query(IOC).filter(IOC.id == ioc_id, IOC.tenant_id == tenant_id).first()
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
            "active_iocs": db.query(func.count(IOC.id)).filter(IOC.tenant_id == tenant_id, IOC.lifecycle_status == "active").scalar() or 0,
            "monitoring_iocs": db.query(func.count(IOC.id)).filter(IOC.tenant_id == tenant_id, IOC.lifecycle_status == "monitoring").scalar() or 0,
            "expired_iocs": db.query(func.count(IOC.id)).filter(IOC.tenant_id == tenant_id, IOC.lifecycle_status == "expired").scalar() or 0,
            "revoked_iocs": db.query(func.count(IOC.id)).filter(IOC.tenant_id == tenant_id, IOC.lifecycle_status == "revoked").scalar() or 0,
            "high_risk_iocs": db.query(func.count(IOC.id)).filter(IOC.tenant_id == tenant_id, IOC.risk_score >= 70).scalar() or 0,
            "iocs_with_sightings": db.query(func.count(IOC.id)).filter(IOC.tenant_id == tenant_id, IOC.internal_sighting_count > 0).scalar() or 0,
        }

    def get_ioc_by_value_and_type(
        self, db: Session, tenant_id: str, value: str, ioc_type: IndicatorType
    ) -> Optional[IOC]:
        normalized = normalize_ioc(ioc_type, value)
        return (
            db.query(IOC)
            .filter(
                IOC.tenant_id == tenant_id,
                IOC.normalized_value == normalized.canonical,
                IOC.type == IndicatorType(normalized.type)
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
            .filter(IOC.tenant_id == tenant_id, IOC.id.in_(ioc_ids))
            .all()
        )


ioc_service = IOCService()
