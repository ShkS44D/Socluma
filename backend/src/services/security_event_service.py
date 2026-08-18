from __future__ import annotations
from typing import Optional
from datetime import datetime, timezone
from sqlalchemy import func
from sqlalchemy.orm import Session, selectinload

from src.models.sqlalchemy import SecurityEvent, EventType, Severity
from src.models.pydantic import SecurityEventCreate
from src.utils.ocsf_normalizer import normalize_alert
from src.utils.datetime_utils import ensure_utc, get_utc_now, utc_isoformat
from src.services.websocket_service import broadcast_notification_sync, NotificationType


class SecurityEventService:
    def list_events(
        self,
        db: Session,
        tenant_id: str,
        event_type: Optional[EventType] = None,
        severity: Optional[Severity] = None,
        limit: int = 100,
        offset: int = 0,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
    ) -> list[SecurityEvent]:
        query = db.query(SecurityEvent).filter(SecurityEvent.tenant_id == tenant_id)
        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type)
        if severity:
            query = query.filter(SecurityEvent.severity == severity)
        sort_map = {
            "timestamp": SecurityEvent.timestamp,
            "created_at": SecurityEvent.created_at,
            "severity": SecurityEvent.severity,
            "event_type": SecurityEvent.event_type,
        }
        sort_column = sort_map.get(sort_by, SecurityEvent.timestamp)
        order_clause = sort_column.asc() if sort_order.lower() == "asc" else sort_column.desc()
        return (
            query.options(selectinload(SecurityEvent.detection_matches))
            .order_by(order_clause)
            .offset(offset)
            .limit(limit)
            .all()
        )

    def count_events_since(
        self,
        db: Session,
        tenant_id: str,
        since: datetime,
    ) -> int:
        return (
            db.query(func.count(SecurityEvent.id))
            .filter(
                SecurityEvent.tenant_id == tenant_id,
                SecurityEvent.created_at >= since,
            )
            .scalar()
            or 0
        )

    def get_event_by_id(self, db: Session, tenant_id: str, event_id: str) -> SecurityEvent:
        event = db.query(SecurityEvent).filter(
            SecurityEvent.id == event_id,
            SecurityEvent.tenant_id == tenant_id,
        ).options(selectinload(SecurityEvent.detection_matches)).first()
        if not event:
            raise ValueError("Security event not found")
        return event

    def create_event(
        self,
        db: Session,
        tenant_id: str,
        event_data: SecurityEventCreate,
    ) -> SecurityEvent:
        # Use the provided normalized_event if available, otherwise normalize it
        normalized_event = event_data.normalized_event
        if not normalized_event:
            normalized_event = normalize_alert(event_data.raw_event)
        
        # Use provided timestamp or current time
        timestamp = ensure_utc(event_data.timestamp) if event_data.timestamp else get_utc_now()
        existing_event = self._find_existing_event(
            db=db,
            tenant_id=tenant_id,
            source=event_data.source,
            event_type=event_data.event_type,
            timestamp=timestamp,
            raw_event=event_data.raw_event,
        )
        if existing_event:
            return existing_event
        
        event = SecurityEvent(
            tenant_id=tenant_id,
            source=event_data.source,
            event_type=event_data.event_type,
            raw_event=event_data.raw_event,
            normalized_event=normalized_event,
            severity=event_data.severity,
            timestamp=timestamp,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        
        # Broadcast new event
        broadcast_notification_sync(tenant_id, NotificationType.NEW_EVENT, {
            "id": event.id,
            "source": event.source,
            "event_type": event.event_type.value if hasattr(event.event_type, 'value') else str(event.event_type),
            "severity": event.severity.value if hasattr(event.severity, 'value') else str(event.severity),
            "timestamp": utc_isoformat(event.timestamp) if event.timestamp else None,
            "created_at": utc_isoformat(event.created_at)
        })
        
        return event

    def _find_existing_event(
        self,
        db: Session,
        tenant_id: str,
        source: str,
        event_type: EventType,
        timestamp: datetime,
        raw_event: dict,
    ) -> SecurityEvent | None:
        candidates = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.tenant_id == tenant_id,
                SecurityEvent.source == source,
                SecurityEvent.event_type == event_type,
            )
            .order_by(SecurityEvent.created_at.desc())
            .limit(20)
            .all()
        )
        event_id = raw_event.get("event_id") or raw_event.get("EventID")
        record_number = raw_event.get("record_number") or raw_event.get("RecordNumber")
        image = raw_event.get("Image") or raw_event.get("process")
        command_line = raw_event.get("CommandLine") or raw_event.get("command_line") or raw_event.get("command")
        source_timestamp = raw_event.get("timestamp") or raw_event.get("TimeCreated")
        for candidate in candidates:
            candidate_raw = candidate.raw_event or {}
            candidate_source_timestamp = candidate_raw.get("timestamp") or candidate_raw.get("TimeCreated")
            if source_timestamp is not None and candidate_source_timestamp is not None:
                if str(source_timestamp) != str(candidate_source_timestamp):
                    continue
            elif ensure_utc(candidate.timestamp) != ensure_utc(timestamp):
                continue
            candidate_record_number = candidate_raw.get("record_number") or candidate_raw.get("RecordNumber")
            if record_number and candidate_record_number and str(record_number) == str(candidate_record_number):
                return candidate
            if (
                (candidate_raw.get("event_id") or candidate_raw.get("EventID")) == event_id
                and (candidate_raw.get("Image") or candidate_raw.get("process")) == image
                and (candidate_raw.get("CommandLine") or candidate_raw.get("command_line") or candidate_raw.get("command")) == command_line
            ):
                return candidate
        return None


security_event_service = SecurityEventService()
