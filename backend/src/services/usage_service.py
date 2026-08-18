from __future__ import annotations

from datetime import date, datetime, time, timezone

from sqlalchemy import Text, cast, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.models.sqlalchemy import (
    Alert,
    Collector,
    ConnectorActionExecution,
    Incident,
    OrganizationMembership,
    OrganizationUsage,
    Playbook,
    PlaybookExecution,
    SecurityEvent,
)
from src.utils.datetime_utils import get_utc_now


class UsageService:
    """Tenant-scoped application usage.

    Storage is an estimate of persisted application payload bytes in event,
    alert, and incident records. It is not filesystem or database-volume size.
    """

    def _payload_bytes(self, db: Session, tenant_id: str) -> int:
        event_bytes = db.query(
            func.coalesce(
                func.sum(
                    func.length(cast(SecurityEvent.raw_event, Text))
                    + func.length(cast(SecurityEvent.normalized_event, Text))
                ),
                0,
            )
        ).filter(SecurityEvent.tenant_id == tenant_id).scalar()
        alert_bytes = db.query(
            func.coalesce(
                func.sum(
                    func.length(cast(Alert.ocsf_data, Text))
                    + func.coalesce(func.length(cast(Alert.raw_data, Text)), 0)
                ),
                0,
            )
        ).filter(Alert.tenant_id == tenant_id).scalar()
        incident_bytes = db.query(
            func.coalesce(
                func.sum(
                    func.length(func.coalesce(Incident.title, ""))
                    + func.length(func.coalesce(Incident.description, ""))
                ),
                0,
            )
        ).filter(Incident.tenant_id == tenant_id).scalar()
        return int(event_bytes or 0) + int(alert_bytes or 0) + int(incident_bytes or 0)

    def calculate_current(self, db: Session, tenant_id: str) -> dict:
        today = get_utc_now().date()
        month_start = today.replace(day=1)
        daily = (
            db.query(
                func.coalesce(func.sum(OrganizationUsage.api_request_count), 0),
                func.coalesce(func.sum(OrganizationUsage.triage_ai_request_count), 0),
            )
            .filter(
                OrganizationUsage.tenant_id == tenant_id,
                OrganizationUsage.snapshot_date >= month_start,
                OrganizationUsage.snapshot_date <= today,
            )
            .one()
        )
        return {
            "organization_id": tenant_id,
            "user_count": db.query(OrganizationMembership).filter_by(tenant_id=tenant_id, is_active=True).count(),
            "collector_count": db.query(Collector).filter_by(tenant_id=tenant_id).count(),
            "event_count": db.query(SecurityEvent).filter_by(tenant_id=tenant_id).count(),
            "alert_count": db.query(Alert).filter_by(tenant_id=tenant_id).count(),
            "incident_count": db.query(Incident).filter_by(tenant_id=tenant_id).count(),
            "playbook_count": db.query(Playbook).filter_by(tenant_id=tenant_id).count(),
            "playbook_execution_count": db.query(PlaybookExecution).filter_by(tenant_id=tenant_id).count(),
            "soar_execution_count": db.query(ConnectorActionExecution).filter_by(tenant_id=tenant_id).count(),
            "triage_ai_request_count": int(daily[1] or 0),
            "storage_bytes": self._payload_bytes(db, tenant_id),
            "api_request_count": int(daily[0] or 0),
            "period_start": datetime.combine(month_start, time.min, tzinfo=timezone.utc),
            "period_end": get_utc_now(),
            "storage_measurement": "estimated_application_payload_bytes",
        }

    def snapshot_current(self, db: Session, tenant_id: str, values: dict | None = None) -> OrganizationUsage:
        values = values or self.calculate_current(db, tenant_id)
        snapshot_date = get_utc_now().date()
        row = (
            db.query(OrganizationUsage)
            .filter_by(tenant_id=tenant_id, snapshot_date=snapshot_date)
            .with_for_update()
            .first()
        )
        if row is None:
            row = OrganizationUsage(tenant_id=tenant_id, snapshot_date=snapshot_date)
            db.add(row)
        for field in (
            "user_count",
            "collector_count",
            "event_count",
            "alert_count",
            "incident_count",
            "playbook_count",
            "playbook_execution_count",
            "soar_execution_count",
            "storage_bytes",
        ):
            setattr(row, field, values[field])
        row.period_start = datetime.combine(snapshot_date, time.min, tzinfo=timezone.utc)
        row.period_end = get_utc_now()
        row.calculated_at = get_utc_now()
        db.flush()
        return row

    def history(self, db: Session, tenant_id: str, start_date: date, end_date: date) -> list[OrganizationUsage]:
        return (
            db.query(OrganizationUsage)
            .filter(
                OrganizationUsage.tenant_id == tenant_id,
                OrganizationUsage.snapshot_date >= start_date,
                OrganizationUsage.snapshot_date <= end_date,
            )
            .order_by(OrganizationUsage.snapshot_date.asc())
            .all()
        )

    def increment_request(
        self,
        db: Session,
        tenant_id: str,
        *,
        triage_ai: bool = False,
    ) -> None:
        today = get_utc_now().date()
        updates = {"api_request_count": OrganizationUsage.api_request_count + 1}
        if triage_ai:
            updates["triage_ai_request_count"] = OrganizationUsage.triage_ai_request_count + 1
        changed = (
            db.query(OrganizationUsage)
            .filter_by(tenant_id=tenant_id, snapshot_date=today)
            .update(updates, synchronize_session=False)
        )
        if not changed:
            row = OrganizationUsage(
                tenant_id=tenant_id,
                snapshot_date=today,
                api_request_count=1,
                triage_ai_request_count=1 if triage_ai else 0,
                period_start=datetime.combine(today, time.min, tzinfo=timezone.utc),
                period_end=get_utc_now(),
            )
            db.add(row)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            updates = {"api_request_count": OrganizationUsage.api_request_count + 1}
            if triage_ai:
                updates["triage_ai_request_count"] = OrganizationUsage.triage_ai_request_count + 1
            db.query(OrganizationUsage).filter_by(tenant_id=tenant_id, snapshot_date=today).update(
                updates, synchronize_session=False
            )
            db.commit()


usage_service = UsageService()
