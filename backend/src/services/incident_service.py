from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from sqlalchemy import asc, case, desc, func, or_
from sqlalchemy.orm import Session, joinedload

from src.core.logging import logger
from src.models.pydantic import (
    AIAnalysisResponse,
    AnalystActivity,
    FeedbackCreate,
    FeedbackResponse,
    FeedbackStats,
    IncidentEvidenceCreate,
    IncidentEvidenceResponse,
    IncidentPriorityUpdate,
    InvestigationNoteCreate,
    InvestigationNoteResponse,
    TimelineActor,
    TimelineItem,
)
from src.models.pydantic import Incident as IncidentSchema
from src.models.pydantic import IncidentDetail, IncidentListResponse, IncidentStats
from src.models.sqlalchemy import (
    Alert,
    AlertSource,
    AuditLog,
    IncidentEvidence,
    InvestigationNote,
    Incident,
    IncidentAlert,
    IncidentStatus,
    IncidentPriority,
    Severity,
    Feedback,
    Classification,
    User,
    UserRole,
)
from src.services.ai_service import ai_service
from src.services.correlation_service import CorrelationCandidate, correlation_service
from src.services.risk_service import risk_service
from src.services.threat_intel_service import threat_intel_service
from src.services.ioc_service import ioc_service
from src.services.ioc_extraction_service import ioc_extraction_service
from src.services.incident_intelligence_service import incident_intelligence_service
from src.services.websocket_service import broadcast_notification_sync, NotificationType
from src.core.observability import INCIDENTS_CREATED
from src.utils.datetime_utils import utc_isoformat


class IncidentService:
    _ALLOWED_STATUS_TRANSITIONS: dict[IncidentStatus, tuple[IncidentStatus, ...]] = {
        IncidentStatus.OPEN: (IncidentStatus.INVESTIGATING,),
        IncidentStatus.INVESTIGATING: (IncidentStatus.RESOLVED,),
        IncidentStatus.RESOLVED: (IncidentStatus.CLOSED,),
        IncidentStatus.CLOSED: (),
    }

    def process_alert(self, db: Session, alert: Alert) -> Incident:
        candidate = correlation_service.correlate_alert(db, alert)
        title, description = correlation_service.derive_incident_metadata(candidate.alerts)
        threat_intel_results = threat_intel_service.lookup_incident_indicators(db, candidate.alerts)
        risk = risk_service.calculate_risk(
            db,
            tenant_id=alert.tenant_id,
            alerts=candidate.alerts,
            correlation_reasons=candidate.correlation_reasons,
            incident_title=title,
            threat_intel_results=threat_intel_results,
        )

        if candidate.incident:
            incident = self._update_existing_incident(
                db=db,
                incident=candidate.incident,
                alerts=candidate.alerts,
                title=title,
                description=description,
                candidate=candidate,
                risk=risk,
                threat_intel_results=threat_intel_results,
                triggering_alert_id=alert.id,
            )
        else:
            incident = self._create_incident(
                db=db,
                tenant_id=alert.tenant_id,
                alerts=candidate.alerts,
                title=title,
                description=description,
                candidate=candidate,
                risk=risk,
                threat_intel_results=threat_intel_results,
                triggering_alert_id=alert.id,
            )

        return incident

    def list_incidents(
        self,
        db: Session,
        tenant_id: str,
        page: int,
        page_size: int,
        assigned_to: Optional[str] = None,
        priority: Optional[IncidentPriority] = None,
        status: Optional[IncidentStatus] = None,
        severity: Optional[Severity] = None,
        created_from: Optional[datetime] = None,
        created_to: Optional[datetime] = None,
        search: Optional[str] = None,
        sort_by: str = "updated_at",
        sort_order: str = "desc",
    ) -> IncidentListResponse:
        query = db.query(Incident).filter(Incident.tenant_id == tenant_id)
        if assigned_to:
            query = query.filter(Incident.assigned_to == assigned_to)
        if priority:
            query = query.filter(Incident.priority == priority)
        if status:
            query = query.filter(Incident.status == status)
        if severity:
            query = query.filter(Incident.severity == severity)
        if created_from:
            query = query.filter(Incident.created_at >= created_from)
        if created_to:
            query = query.filter(Incident.created_at <= created_to)
        if search:
            search_term = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    Incident.title.ilike(search_term),
                    Incident.description.ilike(search_term),
                )
            )

        total = query.count()
        sort_column = self._resolve_incident_sort_column(sort_by)
        order_clause = desc(sort_column) if sort_order.lower() != "asc" else asc(sort_column)
        incidents = (
            query.options(joinedload(Incident.incident_alerts), joinedload(Incident.assigned_analyst))
            .order_by(order_clause, Incident.updated_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )

        items = [
            self.serialize_incident(incident, alert_count=len(incident.incident_alerts))
            for incident in incidents
        ]

        return IncidentListResponse(items=items, total=total, page=page, page_size=page_size)

    def get_incident_detail(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
        *,
        alert_page: int = 1,
        alert_page_size: int = 20,
        include_alert_payloads: bool = False,
    ) -> IncidentDetail:
        incident = (
            db.query(Incident)
            .options(
                joinedload(Incident.assigned_analyst),
            )
            .filter(Incident.id == incident_id, Incident.tenant_id == tenant_id)
            .first()
        )
        if incident is None:
            raise ValueError("Incident not found")

        link_query = db.query(IncidentAlert).filter(IncidentAlert.incident_id == incident.id)
        related_alert_total = link_query.count()
        links = (
            link_query.options(joinedload(IncidentAlert.alert))
            .order_by(IncidentAlert.sequence_order.asc(), IncidentAlert.created_at.asc())
            .offset((alert_page - 1) * alert_page_size)
            .limit(alert_page_size)
            .all()
        )
        correlation_reasons = [
            value
            for (value,) in db.query(IncidentAlert.correlation_reason)
            .filter(IncidentAlert.incident_id == incident.id, IncidentAlert.correlation_reason.isnot(None))
            .distinct()
            .all()
            if value
        ]
        related_alerts = [
            self._serialize_incident_alert_link(link, include_alert_payloads)
            for link in links
            if link.alert is not None
        ]
        return IncidentDetail(
            id=incident.id,
            tenant_id=incident.tenant_id,
            title=incident.title,
            description=incident.description,
            severity=incident.severity,
            risk_score=float(incident.risk_score or 0),
            status=incident.status,
            priority=incident.priority,
            due_date=incident.due_date,
            escalation_level=incident.escalation_level,
            ai_summary=incident.ai_summary,
            why_suspicious=incident.why_suspicious,
            ai_analyzed_at=incident.ai_analyzed_at,
            attack_technique=self._normalize_attack_technique(incident.attack_technique),
            recommended_actions=incident.recommended_actions,
            threat_intel_results=incident.threat_intel_results,
            creation_source=incident.creation_source or "manual",
            provenance_status=incident.provenance_status or "legacy_derived",
            creation_reason=incident.creation_reason,
            primary_alert_id=incident.primary_alert_id,
            correlation_rule_id=incident.correlation_rule_id,
            correlation_rule_name=incident.correlation_rule_name,
            correlation_key=incident.correlation_key,
            correlation_score=incident.correlation_score,
            correlation_window_start=incident.correlation_window_start,
            correlation_window_end=incident.correlation_window_end,
            first_seen_at=incident.first_seen_at,
            last_seen_at=incident.last_seen_at,
            risk_score_breakdown=incident.risk_score_breakdown or {},
            severity_reason=incident.severity_reason,
            attack_summary=incident.attack_summary,
            status_reason=incident.status_reason,
            assigned_to=incident.assigned_to,
            assigned_at=incident.assigned_at,
            assigned_analyst=self._serialize_user(incident.assigned_analyst) if incident.assigned_analyst else None,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
            resolved_at=incident.resolved_at,
            related_alerts=related_alerts,
            correlation_reasons=correlation_reasons,
            related_alert_total=related_alert_total,
            related_alert_page=alert_page,
            related_alert_page_size=alert_page_size,
            related_alert_has_more=alert_page * alert_page_size < related_alert_total,
        )

    def _serialize_incident_alert_link(
        self,
        link: IncidentAlert,
        include_alert_payloads: bool,
    ) -> dict[str, Any]:
        alert = link.alert
        return {
            "id": link.id,
            "alert_id": link.alert_id,
            "correlation_score": float(link.correlation_score or 0),
            "correlation_reason": link.correlation_reason,
            "is_primary": bool(link.is_primary),
            "attachment_reason": link.attachment_reason,
            "sequence_order": int(link.sequence_order or 0),
            "risk_contribution": link.risk_contribution,
            "matching_entities": link.matching_entities or [],
            "matching_indicators": link.matching_indicators or [],
            "time_delta_seconds": link.time_delta_seconds,
            "created_at": link.created_at,
            "alert": {
                "id": alert.id,
                "tenant_id": alert.tenant_id,
                "source_id": alert.source_id,
                "detection_rule_id": alert.detection_rule_id,
                "incident_id": alert.incident_id,
                "event_id": alert.event_id,
                "raw_data": alert.raw_data if include_alert_payloads else None,
                "ocsf_data": alert.ocsf_data if include_alert_payloads else {},
                "risk_score": alert.risk_score,
                "matched_condition": alert.matched_condition,
                "why_matched": alert.why_matched,
                "severity": alert.severity,
                "status": alert.status,
                "created_at": alert.created_at,
                "processed_at": alert.processed_at,
            },
        }

    def update_status(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
        status: IncidentStatus,
    ) -> Incident:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id, Incident.tenant_id == tenant_id)
            .first()
        )
        if incident is None:
            raise ValueError("Incident not found")

        self._validate_status_transition(incident.status, status)
        now = self._utcnow()
        incident.status = status
        incident.updated_at = now
        if status == IncidentStatus.RESOLVED and incident.resolved_at is None:
            incident.resolved_at = now
        db.add(incident)
        db.commit()
        db.refresh(incident)
        return incident

    def get_incident_model(self, db: Session, tenant_id: str, incident_id: str) -> Incident:
        incident = (
            db.query(Incident)
            .options(
                joinedload(Incident.incident_alerts).joinedload(IncidentAlert.alert),
                joinedload(Incident.investigation_notes).joinedload(InvestigationNote.user),
                joinedload(Incident.feedback).joinedload(Feedback.user),
                joinedload(Incident.assigned_analyst),
            )
            .filter(Incident.id == incident_id, Incident.tenant_id == tenant_id)
            .first()
        )
        if incident is None:
            raise ValueError("Incident not found")
        return incident

    def assign_incident(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
        assignee_id: str,
    ) -> Incident:
        incident = self.get_incident_model(db, tenant_id, incident_id)
        assignee = (
            db.query(User)
            .filter(
                User.id == assignee_id,
                User.tenant_id == tenant_id,
                User.role.in_([UserRole.ADMIN, UserRole.ANALYST]),
                User.is_active.is_(True),
            )
            .first()
        )
        if assignee is None:
            raise ValueError("Assignee not found")

        incident.assigned_to = assignee.id
        incident.assigned_at = self._utcnow()
        incident.updated_at = incident.assigned_at
        db.add(incident)
        db.commit()
        db.refresh(incident)
        return (
            db.query(Incident)
            .options(joinedload(Incident.incident_alerts), joinedload(Incident.assigned_analyst))
            .filter(Incident.id == incident.id)
            .first()
        )

    def list_assigned_incidents(self, db: Session, tenant_id: str, user_id: str) -> list[IncidentSchema]:
        incidents = (
            db.query(Incident)
            .options(joinedload(Incident.incident_alerts), joinedload(Incident.assigned_analyst))
            .filter(Incident.tenant_id == tenant_id, Incident.assigned_to == user_id)
            .order_by(Incident.updated_at.desc())
            .all()
        )
        return [self.serialize_incident(incident) for incident in incidents]

    def create_note(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
        user: User,
        note_data: InvestigationNoteCreate,
    ) -> InvestigationNoteResponse:
        self.get_incident_model(db, tenant_id, incident_id)

        note = InvestigationNote(
            incident_id=incident_id,
            user_id=user.id,
            content=note_data.content.strip(),
        )
        db.add(note)
        db.commit()
        db.refresh(note)
        note = (
            db.query(InvestigationNote)
            .options(joinedload(InvestigationNote.user))
            .filter(InvestigationNote.id == note.id)
            .first()
        )
        return self._serialize_note(note)

    def get_notes_for_incident(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
    ) -> list[InvestigationNoteResponse]:
        self.get_incident_model(db, tenant_id, incident_id)
        notes = (
            db.query(InvestigationNote)
            .options(joinedload(InvestigationNote.user))
            .join(Incident, InvestigationNote.incident_id == Incident.id)
            .filter(Incident.tenant_id == tenant_id, InvestigationNote.incident_id == incident_id)
            .order_by(InvestigationNote.created_at.desc())
            .all()
        )
        return [self._serialize_note(note) for note in notes]

    def get_timeline(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
    ) -> list[TimelineItem]:
        incident = self.get_incident_model(db, tenant_id, incident_id)
        alert_ids = [item.alert_id for item in incident.incident_alerts]

        audit_logs = (
            db.query(AuditLog)
            .options(joinedload(AuditLog.user))
            .filter(
                AuditLog.tenant_id == tenant_id,
                or_(
                    (AuditLog.resource_type == "incident") & (AuditLog.resource_id == incident_id),
                    (AuditLog.resource_type == "alert") & (AuditLog.resource_id.in_(alert_ids)),
                ),
            )
            .order_by(AuditLog.created_at.desc())
            .all()
        )

        timeline: list[TimelineItem] = [
            TimelineItem(
                id=f"incident-created-{incident.id}",
                event_type="incident_created",
                title="Incident created",
                description=incident.title,
                created_at=incident.created_at,
                metadata={"incident_id": incident.id, "severity": incident.severity.value},
            )
        ]

        for item in incident.incident_alerts:
            timeline.append(
                TimelineItem(
                    id=f"alert-{item.alert.id}",
                    event_type="alert_created",
                    title=item.alert.ocsf_data.get("activity_name", "Alert event"),
                    description=item.correlation_reason,
                    created_at=item.alert.created_at,
                    metadata={
                        "alert_id": item.alert.id,
                        "severity": item.alert.severity.value,
                        "correlation_score": item.correlation_score,
                    },
                )
            )

        for feedback in incident.feedback:
            timeline.append(
                TimelineItem(
                    id=f"feedback-{feedback.id}",
                    event_type="feedback_submitted",
                    title="Analyst feedback submitted",
                    description=feedback.comment,
                    created_at=feedback.created_at,
                    actor=self._build_actor(feedback.user),
                    metadata={"classification": feedback.classification.value},
                )
            )

        for note in incident.investigation_notes:
            timeline.append(
                TimelineItem(
                    id=f"note-{note.id}",
                    event_type="note_added",
                    title="Investigation note added",
                    description=note.content,
                    created_at=note.created_at,
                    actor=self._build_actor(note.user),
                    metadata={"note_id": note.id},
                )
            )

        for audit_row in audit_logs:
            if audit_row.action == "incident_status_changed":
                timeline.append(
                    TimelineItem(
                        id=f"status-{audit_row.id}",
                        event_type="status_changed",
                        title="Status changed",
                        description=self._describe_status_change(audit_row.details or {}),
                        created_at=audit_row.created_at,
                        actor=self._build_actor(audit_row.user),
                        metadata=audit_row.details or {},
                    )
                )
            elif audit_row.action == "incident_assigned":
                timeline.append(
                    TimelineItem(
                        id=f"assignment-{audit_row.id}",
                        event_type="assignment",
                        title="Incident assigned",
                        description=self._describe_assignment(audit_row.details or {}),
                        created_at=audit_row.created_at,
                        actor=self._build_actor(audit_row.user),
                        metadata=audit_row.details or {},
                    )
                )

            timeline.append(
                TimelineItem(
                    id=f"audit-{audit_row.id}",
                    event_type="audit",
                    title=self._humanize_action(audit_row.action),
                    description=self._describe_audit_event(audit_row),
                    created_at=audit_row.created_at,
                    actor=self._build_actor(audit_row.user),
                    metadata={
                        "resource_type": audit_row.resource_type,
                        "resource_id": audit_row.resource_id,
                        **(audit_row.details or {}),
                    },
                )
            )

        return sorted(timeline, key=lambda item: item.created_at, reverse=True)

    def analyze_incident(self, db: Session, tenant_id: str, incident_id: str) -> AIAnalysisResponse:
        incident = self.get_incident_model(db, tenant_id, incident_id)
        return self._run_ai_analysis(db, tenant_id, incident)

    def _run_ai_analysis(self, db: Session, tenant_id: str, incident: Incident) -> AIAnalysisResponse:
        alerts = [item.alert for item in incident.incident_alerts]
        correlation_reasons = list(
            dict.fromkeys(
                item.correlation_reason for item in incident.incident_alerts if item.correlation_reason
            )
        )
        threat_intel_results = incident.threat_intel_results or []
        if not threat_intel_results:
            threat_intel_results = threat_intel_service.lookup_incident_indicators(db, alerts)
            incident.threat_intel_results = threat_intel_results

        analysis = ai_service.analyze_incident(
            incident=incident,
            alerts=alerts,
            correlation_reasons=correlation_reasons,
            threat_intel_results=threat_intel_results,
        )
        incident.ai_summary = analysis["summary"]
        incident.why_suspicious = analysis["why_suspicious"]
        incident.attack_technique = self._normalize_attack_technique(analysis["attack_technique"])
        incident.recommended_actions = analysis["recommended_actions"]
        incident.ai_analyzed_at = self._utcnow()
        db.add(incident)
        db.commit()
        db.refresh(incident)
        return AIAnalysisResponse(**analysis)

    def get_stats(self, db: Session, tenant_id: str) -> IncidentStats:
        total, critical, active_investigations, average_risk = (
            db.query(
                func.count(Incident.id),
                func.coalesce(func.sum(case((Incident.severity == Severity.CRITICAL, 1), else_=0)), 0),
                func.coalesce(func.sum(case((Incident.status == IncidentStatus.INVESTIGATING, 1), else_=0)), 0),
                func.coalesce(func.avg(Incident.risk_score), 0),
            )
            .filter(Incident.tenant_id == tenant_id)
            .one()
        )
        total = int(total or 0)
        critical = int(critical or 0)
        active_investigations = int(active_investigations or 0)
        average_risk = round(float(average_risk or 0), 2)

        resolved_rows = (
            db.query(Incident.created_at, Incident.resolved_at)
            .filter(
                Incident.tenant_id == tenant_id,
                Incident.created_at.is_not(None),
                Incident.resolved_at.is_not(None),
            )
            .all()
        )
        resolution_durations = [
            (resolved_at - created_at).total_seconds() / 3600
            for created_at, resolved_at in resolved_rows
        ]
        average_resolution_time = (
            round(sum(resolution_durations) / len(resolution_durations), 2)
            if resolution_durations else 0.0
        )

        open_incidents_by_severity = {
            severity.value if hasattr(severity, "value") else str(severity): count
            for severity, count in (
                db.query(Incident.severity, func.count(Incident.id))
                .filter(Incident.tenant_id == tenant_id, Incident.status == IncidentStatus.OPEN)
                .group_by(Incident.severity)
                .all()
            )
        }

        # Get top alert sources (simple implementation)
        alert_sources_data = db.query(AlertSource.id, AlertSource.name, func.count(Alert.id)) \
            .join(Alert, AlertSource.id == Alert.source_id) \
            .filter(AlertSource.tenant_id == tenant_id) \
            .group_by(AlertSource.id, AlertSource.name) \
            .order_by(func.count(Alert.id).desc()) \
            .limit(5) \
            .all()
        top_alert_sources = [{"id": id, "name": name, "count": count} for id, name, count in alert_sources_data]

        analysts = (
            db.query(User)
            .filter(
                User.tenant_id == tenant_id,
                User.role.in_([UserRole.ADMIN, UserRole.ANALYST]),
                User.is_active.is_(True),
            )
            .all()
        )
        note_counts = defaultdict(int)
        for user_id, count in (
            db.query(InvestigationNote.user_id, func.count(InvestigationNote.id))
            .join(Incident, InvestigationNote.incident_id == Incident.id)
            .filter(Incident.tenant_id == tenant_id)
            .group_by(InvestigationNote.user_id)
            .all()
        ):
            note_counts[user_id] = count

        feedback_counts = defaultdict(int)
        for user_id, count in (
            db.query(Feedback.user_id, func.count(Feedback.id))
            .filter(Feedback.tenant_id == tenant_id)
            .group_by(Feedback.user_id)
            .all()
        ):
            feedback_counts[user_id] = count

        assignment_rows = (
            db.query(
                Incident.assigned_to,
                func.count(Incident.id),
                func.coalesce(func.sum(case((Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]), 1), else_=0)), 0),
                func.coalesce(func.sum(case((Incident.status.in_([IncidentStatus.RESOLVED, IncidentStatus.CLOSED]), 1), else_=0)), 0),
            )
            .filter(Incident.tenant_id == tenant_id, Incident.assigned_to.is_not(None))
            .group_by(Incident.assigned_to)
            .all()
        )
        assigned_counts = defaultdict(int, {user_id: int(count or 0) for user_id, count, _active, _resolved in assignment_rows})
        active_assignment_counts = defaultdict(int, {user_id: int(active or 0) for user_id, _count, active, _resolved in assignment_rows})
        resolved_counts = defaultdict(int, {user_id: int(resolved or 0) for user_id, _count, _active, resolved in assignment_rows})

        analyst_activity = [
            AnalystActivity(
                user_id=analyst.id,
                analyst_name=analyst.full_name or analyst.email,
                assigned_count=assigned_counts[analyst.id],
                active_investigations=active_assignment_counts[analyst.id],
                note_count=note_counts[analyst.id],
                feedback_count=feedback_counts[analyst.id],
                resolved_count=resolved_counts[analyst.id],
            )
            for analyst in analysts
        ]
        analyst_activity.sort(
            key=lambda item: (
                item.active_investigations,
                item.note_count + item.feedback_count,
                item.assigned_count,
            ),
            reverse=True,
        )
        return IncidentStats(
            total_incidents=total,
            critical_incidents=critical,
            average_risk_score=average_risk,
            active_investigations=active_investigations,
            average_resolution_time_hours=average_resolution_time,
            mean_time_to_detect_hours=0.0,  # Safe default
            mean_time_to_respond_hours=0.0,  # Safe default
            open_incidents_by_severity=open_incidents_by_severity,
            top_alert_sources=top_alert_sources,
            analyst_activity=analyst_activity[:5],
        )

    def serialize_incident(self, incident: Incident, alert_count: int | None = None) -> IncidentSchema:
        return IncidentSchema(
            id=incident.id,
            tenant_id=incident.tenant_id,
            title=incident.title,
            description=incident.description,
            severity=incident.severity,
            risk_score=float(incident.risk_score or 0),
            status=incident.status,
            priority=incident.priority,
            due_date=incident.due_date,
            escalation_level=incident.escalation_level,
            ai_summary=incident.ai_summary,
            why_suspicious=incident.why_suspicious,
            ai_analyzed_at=incident.ai_analyzed_at,
            attack_technique=self._normalize_attack_technique(incident.attack_technique),
            recommended_actions=incident.recommended_actions,
            threat_intel_results=incident.threat_intel_results,
            creation_source=incident.creation_source or "manual",
            provenance_status=incident.provenance_status or "legacy_derived",
            creation_reason=incident.creation_reason,
            primary_alert_id=incident.primary_alert_id,
            correlation_rule_id=incident.correlation_rule_id,
            correlation_rule_name=incident.correlation_rule_name,
            correlation_key=incident.correlation_key,
            correlation_score=incident.correlation_score,
            correlation_window_start=incident.correlation_window_start,
            correlation_window_end=incident.correlation_window_end,
            first_seen_at=incident.first_seen_at,
            last_seen_at=incident.last_seen_at,
            risk_score_breakdown=incident.risk_score_breakdown or {},
            severity_reason=incident.severity_reason,
            attack_summary=incident.attack_summary,
            status_reason=incident.status_reason,
            assigned_to=incident.assigned_to,
            assigned_at=incident.assigned_at,
            assigned_analyst=self._serialize_user(incident.assigned_analyst) if incident.assigned_analyst else None,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
            resolved_at=incident.resolved_at,
            alert_count=alert_count if alert_count is not None else len(incident.incident_alerts),
        )

    def _create_incident(
        self,
        db: Session,
        tenant_id: str,
        alerts: Sequence[Alert],
        title: str,
        description: str,
        candidate: CorrelationCandidate,
        risk: dict,
        threat_intel_results: list[dict],
        triggering_alert_id: str,
    ) -> Incident:
        incident = Incident(
            tenant_id=tenant_id,
            title=title,
            description=description,
            severity=risk["severity"],
            risk_score=risk["risk_score"],
            status=IncidentStatus.OPEN,
            attack_technique=self._derive_attack_technique(alerts),
            recommended_actions=self._derive_recommended_actions(alerts),
            threat_intel_results=threat_intel_results,
            creation_source="detection_engine",
            provenance_status="recorded",
        )
        db.add(incident)
        db.flush()
        self._sync_incident_links(db, incident, alerts, candidate)
        db.flush()
        incident_intelligence_service.capture_provenance(
            db,
            incident,
            alerts,
            correlation_score=candidate.correlation_score,
            correlation_reasons=candidate.correlation_reasons,
            risk=risk,
            created=True,
            triggering_alert_id=triggering_alert_id,
        )
        threat_intel_service.persist_incident_results(db, tenant_id, incident.id, threat_intel_results)
        self._extract_and_associate_iocs(db, tenant_id, incident.id, alerts)
        db.commit()
        db.refresh(incident)
        INCIDENTS_CREATED.labels("correlation_engine").inc()

        # Broadcast new incident
        broadcast_notification_sync(tenant_id, NotificationType.NEW_INCIDENT, {
            "id": incident.id,
            "title": incident.title,
            "severity": incident.severity.value if hasattr(incident.severity, 'value') else str(incident.severity),
            "priority": incident.priority.value if hasattr(incident.priority, 'value') else str(incident.priority),
            "status": incident.status.value if hasattr(incident.status, 'value') else str(incident.status),
            "risk_score": float(incident.risk_score or 0),
            "created_at": utc_isoformat(incident.created_at)
        })

        # Auto-run configured AI analysis on new incidents
        try:
            self._run_ai_analysis(db, tenant_id, incident)
        except Exception:
            logger.exception("AI analysis failed after incident creation", extra={"incident_id": incident.id})
        
        return incident

    def _update_existing_incident(
        self,
        db: Session,
        incident: Incident,
        alerts: Sequence[Alert],
        title: str,
        description: str,
        candidate: CorrelationCandidate,
        risk: dict,
        threat_intel_results: list[dict],
        triggering_alert_id: str,
    ) -> Incident:
        incident.title = title
        incident.description = description
        incident.severity = risk["severity"]
        incident.risk_score = risk["risk_score"]
        incident.attack_technique = self._derive_attack_technique(alerts)
        incident.recommended_actions = self._derive_recommended_actions(alerts)
        incident.threat_intel_results = threat_intel_results
        db.add(incident)
        self._sync_incident_links(db, incident, alerts, candidate)
        db.flush()
        incident_intelligence_service.capture_provenance(
            db,
            incident,
            alerts,
            correlation_score=candidate.correlation_score,
            correlation_reasons=candidate.correlation_reasons,
            risk=risk,
            created=False,
            triggering_alert_id=triggering_alert_id,
        )
        threat_intel_service.persist_incident_results(db, incident.tenant_id, incident.id, threat_intel_results)
        self._extract_and_associate_iocs(db, incident.tenant_id, incident.id, alerts)
        db.commit()
        db.refresh(incident)
        return incident

    def _extract_and_associate_iocs(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
        alerts: Sequence[Alert],
    ):
        # Extract IOCs from all alerts
        extracted = []
        for alert in alerts:
            if alert.ocsf_data:
                extracted.extend(ioc_extraction_service.extract_from_dict(alert.ocsf_data))
            if alert.raw_data:
                extracted.extend(ioc_extraction_service.extract_from_dict(alert.raw_data))
        # Deduplicate
        unique_iocs = list(dict.fromkeys(extracted))
        # For each unique (type, value):
        for ioc_type, value in unique_iocs:
            ioc = ioc_service.get_ioc_by_value_and_type(db, tenant_id, value, ioc_type)
            if not ioc:
                # Create new IOC
                from src.models.pydantic import IOCCreate, Severity
                create_data = IOCCreate(
                    type=ioc_type,
                    value=value,
                    source="auto-extracted",
                    severity=Severity.MEDIUM,
                    is_active=True
                )
                ioc = ioc_service.create_ioc(db, tenant_id, None, create_data)
            # Associate with incident
            ioc_service.associate_ioc_with_incident(db, tenant_id, incident_id, ioc.id)

    def _sync_incident_links(
        self,
        db: Session,
        incident: Incident,
        alerts: Sequence[Alert],
        candidate: CorrelationCandidate,
    ) -> None:
        existing_links = {
            item.alert_id: item
            for item in db.query(IncidentAlert).filter(IncidentAlert.incident_id == incident.id).all()
        }
        link_reason = "; ".join(candidate.correlation_reasons)

        for alert in alerts:
            alert.incident_id = incident.id
            alert.risk_score = incident.risk_score
            db.add(alert)

            if alert.id not in existing_links:
                db.add(
                    IncidentAlert(
                        incident_id=incident.id,
                        alert_id=alert.id,
                        correlation_score=float(candidate.correlation_score or 0),
                        correlation_reason=link_reason,
                    )
                )

    def _derive_attack_technique(self, alerts: Sequence[Alert]) -> dict[str, Any] | None:
        for alert in alerts:
            ocsf = alert.ocsf_data or {}
            techniques = ocsf.get("attack_techniques") or []
            if isinstance(techniques, list) and techniques:
                technique_id = str(techniques[0])
                return {
                    "technique_id": technique_id,
                    "technique_name": self._mitre_name(technique_id),
                    "confidence": ocsf.get("confidence"),
                    "reasoning": alert.why_matched or ocsf.get("why_matched"),
                }
            if alert.detection_rule and alert.detection_rule.mitre_technique_id:
                technique_id = alert.detection_rule.mitre_technique_id
                return {
                    "technique_id": technique_id,
                    "technique_name": self._mitre_name(technique_id),
                    "confidence": (alert.ocsf_data or {}).get("confidence"),
                    "reasoning": alert.why_matched,
                }
        return None

    def _normalize_attack_technique(self, value: Any) -> dict[str, Any] | None:
        if value is None:
            return None
        if isinstance(value, dict):
            if "technique_id" in value or "technique_name" in value:
                return value
            if len(value) == 1:
                technique_id, technique_value = next(iter(value.items()))
                if isinstance(technique_value, dict):
                    return {"technique_id": str(technique_id), **technique_value}
                return {"technique_id": str(technique_id), "technique_name": str(technique_value)}
            return value
        if isinstance(value, list):
            first = next((item for item in value if item), None)
            if isinstance(first, dict):
                return first
            if first:
                return {"technique_id": str(first), "technique_name": self._mitre_name(str(first))}
        if isinstance(value, str):
            return {"technique_id": value, "technique_name": self._mitre_name(value)}
        return None

    def _derive_recommended_actions(self, alerts: Sequence[Alert]) -> list[str]:
        actions: list[str] = []
        for alert in alerts:
            recommendations = (alert.ocsf_data or {}).get("recommendations") or []
            if isinstance(recommendations, list):
                actions.extend(str(item) for item in recommendations if item)
        if not actions:
            actions = [
                "Review correlated alerts and raw event evidence.",
                "Validate affected users, hosts, and IOCs.",
                "Document analyst disposition and containment decision.",
            ]
        return list(dict.fromkeys(actions))[:8]

    def _mitre_name(self, technique_id: str) -> str:
        names = {
            "T1003.001": "LSASS Memory",
            "T1047": "Windows Management Instrumentation",
            "T1053.005": "Scheduled Task",
            "T1059.001": "PowerShell",
            "T1059.003": "Windows Command Shell",
            "T1071": "Application Layer Protocol",
            "T1105": "Ingress Tool Transfer",
            "T1110": "Brute Force",
            "T1136": "Create Account",
            "T1218.010": "Regsvr32",
            "T1218.011": "Rundll32",
            "T1543.003": "Windows Service",
            "T1564.003": "Hidden Window",
        }
        return names.get(technique_id, "Mapped MITRE ATT&CK Technique")


    def create_feedback(
        self, 
        db: Session, 
        tenant_id: str, 
        incident_id: str, 
        user_id: str, 
        feedback_data: FeedbackCreate
    ) -> FeedbackResponse:
        incident = self.get_incident_model(db, tenant_id, incident_id)
        
        # Create feedback
        feedback = Feedback(
            tenant_id=tenant_id,
            incident_id=incident_id,
            user_id=user_id,
            classification=feedback_data.classification,
            comment=feedback_data.comment,
        )
        
        # Update incident classification
        incident.classification = feedback_data.classification
        
        db.add(feedback)
        db.add(incident)
        db.commit()
        db.refresh(feedback)
        
        # Load the user relationship
        feedback = db.query(Feedback).options(joinedload(Feedback.user)).filter(Feedback.id == feedback.id).first()
        
        return FeedbackResponse(
            id=feedback.id,
            tenant_id=feedback.tenant_id,
            incident_id=feedback.incident_id,
            user_id=feedback.user_id,
            classification=feedback.classification,
            comment=feedback.comment,
            created_at=feedback.created_at,
            user=self._serialize_user(feedback.user) if feedback.user else None,
        )

    def get_feedback_for_incident(
        self, 
        db: Session, 
        tenant_id: str, 
        incident_id: str
    ) -> list[FeedbackResponse]:
        self.get_incident_model(db, tenant_id, incident_id)
        feedbacks = (
            db.query(Feedback)
            .options(joinedload(Feedback.user))
            .filter(Feedback.tenant_id == tenant_id, Feedback.incident_id == incident_id)
            .order_by(Feedback.created_at.desc())
            .all()
        )
        
        return [
            FeedbackResponse(
                id=f.id,
                tenant_id=f.tenant_id,
                incident_id=f.incident_id,
                user_id=f.user_id,
                classification=f.classification,
                comment=f.comment,
                created_at=f.created_at,
                user=self._serialize_user(f.user) if f.user else None,
            )
            for f in feedbacks
        ]

    def get_feedback_stats(self, db: Session, tenant_id: str) -> FeedbackStats:
        total_reviewed = db.query(func.count(Feedback.id)).filter(Feedback.tenant_id == tenant_id).scalar() or 0
        true_positives = db.query(func.count(Feedback.id)).filter(
            Feedback.tenant_id == tenant_id, 
            Feedback.classification == Classification.TRUE_POSITIVE
        ).scalar() or 0
        false_positives = db.query(func.count(Feedback.id)).filter(
            Feedback.tenant_id == tenant_id, 
            Feedback.classification == Classification.FALSE_POSITIVE
        ).scalar() or 0
        benign = db.query(func.count(Feedback.id)).filter(
            Feedback.tenant_id == tenant_id, 
            Feedback.classification == Classification.BENIGN
        ).scalar() or 0
        
        accuracy = 0.0
        if total_reviewed > 0:
            accuracy = ((true_positives + benign) / total_reviewed) * 100
        
        return FeedbackStats(
            total_reviewed=total_reviewed,
            true_positives=true_positives,
            false_positives=false_positives,
            benign=benign,
            accuracy_percentage=round(accuracy, 2),
        )

    def _validate_status_transition(
        self,
        current_status: IncidentStatus,
        new_status: IncidentStatus,
    ) -> None:
        if new_status == current_status:
            return
        if new_status not in self._ALLOWED_STATUS_TRANSITIONS[current_status]:
            raise ValueError(
                f"Invalid status transition from {current_status.value} to {new_status.value}"
            )

    def _serialize_note(self, note: InvestigationNote) -> InvestigationNoteResponse:
        return InvestigationNoteResponse(
            id=note.id,
            incident_id=note.incident_id,
            user_id=note.user_id,
            content=note.content,
            created_at=note.created_at,
            updated_at=note.updated_at,
            user=self._serialize_user(note.user) if note.user else None,
        )

    def _build_actor(self, user: Optional[User]) -> Optional[TimelineActor]:
        if user is None:
            return None
        return TimelineActor(user_id=user.id, name=user.full_name, email=user.email)

    def _describe_status_change(self, details: dict[str, Any]) -> str:
        previous_status = details.get("previous_status")
        new_status = details.get("new_status")
        if previous_status and new_status:
            return f"{previous_status} -> {new_status}"
        return "Incident status updated"

    def _describe_assignment(self, details: dict[str, Any]) -> str:
        assignee_name = details.get("assignee_name") or details.get("assignee_email") or "analyst"
        return f"Assigned to {assignee_name}"

    def _humanize_action(self, action: str) -> str:
        return action.replace("_", " ").title()

    def _describe_audit_event(self, audit_row: AuditLog) -> str | None:
        if audit_row.action == "incident_status_changed":
            return self._describe_status_change(audit_row.details or {})
        if audit_row.action == "incident_assigned":
            return self._describe_assignment(audit_row.details or {})
        if audit_row.action == "investigation_note_added":
            return (audit_row.details or {}).get("preview") or "Investigation note recorded"
        if audit_row.action == "analyst_feedback_submitted":
            classification = (audit_row.details or {}).get("classification")
            if classification:
                return f"Classification: {classification}"
        return None

    def _utcnow(self) -> datetime:
        return datetime.now(timezone.utc)

    def update_priority(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
        priority_data: IncidentPriorityUpdate,
    ) -> Incident:
        incident = self.get_incident_model(db, tenant_id, incident_id)
        incident.priority = priority_data.priority
        incident.due_date = priority_data.due_date
        incident.escalation_level = priority_data.escalation_level
        incident.updated_at = self._utcnow()
        db.add(incident)
        db.commit()
        db.refresh(incident)
        return incident

    def create_evidence(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
        user: User,
        evidence_data: IncidentEvidenceCreate,
    ) -> IncidentEvidenceResponse:
        self.get_incident_model(db, tenant_id, incident_id)
        evidence = IncidentEvidence(
            tenant_id=tenant_id,
            incident_id=incident_id,
            user_id=user.id,
            type=evidence_data.type,
            value=evidence_data.value,
            description=evidence_data.description,
        )
        db.add(evidence)
        db.commit()
        db.refresh(evidence)
        evidence = (
            db.query(IncidentEvidence)
            .options(joinedload(IncidentEvidence.user))
            .filter(IncidentEvidence.id == evidence.id)
            .first()
        )
        return self._serialize_evidence(evidence)

    def list_evidence(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
    ) -> list[IncidentEvidenceResponse]:
        self.get_incident_model(db, tenant_id, incident_id)
        evidence_list = (
            db.query(IncidentEvidence)
            .options(joinedload(IncidentEvidence.user))
            .join(Incident, IncidentEvidence.incident_id == Incident.id)
            .filter(Incident.tenant_id == tenant_id, IncidentEvidence.incident_id == incident_id)
            .order_by(IncidentEvidence.created_at.desc())
            .all()
        )
        return [self._serialize_evidence(e) for e in evidence_list]

    def delete_evidence(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
        evidence_id: str,
    ) -> None:
        self.get_incident_model(db, tenant_id, incident_id)
        evidence = (
            db.query(IncidentEvidence)
            .filter(
                IncidentEvidence.id == evidence_id,
                IncidentEvidence.incident_id == incident_id,
            )
            .first()
        )
        if not evidence:
            raise ValueError("Evidence not found")
        db.delete(evidence)
        db.commit()

    def _serialize_evidence(self, evidence: IncidentEvidence) -> IncidentEvidenceResponse:
        return IncidentEvidenceResponse(
            id=evidence.id,
            incident_id=evidence.incident_id,
            tenant_id=evidence.tenant_id,
            user_id=evidence.user_id,
            source_event_id=evidence.source_event_id,
            source_alert_id=evidence.source_alert_id,
            source_entity_id=evidence.source_entity_id,
            type=evidence.type,
            value=evidence.value,
            description=evidence.description,
            confidence=evidence.confidence,
            risk_contribution=evidence.risk_contribution,
            evidence_metadata=evidence.evidence_metadata or {},
            created_at=evidence.created_at,
            user=self._serialize_user(evidence.user) if evidence.user else None,
        )

    def _resolve_incident_sort_column(self, sort_by: str):
        sort_map = {
            "created_at": Incident.created_at,
            "updated_at": Incident.updated_at,
            "risk_score": Incident.risk_score,
            "severity": Incident.severity,
            "priority": Incident.priority,
        }
        return sort_map.get(sort_by, Incident.updated_at)

    def _serialize_user(self, user: User) -> dict:
        return {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "tenant_id": user.tenant_id,
            "role": user.role,
            "is_active": user.is_active,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
        }


incident_service = IncidentService()
