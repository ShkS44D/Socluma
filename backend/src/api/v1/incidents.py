from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from src.api.deps import get_current_user, get_db, require_roles
from src.models.pydantic import (
    AIAnalysisResponse,
    Incident as IncidentResponse,
    IncidentAssignmentRequest,
    IncidentDetail,
    IncidentEvidenceCreate,
    IncidentEvidenceResponse,
    IncidentExplanationResponse,
    IncidentListResponse,
    IncidentPriorityUpdate,
    IncidentStats,
    IncidentStatusUpdate,
    FeedbackCreate,
    FeedbackResponse,
    FeedbackStats,
    InvestigationNoteCreate,
    InvestigationNoteResponse,
    TimelineItem,
    IncidentCommentCreate,
    IncidentComment,
    ResponseAction,
    ResponseActionCreate,
    IOC,
)
from src.models.sqlalchemy import IncidentPriority, IncidentStatus, Severity, User, UserRole
from src.services.incident_service import incident_service
from src.services.incident_comment_service import incident_comment_service
from src.services.response_action_service import response_action_service
from src.services.audit_service import audit_service
from src.services.ioc_service import ioc_service
from src.services.incident_intelligence_service import incident_intelligence_service
from src.core.validation import validate_uuid
from src.core.observability import (
    INCIDENT_CORRELATION_CONFIDENCE,
    INCIDENT_EXPLANATIONS,
    INCIDENT_SOURCE_ALERTS,
    INCIDENT_SOURCE_EVENTS,
)


router = APIRouter(prefix="/incidents", tags=["Incidents"])


def _client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


def _handle_incident_error(exc: ValueError) -> None:
    detail = str(exc)
    if detail == "Incident not found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail) from exc
    if detail == "Assignee not found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail) from exc
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc


@router.get("", response_model=IncidentListResponse)
def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[IncidentStatus] = None,
    severity: Optional[Severity] = None,
    priority: Optional[IncidentPriority] = None,
    assigned_to: Optional[str] = None,
    search: Optional[str] = None,
    created_from: Optional[datetime] = None,
    created_to: Optional[datetime] = None,
    sort_by: str = Query("updated_at", pattern="^(created_at|updated_at|risk_score|severity|priority)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return incident_service.list_incidents(
        db=db,
        tenant_id=current_user.tenant_id,
        page=page,
        page_size=page_size,
        status=status,
        severity=severity,
        priority=priority,
        assigned_to=assigned_to,
        search=search,
        created_from=created_from,
        created_to=created_to,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@router.get("/stats", response_model=IncidentStats)
def get_incident_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return incident_service.get_stats(db, current_user.tenant_id)


@router.get("/feedback/stats", response_model=FeedbackStats)
def get_feedback_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return incident_service.get_feedback_stats(db, current_user.tenant_id)


@router.get("/assigned", response_model=list[IncidentResponse])
def get_assigned_incidents(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.RESPONDER)),
):
    return incident_service.list_assigned_incidents(db, current_user.tenant_id, current_user.id)


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(
    incident_id: str,
    alert_page: int = Query(1, ge=1),
    alert_page_size: int = Query(20, ge=1, le=100),
    include_alert_payloads: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    validate_uuid(incident_id, "incident_id")
    try:
        return incident_service.get_incident_detail(
            db,
            current_user.tenant_id,
            incident_id,
            alert_page=alert_page,
            alert_page_size=alert_page_size,
            include_alert_payloads=include_alert_payloads,
        )
    except ValueError as exc:
        _handle_incident_error(exc)


@router.get(
    "/{incident_id}/explanation",
    response_model=IncidentExplanationResponse,
    summary="Explain how an incident was created",
    description=(
        "Returns tenant-scoped, deterministic provenance from source events through detection rules, "
        "alerts, correlation, entities, evidence, MITRE ATT&CK mappings, and risk factors."
    ),
)
def get_incident_explanation(
    incident_id: str,
    alert_page: int = Query(1, ge=1),
    alert_limit: int = Query(20, ge=1, le=100),
    event_limit: int = Query(30, ge=1, le=100),
    entity_limit: int = Query(50, ge=1, le=250),
    ioc_limit: int = Query(20, ge=1, le=100),
    evidence_limit: int = Query(20, ge=1, le=100),
    timeline_limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    validate_uuid(incident_id, "incident_id")
    try:
        result = incident_intelligence_service.build_explanation(
            db,
            current_user.tenant_id,
            incident_id,
            alert_page=alert_page,
            alert_limit=alert_limit,
            event_limit=event_limit,
            entity_limit=entity_limit,
            ioc_limit=ioc_limit,
            evidence_limit=evidence_limit,
            timeline_limit=timeline_limit,
        )
        INCIDENT_EXPLANATIONS.labels("success").inc()
        INCIDENT_CORRELATION_CONFIDENCE.observe(float(result["correlation"].get("score") or 0))
        INCIDENT_SOURCE_ALERTS.observe(result["evidence_summary"]["source_alert_count"])
        INCIDENT_SOURCE_EVENTS.observe(result["evidence_summary"]["source_event_count"])
        return result
    except ValueError as exc:
        INCIDENT_EXPLANATIONS.labels("not_found").inc()
        _handle_incident_error(exc)


@router.post("/{incident_id}/assign", response_model=IncidentResponse)
def assign_incident(
    incident_id: str,
    assignment: IncidentAssignmentRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
):
    validate_uuid(incident_id, "incident_id")
    validate_uuid(assignment.user_id, "assignment.user_id")
    try:
        incident = incident_service.assign_incident(
            db=db,
            tenant_id=current_user.tenant_id,
            incident_id=incident_id,
            assignee_id=assignment.user_id,
        )
        audit_service.record(
            db,
            action="incident_assigned",
            user=current_user,
            resource_type="incident",
            resource_id=incident.id,
            ip_address=_client_ip(request),
            details={
                "assigned_to": incident.assigned_to,
                "assigned_at": incident.assigned_at.isoformat() if incident.assigned_at else None,
                "assignee_name": incident.assigned_analyst.full_name if incident.assigned_analyst else None,
                "assignee_email": incident.assigned_analyst.email if incident.assigned_analyst else None,
            },
        )
        return incident_service.serialize_incident(incident)
    except ValueError as exc:
        _handle_incident_error(exc)


@router.post("/{incident_id}/status", response_model=IncidentResponse)
def update_incident_status(
    incident_id: str,
    status_update: IncidentStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.RESPONDER)),
):
    try:
        existing = incident_service.get_incident_model(db, current_user.tenant_id, incident_id)
        previous_status = existing.status.value if hasattr(existing.status, "value") else str(existing.status)
        incident = incident_service.update_status(
            db=db,
            tenant_id=current_user.tenant_id,
            incident_id=incident_id,
            status=status_update.status,
        )
        audit_service.record(
            db,
            action="incident_status_changed",
            user=current_user,
            resource_type="incident",
            resource_id=incident.id,
            ip_address=_client_ip(request),
            details={
                "previous_status": previous_status,
                "new_status": incident.status.value if hasattr(incident.status, "value") else str(incident.status),
            },
        )
        return incident_service.serialize_incident(incident)
    except ValueError as exc:
        _handle_incident_error(exc)


@router.post(
    "/{incident_id}/analyze",
    response_model=AIAnalysisResponse,
    summary="Generate AI incident analysis",
    description=(
        "Run OpenAI-powered analysis on an incident. Returns summary, why suspicious, "
        "MITRE ATT&CK mapping, recommended actions, and threat intel results. "
        "Results are persisted to the incident record."
    ),
)
def analyze_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    try:
        return incident_service.analyze_incident(db, current_user.tenant_id, incident_id)
    except ValueError as exc:
        _handle_incident_error(exc)


@router.post("/{incident_id}/notes", response_model=InvestigationNoteResponse)
def create_investigation_note(
    incident_id: str,
    note_data: InvestigationNoteCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.RESPONDER)),
):
    try:
        note = incident_service.create_note(
            db=db,
            tenant_id=current_user.tenant_id,
            incident_id=incident_id,
            user=current_user,
            note_data=note_data,
        )
        audit_service.record(
            db,
            action="investigation_note_added",
            user=current_user,
            resource_type="incident",
            resource_id=incident_id,
            ip_address=_client_ip(request),
            details={
                "note_id": note.id,
                "preview": note.content[:120],
            },
        )
        return note
    except ValueError as exc:
        _handle_incident_error(exc)


@router.get("/{incident_id}/notes", response_model=list[InvestigationNoteResponse])
def get_investigation_notes(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        return incident_service.get_notes_for_incident(db, current_user.tenant_id, incident_id)
    except ValueError as exc:
        _handle_incident_error(exc)


@router.post("/{incident_id}/feedback", response_model=FeedbackResponse)
def create_feedback(
    incident_id: str,
    feedback_data: FeedbackCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    try:
        feedback = incident_service.create_feedback(
            db,
            current_user.tenant_id,
            incident_id,
            current_user.id,
            feedback_data,
        )
        audit_service.record(
            db,
            action="analyst_feedback_submitted",
            user=current_user,
            resource_type="incident",
            resource_id=incident_id,
            ip_address=_client_ip(request),
            details={
                "feedback_id": feedback.id,
                "classification": feedback.classification.value if hasattr(feedback.classification, "value") else str(feedback.classification),
            },
        )
        return feedback
    except ValueError as exc:
        _handle_incident_error(exc)


@router.get("/{incident_id}/feedback", response_model=list[FeedbackResponse])
def get_incident_feedback(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        return incident_service.get_feedback_for_incident(
            db,
            current_user.tenant_id,
            incident_id,
        )
    except ValueError as exc:
        _handle_incident_error(exc)


@router.get("/{incident_id}/timeline", response_model=list[TimelineItem])
def get_incident_timeline(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        return incident_service.get_timeline(db, current_user.tenant_id, incident_id)
    except ValueError as exc:
        _handle_incident_error(exc)


@router.post("/{incident_id}/priority", response_model=IncidentResponse)
def update_incident_priority(
    incident_id: str,
    priority_update: IncidentPriorityUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    try:
        incident = incident_service.update_priority(
            db=db,
            tenant_id=current_user.tenant_id,
            incident_id=incident_id,
            priority_data=priority_update,
        )
        audit_service.record(
            db,
            action="incident_priority_updated",
            user=current_user,
            resource_type="incident",
            resource_id=incident.id,
            ip_address=_client_ip(request),
            details={
                "priority": incident.priority.value,
                "due_date": incident.due_date.isoformat() if incident.due_date else None,
                "escalation_level": incident.escalation_level,
            },
        )
        return incident_service.serialize_incident(incident)
    except ValueError as exc:
        _handle_incident_error(exc)


@router.post("/{incident_id}/evidence", response_model=IncidentEvidenceResponse, status_code=status.HTTP_201_CREATED)
def create_evidence(
    incident_id: str,
    evidence_data: IncidentEvidenceCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    try:
        evidence = incident_service.create_evidence(
            db=db,
            tenant_id=current_user.tenant_id,
            incident_id=incident_id,
            user=current_user,
            evidence_data=evidence_data,
        )
        audit_service.record(
            db,
            action="incident_evidence_added",
            user=current_user,
            resource_type="incident",
            resource_id=incident_id,
            ip_address=_client_ip(request),
            details={
                "evidence_id": evidence.id,
                "type": evidence.type.value,
                "value": evidence.value,
            },
        )
        return evidence
    except ValueError as exc:
        _handle_incident_error(exc)


@router.get("/{incident_id}/evidence", response_model=list[IncidentEvidenceResponse])
def list_evidence(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        return incident_service.list_evidence(db, current_user.tenant_id, incident_id)
    except ValueError as exc:
        _handle_incident_error(exc)


@router.delete("/{incident_id}/evidence/{evidence_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_evidence(
    incident_id: str,
    evidence_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    try:
        incident_service.delete_evidence(
            db=db,
            tenant_id=current_user.tenant_id,
            incident_id=incident_id,
            evidence_id=evidence_id,
        )
        audit_service.record(
            db,
            action="incident_evidence_deleted",
            user=current_user,
            resource_type="incident",
            resource_id=incident_id,
            ip_address=_client_ip(request),
            details={"evidence_id": evidence_id},
        )
        return None
    except ValueError as exc:
        _handle_incident_error(exc)


@router.post("/{incident_id}/comments", response_model=IncidentComment, status_code=status.HTTP_201_CREATED)
def create_comment(
    incident_id: str,
    comment_data: IncidentCommentCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    try:
        comment = incident_comment_service.create_comment(
            db, current_user.tenant_id, incident_id, current_user.id, comment_data
        )
        audit_service.record(
            db,
            action="incident_comment_created",
            user=current_user,
            resource_type="incident",
            resource_id=incident_id,
            ip_address=_client_ip(request),
            details={"comment_id": comment.id},
        )
        return IncidentComment.model_validate(comment)
    except ValueError as exc:
        _handle_incident_error(exc)


@router.get("/{incident_id}/comments", response_model=list[IncidentComment])
def list_comments(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        comments = incident_comment_service.list_comments(
            db, current_user.tenant_id, incident_id
        )
        return [IncidentComment.model_validate(comment) for comment in comments]
    except ValueError as exc:
        _handle_incident_error(exc)


@router.post("/{incident_id}/actions", response_model=ResponseAction, status_code=status.HTTP_201_CREATED)
def create_response_action(
    incident_id: str,
    action_data: ResponseActionCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.RESPONDER)),
):
    try:
        action = response_action_service.create_action(
            db, current_user.tenant_id, incident_id, current_user.id, action_data
        )
        audit_service.record(
            db,
            action="incident_response_action_created",
            user=current_user,
            resource_type="incident",
            resource_id=incident_id,
            ip_address=_client_ip(request),
            details={"action_type": action.action_type},
        )
        return ResponseAction.model_validate(action)
    except ValueError as exc:
        _handle_incident_error(exc)


@router.get("/{incident_id}/actions", response_model=list[ResponseAction])
def list_response_actions(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        actions = response_action_service.list_actions(
            db, current_user.tenant_id, incident_id
        )
        return [ResponseAction.model_validate(action) for action in actions]
    except ValueError as exc:
        _handle_incident_error(exc)


@router.get("/{incident_id}/iocs", response_model=list[IOC])
def get_incident_iocs(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        iocs = ioc_service.get_iocs_for_incident(db, current_user.tenant_id, incident_id)
        return [IOC.model_validate(ioc) for ioc in iocs]
    except ValueError as exc:
        _handle_incident_error(exc)


@router.post("/{incident_id}/iocs/{ioc_id}/enrich")
def enrich_incident_ioc(
    incident_id: str,
    ioc_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    try:
        # Verify both incident and IOC exist and belong to tenant
        incident_service.get_incident_model(db, current_user.tenant_id, incident_id)
        ioc = ioc_service.get_ioc_by_id(db, current_user.tenant_id, ioc_id)
        from src.services.threat_intel_service import threat_intel_service
        return threat_intel_service.enrich_ioc(db, ioc)
    except ValueError as exc:
        _handle_incident_error(exc)
