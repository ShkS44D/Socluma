from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from src.api.deps import get_db
from src.core.permissions import Permission, require_permission
from src.models.pydantic import (
    AIAlertExplanationResponse,
    AIChatRequest,
    AIChatResponse,
    AIConversationDetailResponse,
    AIConversationSummaryResponse,
    AIDetectionSuggestionsResponse,
    AIIncidentSummaryResponse,
    AIIocAnalysisResponse,
    AIPlaybookSuggestionsResponse,
    AIReportResponse,
    AITimelineResponse,
)
from src.models.sqlalchemy import User
from src.services.ai_investigation_service import (
    AIInvestigationRateLimitError,
    AIInvestigationRequestInProgressError,
    ai_investigation_service,
)
from src.services.audit_service import audit_service


router = APIRouter(prefix="/ai", tags=["VigilantAI Copilot"])


def _client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


def _raise(exc: ValueError) -> None:
    message = str(exc)
    code = status.HTTP_404_NOT_FOUND if "not found" in message.lower() else status.HTTP_400_BAD_REQUEST
    raise HTTPException(status_code=code, detail=message) from exc


def _audit(db: Session, request: Request, user: User, action: str, resource_type: str, resource_id: str | None = None) -> None:
    audit_service.record(
        db,
        action=action,
        user=user,
        tenant_id=user.tenant_id,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=_client_ip(request),
    )


@router.post("/incident/{incident_id}/summary", response_model=AIIncidentSummaryResponse)
def generate_incident_summary(
    incident_id: str,
    request: Request,
    offline: bool = Query(False, description="Use the deterministic local analysis path in non-production environments."),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.TRIAGE_AI_USE)),
):
    try:
        if offline and ai_investigation_service.settings.ENVIRONMENT.casefold() in {"production", "prod"}:
            raise HTTPException(status_code=403, detail="Offline demo mode is unavailable in production")
        result = ai_investigation_service.incident_summary(
            db, current_user.tenant_id, incident_id, current_user, force_fallback=offline,
        )
        _audit(db, request, current_user, "ai_incident_summary_generated", "incident", incident_id)
        return result
    except ValueError as exc:
        _raise(exc)


@router.post("/incident/{incident_id}/chat", response_model=AIChatResponse)
def chat_with_incident_copilot(
    incident_id: str,
    data: AIChatRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.TRIAGE_AI_USE)),
):
    try:
        result = ai_investigation_service.chat(
            db,
            current_user.tenant_id,
            incident_id,
            current_user,
            data.message,
            data.conversation_id,
            request_id=getattr(request.state, "request_id", None),
        )
        _audit(db, request, current_user, "ai_incident_chat", "incident", incident_id)
        return result
    except AIInvestigationRateLimitError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    except AIInvestigationRequestInProgressError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        _raise(exc)


@router.get(
    "/incident/{incident_id}/conversations",
    response_model=list[AIConversationSummaryResponse],
    summary="List the current analyst's incident conversations",
)
def list_incident_conversations(
    incident_id: str,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.TRIAGE_AI_USE)),
):
    try:
        return ai_investigation_service.list_conversations(
            db, current_user.tenant_id, incident_id, current_user, limit, offset
        )
    except ValueError as exc:
        _raise(exc)


@router.get(
    "/incident/{incident_id}/conversations/{conversation_id}",
    response_model=AIConversationDetailResponse,
    summary="Get an incident conversation owned by the current analyst",
)
def get_incident_conversation(
    incident_id: str,
    conversation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.TRIAGE_AI_USE)),
):
    try:
        return ai_investigation_service.get_conversation(
            db, current_user.tenant_id, incident_id, conversation_id, current_user
        )
    except ValueError as exc:
        _raise(exc)


@router.post("/incident/{incident_id}/timeline", response_model=AITimelineResponse)
def generate_investigation_timeline(
    incident_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.TRIAGE_AI_USE)),
):
    try:
        result = ai_investigation_service.timeline(db, current_user.tenant_id, incident_id, current_user)
        _audit(db, request, current_user, "ai_timeline_generated", "incident", incident_id)
        return result
    except ValueError as exc:
        _raise(exc)


@router.post("/incident/{incident_id}/report", response_model=AIReportResponse)
def generate_incident_report(
    incident_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.TRIAGE_AI_USE)),
):
    try:
        result = ai_investigation_service.report(db, current_user.tenant_id, incident_id, current_user)
        _audit(db, request, current_user, "ai_report_generated", "incident", incident_id)
        return result
    except ValueError as exc:
        _raise(exc)


@router.post("/alert/{alert_id}/explain", response_model=AIAlertExplanationResponse)
def explain_alert(
    alert_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.TRIAGE_AI_USE)),
):
    try:
        result = ai_investigation_service.alert_explanation(db, current_user.tenant_id, alert_id, current_user)
        _audit(db, request, current_user, "ai_alert_explained", "alert", alert_id)
        return result
    except ValueError as exc:
        _raise(exc)


@router.post("/ioc/{ioc_id}/analyze", response_model=AIIocAnalysisResponse)
def analyze_ioc(
    ioc_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.TRIAGE_AI_USE)),
):
    try:
        result = ai_investigation_service.ioc_analysis(db, current_user.tenant_id, ioc_id, current_user)
        _audit(db, request, current_user, "ai_ioc_analyzed", "ioc", ioc_id)
        return result
    except ValueError as exc:
        _raise(exc)


@router.post("/detections/suggest", response_model=AIDetectionSuggestionsResponse)
def suggest_detection_rules(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.TRIAGE_AI_USE)),
):
    result = ai_investigation_service.detection_suggestions(db, current_user.tenant_id, current_user)
    _audit(db, request, current_user, "ai_detection_suggestions_generated", "detection_rule")
    return result


@router.post("/playbooks/suggest", response_model=AIPlaybookSuggestionsResponse)
def suggest_playbooks(
    request: Request,
    incident_id: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.TRIAGE_AI_USE)),
):
    try:
        result = ai_investigation_service.playbook_suggestions(db, current_user.tenant_id, current_user, incident_id=incident_id)
        _audit(db, request, current_user, "ai_playbook_suggestions_generated", "playbook", incident_id)
        return result
    except ValueError as exc:
        _raise(exc)
