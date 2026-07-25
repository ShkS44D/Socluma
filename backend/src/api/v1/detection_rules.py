from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, Query
from sqlalchemy.orm import Session

from src.api.deps import get_db, get_current_user, require_roles
from src.models.pydantic import (
    DetectionRule,
    DetectionRuleCreate,
    DetectionRuleSigmaImport,
    DetectionRuleTestRequest,
    DetectionRuleTestResponse,
    DetectionRuleUpdate,
)
from src.models.sqlalchemy import RuleType, User, UserRole
from src.services.detection_engine import detection_engine
from src.services.detection_rule_service import detection_rule_service
from src.services.sigma_rule_service import sigma_rule_service
from src.services.audit_service import audit_service


router = APIRouter(prefix="/detection-rules", tags=["Detection Rules"])


def _client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


@router.post("", response_model=DetectionRule, status_code=status.HTTP_201_CREATED)
def create_rule(
    rule_data: DetectionRuleCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
):
    try:
        rule = detection_rule_service.create_rule(
            db, current_user.tenant_id, current_user.id, rule_data
        )
        audit_service.record(
            db,
            action="detection_rule_created",
            user=current_user,
            resource_type="detection_rule",
            resource_id=rule.id,
            ip_address=_client_ip(request),
            details={"name": rule.name},
        )
        return DetectionRule.model_validate(rule)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.get("", response_model=list[DetectionRule])
def list_rules(
    enabled_only: bool | None = Query(None, description="Filter by enabled status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rules = detection_rule_service.list_rules(db, current_user.tenant_id, enabled_only)
    return [DetectionRule.model_validate(rule) for rule in rules]


@router.post("/import/sigma", response_model=DetectionRule, status_code=status.HTTP_201_CREATED)
def import_sigma_rule(
    payload: DetectionRuleSigmaImport,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
):
    validation = sigma_rule_service.validate(payload.content)
    if not validation.valid or validation.normalized is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="; ".join(validation.errors))
    rule_content = validation.normalized
    rule_data = DetectionRuleCreate(
        name=rule_content.get("title"),
        description=rule_content.get("description"),
        type=RuleType.SIGMA,
        rule_type=RuleType.SIGMA,
        sigma_rule=payload.content,
        rule_content=rule_content,
        event_type=sigma_rule_service.infer_event_type(rule_content),
        severity=sigma_rule_service.infer_severity(rule_content),
        enabled=payload.enabled,
        mitre_technique_id=_first_attack_tag(rule_content),
    )
    rule = detection_rule_service.create_rule(db, current_user.tenant_id, current_user.id, rule_data)
    audit_service.record(
        db,
        action="sigma_rule_imported",
        user=current_user,
        resource_type="detection_rule",
        resource_id=rule.id,
        ip_address=_client_ip(request),
        details={"name": rule.name},
    )
    return DetectionRule.model_validate(rule)


@router.get("/{rule_id}", response_model=DetectionRule)
def get_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        rule = detection_rule_service.get_rule_by_id(db, current_user.tenant_id, rule_id)
        return DetectionRule.model_validate(rule)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e


@router.get("/{rule_id}/export")
def export_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        rule = detection_rule_service.get_rule_by_id(db, current_user.tenant_id, rule_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    if rule.rule_content:
        content = sigma_rule_service.export_yaml(rule.rule_content)
    else:
        content = rule.sigma_rule or rule.query or ""
    media_type = "application/x-yaml" if rule.rule_type == RuleType.SIGMA else "text/plain"
    return Response(content=content, media_type=media_type)


@router.post("/{rule_id}/test", response_model=DetectionRuleTestResponse)
def test_rule(
    rule_id: str,
    payload: DetectionRuleTestRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        rule = detection_rule_service.get_rule_by_id(db, current_user.tenant_id, rule_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    result = detection_engine._match_rule(rule, _event_proxy(payload.event))
    combined_event = {
        **_event_proxy(payload.event).raw_event,
        **_event_proxy(payload.event).normalized_event,
        "raw_data": _event_proxy(payload.event).raw_event,
        "normalized_event": _event_proxy(payload.event).normalized_event,
        "event_data": (
            _event_proxy(payload.event).raw_event.get("EventData")
            or _event_proxy(payload.event).raw_event.get("event_data")
            or {}
        ),
        "source": payload.event.get("source", "rule-tester"),
        "event_type": payload.event.get("event_type"),
    }
    explanation = (
        sigma_rule_service.explain(rule.rule_content, combined_event)
        if rule.rule_type == RuleType.SIGMA and rule.rule_content
        else {
            "matched": bool(result.get("matched")),
            "summary": str(result.get("why_matched") or ""),
            "logsource": {"matched": True, "checks": [], "summary": "not applicable"},
            "selections": [],
            "condition": {"matched": bool(result.get("matched")), "details": str(result.get("why_matched") or "")},
        }
    )
    return DetectionRuleTestResponse(
        matched=bool(result.get("matched")),
        details=str(result.get("why_matched") or result.get("matched_condition") or ""),
        explanation=explanation,
    )


@router.patch("/{rule_id}", response_model=DetectionRule)
def update_rule(
    rule_id: str,
    update_data: DetectionRuleUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
):
    try:
        rule = detection_rule_service.update_rule(
            db, current_user.tenant_id, rule_id, update_data
        )
        audit_service.record(
            db,
            action="detection_rule_updated",
            user=current_user,
            resource_type="detection_rule",
            resource_id=rule.id,
            ip_address=_client_ip(request),
        )
        return DetectionRule.model_validate(rule)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


def _first_attack_tag(rule_content: dict) -> str | None:
    tags = rule_content.get("tags") or []
    if not isinstance(tags, list):
        return None
    for tag in tags:
        tag_text = str(tag)
        if tag_text.startswith("attack.t"):
            return tag_text.removeprefix("attack.").upper()
    return None


def _event_proxy(event: dict):
    class EventProxy:
        raw_event = event.get("raw_event") or event.get("raw_data") or event
        normalized_event = event.get("normalized_event") or event.get("ocsf_data") or event
        source = event.get("source", "rule-tester")
        event_type = event.get("event_type")

    return EventProxy()


@router.patch("/{rule_id}/toggle", response_model=DetectionRule)
def toggle_rule(
    rule_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
):
    try:
        rule = detection_rule_service.toggle_rule(
            db, current_user.tenant_id, rule_id
        )
        audit_service.record(
            db,
            action="detection_rule_toggled",
            user=current_user,
            resource_type="detection_rule",
            resource_id=rule.id,
            ip_address=_client_ip(request),
            details={"enabled": rule.enabled},
        )
        return DetectionRule.model_validate(rule)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
):
    try:
        detection_rule_service.delete_rule(db, current_user.tenant_id, rule_id)
        audit_service.record(
            db,
            action="detection_rule_deleted",
            user=current_user,
            resource_type="detection_rule",
            resource_id=rule_id,
            ip_address=_client_ip(request),
        )
        return None
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
