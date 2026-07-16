from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from src.api.deps import get_current_user, get_db, require_roles
from src.models.pydantic import (
    MessageResponse,
    Playbook,
    PlaybookApproval,
    PlaybookApprovalDecision,
    PlaybookCreate,
    PlaybookExecution,
    PlaybookExecutionCreate,
    PlaybookExecutionStep,
    PlaybookRunLog,
    PlaybookStep,
    PlaybookStepCreate,
    PlaybookUpdate,
    PlaybookVariable,
    PlaybookVariableCreate,
    PlaybookVariableUpdate,
    PlaybookVersion,
    PlaybookVersionCreate,
)
from src.models.sqlalchemy import (
    PlaybookApprovalStatus,
    PlaybookExecutionStatus,
    PlaybookStatus,
    PlaybookTriggerType,
    User,
    UserRole,
)
from src.services.audit_service import audit_service
from src.services.playbook_service import playbook_service
from src.core.validation import validate_uuid


router = APIRouter(prefix="/playbooks", tags=["Playbooks"])


def _client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


def _raise_not_found_or_bad_request(error: ValueError) -> None:
    message = str(error)
    status_code = status.HTTP_404_NOT_FOUND if "not found" in message.lower() else status.HTTP_400_BAD_REQUEST
    raise HTTPException(status_code=status_code, detail=message)


def _audit(
    db: Session,
    request: Request,
    user: User,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict | None = None,
) -> None:
    audit_service.record(
        db,
        action=action,
        user=user,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=_client_ip(request),
        details=details,
    )


@router.post("", response_model=Playbook, status_code=status.HTTP_201_CREATED)
def create_playbook(
    playbook_data: PlaybookCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    playbook = playbook_service.create_playbook(db, current_user.tenant_id, current_user.id, playbook_data)
    _audit(db, request, current_user, "playbook_created", "playbook", playbook.id, {"name": playbook.name})
    return Playbook.model_validate(playbook)


@router.get("", response_model=list[Playbook])
def list_playbooks(
    status_filter: Optional[PlaybookStatus] = Query(None, alias="status"),
    trigger_type: Optional[PlaybookTriggerType] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    playbooks = playbook_service.list_playbooks(
        db,
        current_user.tenant_id,
        status=status_filter,
        trigger_type=trigger_type,
        limit=limit,
        offset=offset,
    )
    return [Playbook.model_validate(pb) for pb in playbooks]


@router.post("/execute", response_model=PlaybookExecution, status_code=status.HTTP_201_CREATED)
def execute_playbook(
    execution_data: PlaybookExecutionCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.RESPONDER)),
):
    return _execute_playbook(execution_data, request, db, current_user)


def _execute_playbook(
    execution_data: PlaybookExecutionCreate,
    request: Request,
    db: Session,
    current_user: User,
) -> PlaybookExecution:
    validate_uuid(execution_data.playbook_id, "playbook_id")
    if execution_data.incident_id:
        validate_uuid(execution_data.incident_id, "incident_id")
    if execution_data.alert_id:
        validate_uuid(execution_data.alert_id, "alert_id")
    try:
        execution = playbook_service.execute_playbook(
            db,
            current_user.tenant_id,
            incident_id=execution_data.incident_id,
            alert_id=execution_data.alert_id,
            playbook_id=execution_data.playbook_id,
            trigger_type=execution_data.trigger_type,
            context=execution_data.context,
            triggered_by=current_user.id,
        )
        _audit(
            db,
            request,
            current_user,
            "playbook_executed",
            "playbook_execution",
            execution.id,
            {"playbook_id": execution_data.playbook_id, "incident_id": execution_data.incident_id},
        )
        return PlaybookExecution.model_validate(execution)
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.get("/executions", response_model=list[PlaybookExecution])
def list_executions(
    incident_id: Optional[str] = None,
    playbook_id: Optional[str] = None,
    status_filter: Optional[PlaybookExecutionStatus] = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if incident_id:
        validate_uuid(incident_id, "incident_id")
    if playbook_id:
        validate_uuid(playbook_id, "playbook_id")
    executions = playbook_service.list_executions(
        db,
        current_user.tenant_id,
        incident_id=incident_id,
        playbook_id=playbook_id,
        status=status_filter,
        limit=limit,
        offset=offset,
    )
    return [PlaybookExecution.model_validate(execution) for execution in executions]


@router.get("/executions/{execution_id}", response_model=PlaybookExecution)
def get_execution(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    validate_uuid(execution_id, "execution_id")
    try:
        return PlaybookExecution.model_validate(playbook_service.get_execution(db, current_user.tenant_id, execution_id))
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.get("/executions/{execution_id}/steps", response_model=list[PlaybookExecutionStep])
def list_execution_steps(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    validate_uuid(execution_id, "execution_id")
    try:
        steps = playbook_service.list_execution_steps(db, current_user.tenant_id, execution_id)
        return [PlaybookExecutionStep.model_validate(step) for step in steps]
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.get("/executions/{execution_id}/logs", response_model=list[PlaybookRunLog])
def list_execution_logs(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    validate_uuid(execution_id, "execution_id")
    try:
        logs = playbook_service.list_logs(db, current_user.tenant_id, execution_id)
        return [PlaybookRunLog.model_validate(log) for log in logs]
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.post("/executions/{execution_id}/pause", response_model=PlaybookExecution)
def pause_execution(
    execution_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    validate_uuid(execution_id, "execution_id")
    try:
        execution = playbook_service.pause_execution(db, current_user.tenant_id, execution_id)
        _audit(db, request, current_user, "playbook_execution_paused", "playbook_execution", execution_id)
        return PlaybookExecution.model_validate(execution)
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.post("/executions/{execution_id}/resume", response_model=PlaybookExecution)
def resume_execution(
    execution_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    validate_uuid(execution_id, "execution_id")
    try:
        execution = playbook_service.resume_execution(db, current_user.tenant_id, execution_id)
        _audit(db, request, current_user, "playbook_execution_resumed", "playbook_execution", execution_id)
        return PlaybookExecution.model_validate(execution)
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.post("/executions/{execution_id}/cancel", response_model=PlaybookExecution)
def cancel_execution(
    execution_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    validate_uuid(execution_id, "execution_id")
    try:
        execution = playbook_service.cancel_execution(db, current_user.tenant_id, execution_id)
        _audit(db, request, current_user, "playbook_execution_cancelled", "playbook_execution", execution_id)
        return PlaybookExecution.model_validate(execution)
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.post("/executions/{execution_id}/approve", response_model=PlaybookExecution)
def approve_execution(
    execution_id: str,
    decision: PlaybookApprovalDecision,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.RESPONDER)),
):
    validate_uuid(execution_id, "execution_id")
    try:
        execution = playbook_service.approve_execution(db, current_user.tenant_id, execution_id, current_user.id, decision.comment)
        _audit(db, request, current_user, "playbook_execution_approved", "playbook_execution", execution_id)
        return PlaybookExecution.model_validate(execution)
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.get("/approvals", response_model=list[PlaybookApproval])
def list_approvals(
    execution_id: Optional[str] = None,
    status_filter: Optional[PlaybookApprovalStatus] = Query(None, alias="status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if execution_id:
        validate_uuid(execution_id, "execution_id")
    approvals = playbook_service.list_approvals(db, current_user.tenant_id, execution_id, status_filter)
    return [PlaybookApproval.model_validate(approval) for approval in approvals]


@router.post("/approvals/{approval_id}/approve", response_model=PlaybookApproval)
def approve_by_id(
    approval_id: str,
    decision: PlaybookApprovalDecision,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.RESPONDER)),
):
    validate_uuid(approval_id, "approval_id")
    try:
        approval = playbook_service.approve_by_id(db, current_user.tenant_id, approval_id, current_user.id, decision.comment)
        _audit(db, request, current_user, "playbook_approval_approved", "playbook_approval", approval_id)
        return PlaybookApproval.model_validate(approval)
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.post("/approvals/{approval_id}/reject", response_model=PlaybookApproval)
def reject_approval(
    approval_id: str,
    decision: PlaybookApprovalDecision,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.RESPONDER)),
):
    validate_uuid(approval_id, "approval_id")
    try:
        approval = playbook_service.reject_approval(db, current_user.tenant_id, approval_id, current_user.id, decision.comment)
        _audit(db, request, current_user, "playbook_approval_rejected", "playbook_approval", approval_id)
        return PlaybookApproval.model_validate(approval)
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.get("/variables", response_model=list[PlaybookVariable])
def list_variables(
    playbook_id: Optional[str] = None,
    scope: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if playbook_id:
        validate_uuid(playbook_id, "playbook_id")
    variables = playbook_service.list_variables(db, current_user.tenant_id, playbook_id, scope)
    return [PlaybookVariable.model_validate(variable) for variable in variables]


@router.post("/variables", response_model=PlaybookVariable, status_code=status.HTTP_201_CREATED)
def create_variable(
    data: PlaybookVariableCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    try:
        variable = playbook_service.create_variable(db, current_user.tenant_id, current_user.id, data)
        _audit(db, request, current_user, "playbook_variable_created", "playbook_variable", variable.id)
        return PlaybookVariable.model_validate(variable)
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.patch("/variables/{variable_id}", response_model=PlaybookVariable)
def update_variable(
    variable_id: str,
    data: PlaybookVariableUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    validate_uuid(variable_id, "variable_id")
    try:
        variable = playbook_service.update_variable(db, current_user.tenant_id, variable_id, current_user.id, data)
        _audit(db, request, current_user, "playbook_variable_updated", "playbook_variable", variable_id)
        return PlaybookVariable.model_validate(variable)
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.delete("/variables/{variable_id}", response_model=MessageResponse)
def delete_variable(
    variable_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
):
    validate_uuid(variable_id, "variable_id")
    try:
        playbook_service.delete_variable(db, current_user.tenant_id, variable_id)
        _audit(db, request, current_user, "playbook_variable_deleted", "playbook_variable", variable_id)
        return MessageResponse(detail="Variable deleted")
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)

@router.get("/{playbook_id}", response_model=Playbook)
def get_playbook(
    playbook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    validate_uuid(playbook_id, "playbook_id")
    playbook = playbook_service.get_playbook(db, current_user.tenant_id, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return Playbook.model_validate(playbook)


@router.patch("/{playbook_id}", response_model=Playbook)
def update_playbook(
    playbook_id: str,
    update_data: PlaybookUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    validate_uuid(playbook_id, "playbook_id")
    try:
        playbook = playbook_service.update_playbook(db, current_user.tenant_id, playbook_id, update_data)
        _audit(db, request, current_user, "playbook_updated", "playbook", playbook_id)
        return Playbook.model_validate(playbook)
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.delete("/{playbook_id}", response_model=MessageResponse)
def delete_playbook(
    playbook_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
):
    validate_uuid(playbook_id, "playbook_id")
    try:
        playbook_service.delete_playbook(db, current_user.tenant_id, playbook_id)
        _audit(db, request, current_user, "playbook_archived", "playbook", playbook_id)
        return MessageResponse(detail="Playbook archived")
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.post("/{playbook_id}/versions", response_model=PlaybookVersion, status_code=status.HTTP_201_CREATED)
def create_version(
    playbook_id: str,
    version_data: PlaybookVersionCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    validate_uuid(playbook_id, "playbook_id")
    try:
        version = playbook_service.create_version(db, current_user.tenant_id, current_user.id, playbook_id, version_data)
        _audit(db, request, current_user, "playbook_version_created", "playbook", playbook_id, {"version_id": version.id})
        return PlaybookVersion.model_validate(version)
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.get("/{playbook_id}/versions", response_model=list[PlaybookVersion])
def list_versions(
    playbook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    validate_uuid(playbook_id, "playbook_id")
    try:
        versions = playbook_service.list_versions(db, current_user.tenant_id, playbook_id)
        return [PlaybookVersion.model_validate(version) for version in versions]
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.post("/{playbook_id}/versions/{version_id}/publish", response_model=PlaybookVersion)
def publish_version(
    playbook_id: str,
    version_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
):
    validate_uuid(playbook_id, "playbook_id")
    validate_uuid(version_id, "version_id")
    try:
        version = playbook_service.publish_version(db, current_user.tenant_id, playbook_id, version_id, current_user.id)
        _audit(db, request, current_user, "playbook_version_published", "playbook", playbook_id, {"version_id": version_id})
        return PlaybookVersion.model_validate(version)
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.post("/{playbook_id}/activate", response_model=Playbook)
def activate_playbook(
    playbook_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
):
    validate_uuid(playbook_id, "playbook_id")
    try:
        playbook = playbook_service.activate_playbook(db, current_user.tenant_id, playbook_id)
        _audit(db, request, current_user, "playbook_activated", "playbook", playbook_id)
        return Playbook.model_validate(playbook)
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.post("/{playbook_id}/deactivate", response_model=Playbook)
def deactivate_playbook(
    playbook_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
):
    validate_uuid(playbook_id, "playbook_id")
    try:
        playbook = playbook_service.deactivate_playbook(db, current_user.tenant_id, playbook_id)
        _audit(db, request, current_user, "playbook_deactivated", "playbook", playbook_id)
        return Playbook.model_validate(playbook)
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.post("/{playbook_id}/steps", response_model=PlaybookStep, status_code=status.HTTP_201_CREATED)
def add_step(
    playbook_id: str,
    step_data: PlaybookStepCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    validate_uuid(playbook_id, "playbook_id")
    try:
        step = playbook_service.add_step(db, current_user.tenant_id, playbook_id, step_data)
        _audit(db, request, current_user, "playbook_step_added", "playbook", playbook_id)
        return PlaybookStep.model_validate(step)
    except ValueError as exc:
        _raise_not_found_or_bad_request(exc)


@router.get("/{playbook_id}/steps", response_model=list[PlaybookStep])
def list_steps(
    playbook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    validate_uuid(playbook_id, "playbook_id")
    playbook = playbook_service.get_playbook(db, current_user.tenant_id, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    steps = playbook_service.get_steps(db, playbook_id)
    return [PlaybookStep.model_validate(step) for step in steps]


@router.post("/{playbook_id}/execute", response_model=PlaybookExecution, status_code=status.HTTP_201_CREATED)
def execute_playbook_by_id(
    playbook_id: str,
    execution_data: PlaybookExecutionCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.RESPONDER)),
):
    validate_uuid(playbook_id, "playbook_id")
    execution_data.playbook_id = playbook_id
    return _execute_playbook(execution_data, request, db, current_user)
