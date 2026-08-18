from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from src.api.deps import get_db
from src.core.permissions import Permission, require_permission
from src.models.pydantic import (
    ActionConnector,
    ActionConnectorCreate,
    ActionConnectorUpdate,
    ConnectorActionExecution,
    ConnectorActionLog,
    ConnectorCredential,
    ConnectorCredentialCreate,
    ConnectorCredentialUpdate,
    ConnectorExecutionCreate,
    ConnectorTestResponse,
    MessageResponse,
    SOARActionApproval,
    SOARApprovalDecision,
)
from src.models.sqlalchemy import User
from src.services.audit_service import audit_service
from src.services.soar_action_service import soar_action_service
from src.core.validation import validate_uuid


router = APIRouter(prefix="/soar", tags=["SOAR"])


def _client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


def _raise(error: ValueError) -> None:
    message = str(error)
    code = status.HTTP_404_NOT_FOUND if "not found" in message.lower() else status.HTTP_400_BAD_REQUEST
    raise HTTPException(status_code=code, detail=message)


def _audit(db: Session, request: Request, user: User, action: str, resource_type: str, resource_id: str | None = None, details: dict | None = None) -> None:
    audit_service.record(
        db,
        action=action,
        user=user,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=_client_ip(request),
        details=details,
    )


@router.get("/connector-types")
def list_connector_types(current_user: User = Depends(require_permission(Permission.SOAR_VIEW))):
    return soar_action_service.list_connector_types()


@router.get("/connectors", response_model=list[ActionConnector])
def list_connectors(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_VIEW)),
):
    return [ActionConnector.model_validate(item) for item in soar_action_service.list_connectors(db, current_user.tenant_id)]


@router.post("/connectors", response_model=ActionConnector, status_code=status.HTTP_201_CREATED)
def create_connector(
    data: ActionConnectorCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_MANAGE)),
):
    try:
        connector = soar_action_service.create_connector(db, current_user.tenant_id, current_user.id, data)
        _audit(db, request, current_user, "soar_connector_created", "action_connector", connector.id)
        return ActionConnector.model_validate(connector)
    except ValueError as exc:
        _raise(exc)


@router.get("/connectors/{connector_id}", response_model=ActionConnector)
def get_connector(
    connector_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_VIEW)),
):
    validate_uuid(connector_id, "connector_id")
    try:
        return ActionConnector.model_validate(soar_action_service.get_connector(db, current_user.tenant_id, connector_id))
    except ValueError as exc:
        _raise(exc)


@router.patch("/connectors/{connector_id}", response_model=ActionConnector)
def update_connector(
    connector_id: str,
    data: ActionConnectorUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_MANAGE)),
):
    validate_uuid(connector_id, "connector_id")
    try:
        connector = soar_action_service.update_connector(db, current_user.tenant_id, connector_id, current_user.id, data)
        _audit(db, request, current_user, "soar_connector_updated", "action_connector", connector.id)
        return ActionConnector.model_validate(connector)
    except ValueError as exc:
        _raise(exc)


@router.delete("/connectors/{connector_id}", response_model=MessageResponse)
def delete_connector(
    connector_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_MANAGE)),
):
    validate_uuid(connector_id, "connector_id")
    try:
        soar_action_service.delete_connector(db, current_user.tenant_id, connector_id)
        _audit(db, request, current_user, "soar_connector_disabled", "action_connector", connector_id)
        return MessageResponse(detail="Connector disabled")
    except ValueError as exc:
        _raise(exc)


@router.post("/connectors/{connector_id}/test", response_model=ConnectorTestResponse)
def test_connector(
    connector_id: str,
    request: Request,
    credential_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_MANAGE)),
):
    validate_uuid(connector_id, "connector_id")
    if credential_id:
        validate_uuid(credential_id, "credential_id")
    try:
        result = soar_action_service.test_connector(db, current_user.tenant_id, connector_id, credential_id)
        _audit(db, request, current_user, "soar_connector_tested", "action_connector", connector_id, {"success": result["success"]})
        return ConnectorTestResponse(**result)
    except ValueError as exc:
        _raise(exc)


@router.get("/credentials", response_model=list[ConnectorCredential])
def list_credentials(
    connector_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_MANAGE)),
):
    if connector_id:
        validate_uuid(connector_id, "connector_id")
    return [ConnectorCredential.model_validate(item) for item in soar_action_service.list_credentials(db, current_user.tenant_id, connector_id)]


@router.post("/credentials", response_model=ConnectorCredential, status_code=status.HTTP_201_CREATED)
def create_credential(
    data: ConnectorCredentialCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_CREDENTIALS_MANAGE)),
):
    validate_uuid(data.connector_id, "connector_id")
    try:
        credential = soar_action_service.create_credential(db, current_user.tenant_id, current_user.id, data)
        _audit(db, request, current_user, "soar_credential_created", "connector_credential", credential.id)
        return ConnectorCredential.model_validate(credential)
    except ValueError as exc:
        _raise(exc)


@router.patch("/credentials/{credential_id}", response_model=ConnectorCredential)
def update_credential(
    credential_id: str,
    data: ConnectorCredentialUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_CREDENTIALS_MANAGE)),
):
    validate_uuid(credential_id, "credential_id")
    try:
        credential = soar_action_service.update_credential(db, current_user.tenant_id, credential_id, current_user.id, data)
        _audit(db, request, current_user, "soar_credential_updated", "connector_credential", credential.id)
        return ConnectorCredential.model_validate(credential)
    except ValueError as exc:
        _raise(exc)


@router.get("/executions", response_model=list[ConnectorActionExecution])
def list_executions(
    connector_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_VIEW)),
):
    if connector_id:
        validate_uuid(connector_id, "connector_id")
    return [ConnectorActionExecution.model_validate(item) for item in soar_action_service.list_executions(db, current_user.tenant_id, connector_id)]


@router.post("/executions", response_model=ConnectorActionExecution, status_code=status.HTTP_201_CREATED)
def create_execution(
    data: ConnectorExecutionCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_EXECUTE)),
):
    validate_uuid(data.connector_id, "connector_id")
    if data.credential_id:
        validate_uuid(data.credential_id, "credential_id")
    try:
        execution = soar_action_service.create_execution(db, current_user.tenant_id, current_user.id, data)
        _audit(db, request, current_user, "soar_action_requested", "connector_action_execution", execution.id)
        return ConnectorActionExecution.model_validate(execution)
    except ValueError as exc:
        _raise(exc)


@router.get("/executions/{execution_id}", response_model=ConnectorActionExecution)
def get_execution(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_VIEW)),
):
    validate_uuid(execution_id, "execution_id")
    try:
        return ConnectorActionExecution.model_validate(soar_action_service.get_execution(db, current_user.tenant_id, execution_id))
    except ValueError as exc:
        _raise(exc)


@router.get("/executions/{execution_id}/logs", response_model=list[ConnectorActionLog])
def list_logs(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_VIEW)),
):
    validate_uuid(execution_id, "execution_id")
    try:
        return [ConnectorActionLog.model_validate(item) for item in soar_action_service.list_logs(db, current_user.tenant_id, execution_id)]
    except ValueError as exc:
        _raise(exc)


@router.get("/approvals", response_model=list[SOARActionApproval])
def list_approvals(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_VIEW)),
):
    return [SOARActionApproval.model_validate(item) for item in soar_action_service.list_approvals(db, current_user.tenant_id)]


@router.post("/approvals/{approval_id}/approve", response_model=SOARActionApproval)
def approve_action(
    approval_id: str,
    decision: SOARApprovalDecision,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_APPROVE)),
):
    validate_uuid(approval_id, "approval_id")
    try:
        approval = soar_action_service.approve_execution(db, current_user.tenant_id, approval_id, current_user, decision.comment)
        _audit(db, request, current_user, "soar_action_approved", "soar_action_approval", approval.id)
        return SOARActionApproval.model_validate(approval)
    except ValueError as exc:
        _raise(exc)


@router.post("/approvals/{approval_id}/reject", response_model=SOARActionApproval)
def reject_action(
    approval_id: str,
    decision: SOARApprovalDecision,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_APPROVE)),
):
    validate_uuid(approval_id, "approval_id")
    try:
        approval = soar_action_service.reject_execution(db, current_user.tenant_id, approval_id, current_user, decision.comment)
        _audit(db, request, current_user, "soar_action_rejected", "soar_action_approval", approval.id)
        return SOARActionApproval.model_validate(approval)
    except ValueError as exc:
        _raise(exc)
