from __future__ import annotations

import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from src.connectors.base import ConnectorRequest
from src.connectors.registry import connector_registry
from src.core.config import get_settings
from src.core.crypto import decrypt_json_secret, encrypt_json_secret, fingerprint_secret
from src.core.logging import logger, request_id_ctx
from src.core.observability import (
    CONNECTOR_APPROVAL_LATENCY,
    CONNECTOR_EXECUTION_DURATION,
    CONNECTOR_EXECUTIONS,
    CONNECTOR_FAILURES,
    CONNECTOR_RETRIES,
    CONNECTOR_TIMEOUTS,
)
from src.models.pydantic import (
    ActionConnectorCreate,
    ActionConnectorUpdate,
    ConnectorCredentialCreate,
    ConnectorCredentialUpdate,
    ConnectorExecutionCreate,
)
from src.models.sqlalchemy import (
    ActionConnector,
    ActionExecutionStatus,
    ConnectorActionExecution,
    ConnectorActionLog,
    ConnectorCredential,
    ConnectorStatus,
    CredentialStatus,
    SOARActionApproval,
    SOARApprovalStatus,
    User,
    UserRole,
)
from src.utils.datetime_utils import ensure_utc


SENSITIVE_KEYS = {"authorization", "password", "secret", "token", "api_key", "webhook_url", "bearer_token"}


class SOARActionService:
    def list_connector_types(self) -> list[dict[str, str]]:
        return connector_registry.list_types()

    def list_connectors(self, db: Session, tenant_id: str) -> list[ActionConnector]:
        return db.query(ActionConnector).filter(ActionConnector.tenant_id == tenant_id).order_by(ActionConnector.name.asc()).all()

    def get_connector(self, db: Session, tenant_id: str, connector_id: str) -> ActionConnector:
        connector = db.query(ActionConnector).filter(ActionConnector.id == connector_id, ActionConnector.tenant_id == tenant_id).first()
        if not connector:
            raise ValueError("Connector not found")
        return connector

    def create_connector(self, db: Session, tenant_id: str, user_id: str, data: ActionConnectorCreate) -> ActionConnector:
        connector_impl = connector_registry.get(data.type.value)
        connector_impl.validate(data.config, None)
        connector = ActionConnector(
            tenant_id=tenant_id,
            name=data.name,
            type=data.type,
            status=ConnectorStatus.ACTIVE,
            config=data.config,
            requires_approval=data.requires_approval,
            approval_roles=[role.value for role in data.approval_roles] if data.approval_roles else None,
            created_by=user_id,
            updated_by=user_id,
        )
        db.add(connector)
        db.commit()
        db.refresh(connector)
        return connector

    def update_connector(self, db: Session, tenant_id: str, connector_id: str, user_id: str, data: ActionConnectorUpdate) -> ActionConnector:
        connector = self.get_connector(db, tenant_id, connector_id)
        next_config = data.config if data.config is not None else connector.config
        connector_registry.get(connector.type.value).validate(next_config, None)
        for field in ("name", "status", "config", "requires_approval"):
            value = getattr(data, field)
            if value is not None:
                setattr(connector, field, value)
        if data.approval_roles is not None:
            connector.approval_roles = [role.value for role in data.approval_roles]
        connector.updated_by = user_id
        db.commit()
        db.refresh(connector)
        return connector

    def delete_connector(self, db: Session, tenant_id: str, connector_id: str) -> None:
        connector = self.get_connector(db, tenant_id, connector_id)
        connector.status = ConnectorStatus.DISABLED
        db.commit()

    def create_credential(self, db: Session, tenant_id: str, user_id: str, data: ConnectorCredentialCreate) -> ConnectorCredential:
        connector = self.get_connector(db, tenant_id, data.connector_id)
        connector_registry.get(connector.type.value).validate(connector.config, data.secret)
        credential = ConnectorCredential(
            tenant_id=tenant_id,
            connector_id=connector.id,
            name=data.name,
            encrypted_secret=encrypt_json_secret(data.secret),
            secret_fingerprint=fingerprint_secret(data.secret),
            status=CredentialStatus.ACTIVE,
            created_by=user_id,
            updated_by=user_id,
        )
        db.add(credential)
        db.commit()
        db.refresh(credential)
        return credential

    def list_credentials(self, db: Session, tenant_id: str, connector_id: Optional[str] = None) -> list[ConnectorCredential]:
        query = db.query(ConnectorCredential).filter(ConnectorCredential.tenant_id == tenant_id)
        if connector_id:
            query = query.filter(ConnectorCredential.connector_id == connector_id)
        return query.order_by(ConnectorCredential.created_at.desc()).all()

    def update_credential(self, db: Session, tenant_id: str, credential_id: str, user_id: str, data: ConnectorCredentialUpdate) -> ConnectorCredential:
        credential = self.get_credential(db, tenant_id, credential_id)
        if data.name is not None:
            credential.name = data.name
        if data.status is not None:
            credential.status = data.status
        if data.secret is not None:
            connector_registry.get(credential.connector.type.value).validate(credential.connector.config, data.secret)
            credential.encrypted_secret = encrypt_json_secret(data.secret)
            credential.secret_fingerprint = fingerprint_secret(data.secret)
            credential.rotated_at = self._utcnow()
        credential.updated_by = user_id
        db.commit()
        db.refresh(credential)
        return credential

    def get_credential(self, db: Session, tenant_id: str, credential_id: str) -> ConnectorCredential:
        credential = db.query(ConnectorCredential).filter(
            ConnectorCredential.id == credential_id,
            ConnectorCredential.tenant_id == tenant_id,
        ).first()
        if not credential:
            raise ValueError("Credential not found")
        return credential

    def test_connector(self, db: Session, tenant_id: str, connector_id: str, credential_id: Optional[str] = None) -> dict[str, Any]:
        connector = self.get_connector(db, tenant_id, connector_id)
        credentials = self._credential_secret(db, tenant_id, credential_id) if credential_id else {}
        try:
            result = connector_registry.get(connector.type.value).test_connection(connector.config, credentials)
        except Exception:
            logger.exception(
                "SOAR connector connection test failed",
                extra={"connector_id": connector.id, "connector_type": connector.type.value},
            )
            raise
        return {"success": result.success, "message": result.message, "status_code": result.status_code, "response": result.response}

    def create_execution(
        self,
        db: Session,
        tenant_id: str,
        user_id: Optional[str],
        data: ConnectorExecutionCreate,
        playbook_execution_id: Optional[str] = None,
        playbook_step_id: Optional[str] = None,
        enqueue: bool = True,
    ) -> ConnectorActionExecution:
        connector = self.get_connector(db, tenant_id, data.connector_id)
        if connector.status != ConnectorStatus.ACTIVE:
            raise ValueError("Connector is not active")
        if data.credential_id:
            credential = self.get_credential(db, tenant_id, data.credential_id)
            if credential.connector_id != connector.id or credential.status != CredentialStatus.ACTIVE:
                raise ValueError("Credential is not active for this connector")
        max_attempts = max(1, int((data.retry_policy or {}).get("max_attempts", 1)))
        execution = ConnectorActionExecution(
            tenant_id=tenant_id,
            connector_id=connector.id,
            credential_id=data.credential_id,
            playbook_execution_id=playbook_execution_id,
            playbook_step_id=playbook_step_id,
            action_name=data.action_name,
            request=self._redact(data.request),
            status=ActionExecutionStatus.QUEUED,
            retry_policy=data.retry_policy,
            max_attempts=max_attempts,
            timeout_seconds=data.timeout_seconds,
            correlation_id=secrets.token_hex(16),
            request_id=request_id_ctx.get(),
            requested_by=user_id,
        )
        db.add(execution)
        db.flush()
        if self._requires_approval(connector, data):
            execution.status = ActionExecutionStatus.AWAITING_APPROVAL
            self._create_approvals(db, execution, connector, data, user_id)
            self._log(db, execution, "info", "SOAR action awaiting approval")
        else:
            self._log(db, execution, "info", "SOAR action queued")
        db.commit()
        db.refresh(execution)
        if enqueue and execution.status == ActionExecutionStatus.QUEUED:
            if self._run_inline():
                execution = self.execute_pending(db, execution.id, worker_id="inline")
            else:
                try:
                    self.enqueue_execution(execution.id)
                except Exception:
                    execution.status = ActionExecutionStatus.FAILED
                    execution.error = "Failed to enqueue connector action"
                    execution.completed_at = self._utcnow()
                    self._log(db, execution, "error", "SOAR action enqueue failed")
                    db.commit()
                    db.refresh(execution)
        return execution

    def enqueue_execution(self, execution_id: str) -> None:
        from src.workers.tasks import execute_connector_action

        try:
            execute_connector_action.apply_async(args=[execution_id])
        except Exception:
            logger.exception("Failed to enqueue SOAR connector action", extra={"execution_id": execution_id})
            raise

    def execute_pending(self, db: Session, execution_id: str, worker_id: Optional[str] = None) -> ConnectorActionExecution:
        execution = db.query(ConnectorActionExecution).filter(ConnectorActionExecution.id == execution_id).first()
        if not execution:
            raise ValueError("Execution not found")
        if execution.status == ActionExecutionStatus.CANCELLED:
            return execution
        if execution.status != ActionExecutionStatus.QUEUED:
            raise ValueError("Execution is not queued")
        connector = execution.connector
        credentials = self._credential_secret(db, execution.tenant_id, execution.credential_id) if execution.credential_id else {}
        payload = dict(execution.request or {})
        retry_policy = execution.retry_policy or {}
        backoff = float(retry_policy.get("backoff_seconds", 0))
        exponential = bool(retry_policy.get("exponential_backoff", True))
        last_error = None

        for attempt in range(execution.attempts + 1, execution.max_attempts + 1):
            started = time.perf_counter()
            execution.attempts = attempt
            execution.status = ActionExecutionStatus.RUNNING
            execution.started_at = execution.started_at or self._utcnow()
            execution.worker_id = worker_id
            self._log(db, execution, "info", "SOAR action attempt started", {"attempt": attempt})
            db.commit()
            try:
                request = ConnectorRequest(
                    action=execution.action_name,
                    payload=payload,
                    config=connector.config or {},
                    credentials=credentials,
                    timeout_seconds=execution.timeout_seconds or 30,
                    correlation_id=execution.correlation_id,
                )
                result = connector_registry.get(connector.type.value).execute(request)
                duration = int((time.perf_counter() - started) * 1000)
                execution.duration_ms = duration
                execution.completed_at = self._utcnow()
                execution.response = self._redact(result.response)
                if result.success:
                    execution.status = ActionExecutionStatus.COMPLETED
                    self._log(db, execution, "info", "SOAR action completed", {"duration_ms": duration})
                    CONNECTOR_EXECUTIONS.labels(connector.type.value, "completed").inc()
                    CONNECTOR_EXECUTION_DURATION.labels(connector.type.value, "completed").observe(duration / 1000)
                    db.commit()
                    db.refresh(execution)
                    return execution
                raise ValueError(result.message or "Connector returned failure")
            except TimeoutError as exc:
                CONNECTOR_TIMEOUTS.labels(connector.type.value).inc()
                logger.exception(
                    "SOAR connector execution timed out",
                    extra={
                        "execution_id": execution.id,
                        "connector_id": connector.id,
                        "connector_type": connector.type.value,
                        "attempt": attempt,
                    },
                )
                last_error = exc
            except Exception as exc:
                logger.exception(
                    "SOAR connector execution attempt failed",
                    extra={
                        "execution_id": execution.id,
                        "connector_id": connector.id,
                        "connector_type": connector.type.value,
                        "attempt": attempt,
                    },
                )
                last_error = exc
            execution.error = str(last_error)
            self._log(db, execution, "warning", "SOAR action attempt failed", {"attempt": attempt, "error": str(last_error)})
            CONNECTOR_RETRIES.labels(connector.type.value).inc()
            db.commit()
            if attempt < execution.max_attempts and backoff > 0:
                time.sleep(backoff * (2 ** (attempt - 1) if exponential else 1))

        execution.status = ActionExecutionStatus.FAILED
        execution.completed_at = self._utcnow()
        execution.error = str(last_error) if last_error else "Action failed"
        CONNECTOR_FAILURES.labels(connector.type.value, "execution_error").inc()
        CONNECTOR_EXECUTIONS.labels(connector.type.value, "failed").inc()
        CONNECTOR_EXECUTION_DURATION.labels(connector.type.value, "failed").observe((execution.duration_ms or 0) / 1000)
        self._log(db, execution, "error", "SOAR action failed", {"error": execution.error})
        db.commit()
        db.refresh(execution)
        return execution

    def approve_execution(self, db: Session, tenant_id: str, approval_id: str, user: User, comment: Optional[str] = None) -> SOARActionApproval:
        approval = self._require_approval(db, tenant_id, approval_id)
        if approval.status != SOARApprovalStatus.PENDING:
            raise ValueError("Approval has already been decided")
        if approval.required_role and not self._role_allows(user.role, approval.required_role):
            raise ValueError("Approver role is not sufficient")
        approval.status = SOARApprovalStatus.APPROVED
        approval.decided_by = user.id
        approval.decision_comment = comment
        approval.decided_at = self._utcnow()
        CONNECTOR_APPROVAL_LATENCY.labels("approved").observe(
            (ensure_utc(approval.decided_at) - ensure_utc(approval.created_at)).total_seconds()
        )
        execution = approval.execution
        execution.approved_by = user.id
        if all(item.status == SOARApprovalStatus.APPROVED for item in execution.approvals):
            execution.status = ActionExecutionStatus.QUEUED
            self._log(db, execution, "info", "SOAR action approval complete")
            db.commit()
            if self._run_inline():
                self.execute_pending(db, execution.id, worker_id="inline")
            else:
                try:
                    self.enqueue_execution(execution.id)
                except Exception:
                    execution.status = ActionExecutionStatus.FAILED
                    execution.error = "Failed to enqueue connector action after approval"
                    execution.completed_at = self._utcnow()
                    self._log(db, execution, "error", "SOAR action enqueue failed after approval")
                    db.commit()
        else:
            db.commit()
        db.refresh(approval)
        return approval

    def reject_execution(self, db: Session, tenant_id: str, approval_id: str, user: User, comment: Optional[str] = None) -> SOARActionApproval:
        approval = self._require_approval(db, tenant_id, approval_id)
        if approval.status != SOARApprovalStatus.PENDING:
            raise ValueError("Approval has already been decided")
        approval.status = SOARApprovalStatus.REJECTED
        approval.decided_by = user.id
        approval.decision_comment = comment
        approval.decided_at = self._utcnow()
        approval.execution.status = ActionExecutionStatus.FAILED
        approval.execution.error = "Approval rejected"
        approval.execution.completed_at = self._utcnow()
        self._log(db, approval.execution, "warning", "SOAR action approval rejected", {"approver": user.id})
        CONNECTOR_APPROVAL_LATENCY.labels("rejected").observe(
            (ensure_utc(approval.decided_at) - ensure_utc(approval.created_at)).total_seconds()
        )
        db.commit()
        db.refresh(approval)
        return approval

    def list_executions(self, db: Session, tenant_id: str, connector_id: Optional[str] = None) -> list[ConnectorActionExecution]:
        query = db.query(ConnectorActionExecution).filter(ConnectorActionExecution.tenant_id == tenant_id)
        if connector_id:
            query = query.filter(ConnectorActionExecution.connector_id == connector_id)
        return query.order_by(ConnectorActionExecution.created_at.desc()).limit(500).all()

    def get_execution(self, db: Session, tenant_id: str, execution_id: str) -> ConnectorActionExecution:
        execution = db.query(ConnectorActionExecution).filter(
            ConnectorActionExecution.id == execution_id,
            ConnectorActionExecution.tenant_id == tenant_id,
        ).first()
        if not execution:
            raise ValueError("Execution not found")
        return execution

    def list_approvals(self, db: Session, tenant_id: str) -> list[SOARActionApproval]:
        return db.query(SOARActionApproval).filter(SOARActionApproval.tenant_id == tenant_id).order_by(SOARActionApproval.created_at.desc()).all()

    def list_logs(self, db: Session, tenant_id: str, execution_id: str) -> list[ConnectorActionLog]:
        self.get_execution(db, tenant_id, execution_id)
        return db.query(ConnectorActionLog).filter(ConnectorActionLog.execution_id == execution_id).order_by(ConnectorActionLog.created_at.asc()).all()

    def _credential_secret(self, db: Session, tenant_id: str, credential_id: str) -> dict[str, Any]:
        credential = self.get_credential(db, tenant_id, credential_id)
        return decrypt_json_secret(credential.encrypted_secret)

    def _requires_approval(self, connector: ActionConnector, data: ConnectorExecutionCreate) -> bool:
        return bool(data.requires_approval if data.requires_approval is not None else connector.requires_approval)

    def _create_approvals(
        self,
        db: Session,
        execution: ConnectorActionExecution,
        connector: ActionConnector,
        data: ConnectorExecutionCreate,
        user_id: Optional[str],
    ) -> None:
        roles = data.approval_roles or [UserRole(role) for role in (connector.approval_roles or [])] or [UserRole.ADMIN]
        timeout_minutes = int((data.retry_policy or {}).get("approval_timeout_minutes", 60))
        expires_at = self._utcnow() + timedelta(minutes=timeout_minutes)
        for role in roles:
            db.add(
                SOARActionApproval(
                    tenant_id=execution.tenant_id,
                    execution_id=execution.id,
                    required_role=role,
                    requested_by=user_id,
                    expires_at=expires_at,
                )
            )

    def _require_approval(self, db: Session, tenant_id: str, approval_id: str) -> SOARActionApproval:
        approval = db.query(SOARActionApproval).filter(
            SOARActionApproval.id == approval_id,
            SOARActionApproval.tenant_id == tenant_id,
        ).first()
        if not approval:
            raise ValueError("Approval not found")
        return approval

    def _role_allows(self, actual: UserRole, required: UserRole) -> bool:
        order = {UserRole.VIEWER: 0, UserRole.RESPONDER: 1, UserRole.ANALYST: 2, UserRole.ADMIN: 3}
        return order[actual] >= order[required]

    def _log(self, db: Session, execution: ConnectorActionExecution, level: str, message: str, data: Optional[dict[str, Any]] = None) -> None:
        db.add(
            ConnectorActionLog(
                tenant_id=execution.tenant_id,
                execution_id=execution.id,
                level=level,
                message=message,
                data=data,
            )
        )

    def _redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: ("[REDACTED]" if key.lower() in SENSITIVE_KEYS else self._redact(item))
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        return value

    def _utcnow(self) -> datetime:
        return datetime.now(timezone.utc)

    def _run_inline(self) -> bool:
        settings = get_settings()
        return settings.SOAR_TASK_ALWAYS_EAGER or settings.USE_REDIS_MOCK


soar_action_service = SOARActionService()
