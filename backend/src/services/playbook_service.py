from __future__ import annotations

import ast
import operator
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import httpx
from sqlalchemy import func
from sqlalchemy.orm import Session

from src.core.logging import logger
from src.models.pydantic import (
    PlaybookCreate,
    PlaybookStepCreate,
    PlaybookStepDefinition,
    PlaybookUpdate,
    PlaybookVariableCreate,
    PlaybookVariableUpdate,
    PlaybookVersionCreate,
)
from src.models.sqlalchemy import (
    ActionStatus,
    ActionType,
    Alert,
    Incident,
    IncidentPriority,
    IncidentStatus,
    Playbook,
    PlaybookApproval,
    PlaybookApprovalStatus,
    PlaybookExecution,
    PlaybookExecutionStatus,
    PlaybookExecutionStep,
    PlaybookRunLog,
    PlaybookStatus,
    PlaybookStep,
    PlaybookStepStatus,
    PlaybookStepType,
    PlaybookTriggerType,
    PlaybookVariable,
    PlaybookVersion,
    ResponseAction,
    Severity,
)
from src.services.ai_service import ai_service
from src.services.notification_service import notification_service
from src.services.soar_action_service import soar_action_service
from src.services.threat_intel_service import threat_intel_service


class PlaybookExecutionError(Exception):
    """Raised when a playbook step fails after retry handling."""


class SafeExpressionEvaluator:
    """Evaluate simple boolean/value expressions without arbitrary code execution."""

    _operators: dict[type[ast.AST], Callable[[Any, Any], Any]] = {
        ast.Eq: operator.eq,
        ast.NotEq: operator.ne,
        ast.Gt: operator.gt,
        ast.GtE: operator.ge,
        ast.Lt: operator.lt,
        ast.LtE: operator.le,
        ast.In: lambda a, b: a in b,
        ast.NotIn: lambda a, b: a not in b,
        ast.And: lambda a, b: bool(a) and bool(b),
        ast.Or: lambda a, b: bool(a) or bool(b),
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
    }

    def evaluate(self, expression: str, context: dict[str, Any]) -> Any:
        tree = ast.parse(expression, mode="eval")
        return self._eval_node(tree.body, context)

    def _eval_node(self, node: ast.AST, context: dict[str, Any]) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id not in context:
                raise ValueError(f"Unknown variable '{node.id}'")
            return context[node.id]
        if isinstance(node, ast.Subscript):
            value = self._eval_node(node.value, context)
            key = self._eval_node(node.slice, context)
            return value[key]
        if isinstance(node, ast.Attribute):
            value = self._eval_node(node.value, context)
            if isinstance(value, dict):
                return value.get(node.attr)
            return getattr(value, node.attr)
        if isinstance(node, ast.BoolOp):
            result = self._eval_node(node.values[0], context)
            for value in node.values[1:]:
                result = self._operators[type(node.op)](result, self._eval_node(value, context))
            return result
        if isinstance(node, ast.Compare):
            left = self._eval_node(node.left, context)
            for op, comparator in zip(node.ops, node.comparators):
                right = self._eval_node(comparator, context)
                if not self._operators[type(op)](left, right):
                    return False
                left = right
            return True
        if isinstance(node, ast.BinOp):
            return self._operators[type(node.op)](
                self._eval_node(node.left, context),
                self._eval_node(node.right, context),
            )
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not self._eval_node(node.operand, context)
        if isinstance(node, ast.List):
            return [self._eval_node(item, context) for item in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(self._eval_node(item, context) for item in node.elts)
        if isinstance(node, ast.Dict):
            return {
                self._eval_node(key, context): self._eval_node(value, context)
                for key, value in zip(node.keys, node.values)
            }
        raise ValueError(f"Unsupported expression element: {type(node).__name__}")


class PlaybookService:
    def __init__(self) -> None:
        self.expression_evaluator = SafeExpressionEvaluator()

    def list_playbooks(
        self,
        db: Session,
        tenant_id: str,
        status: Optional[PlaybookStatus] = None,
        trigger_type: Optional[PlaybookTriggerType] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Playbook]:
        query = db.query(Playbook).filter(Playbook.tenant_id == tenant_id)
        if status:
            query = query.filter(Playbook.status == status)
        if trigger_type:
            query = query.filter(Playbook.trigger_type == trigger_type)
        playbooks = query.order_by(Playbook.updated_at.desc()).offset(offset).limit(min(limit, 500)).all()
        return [self._normalize_playbook_defaults(playbook) for playbook in playbooks]

    def get_playbook(self, db: Session, tenant_id: str, playbook_id: str) -> Optional[Playbook]:
        playbook = db.query(Playbook).filter(
            Playbook.id == playbook_id,
            Playbook.tenant_id == tenant_id,
        ).first()
        return self._normalize_playbook_defaults(playbook) if playbook else None

    def create_playbook(
        self,
        db: Session,
        tenant_id: str,
        user_id: str,
        playbook_data: PlaybookCreate,
    ) -> Playbook:
        playbook = Playbook(
            tenant_id=tenant_id,
            name=playbook_data.name,
            description=playbook_data.description,
            status=PlaybookStatus.DRAFT,
            trigger_type=playbook_data.trigger_type,
            trigger_conditions=playbook_data.trigger_conditions,
            created_by=user_id,
        )
        db.add(playbook)
        db.flush()
        version = self._create_version_record(
            db,
            playbook=playbook,
            tenant_id=tenant_id,
            user_id=user_id,
            version_data=PlaybookVersionCreate(steps=playbook_data.steps, changelog=playbook_data.changelog),
        )
        playbook.active_version_id = version.id
        db.commit()
        db.refresh(playbook)
        return playbook

    def update_playbook(
        self,
        db: Session,
        tenant_id: str,
        playbook_id: str,
        update_data: PlaybookUpdate,
    ) -> Playbook:
        playbook = self._require_playbook(db, tenant_id, playbook_id)
        for field in ("name", "description", "status", "trigger_type", "trigger_conditions"):
            value = getattr(update_data, field)
            if value is not None:
                setattr(playbook, field, value)
        db.commit()
        db.refresh(playbook)
        return playbook

    def delete_playbook(self, db: Session, tenant_id: str, playbook_id: str) -> None:
        playbook = self._require_playbook(db, tenant_id, playbook_id)
        playbook.status = PlaybookStatus.ARCHIVED
        db.commit()

    def activate_playbook(self, db: Session, tenant_id: str, playbook_id: str) -> Playbook:
        playbook = self._require_playbook(db, tenant_id, playbook_id)
        if not playbook.active_version_id:
            raise ValueError("Playbook has no version to activate")
        playbook.status = PlaybookStatus.ACTIVE
        db.commit()
        db.refresh(playbook)
        return playbook

    def deactivate_playbook(self, db: Session, tenant_id: str, playbook_id: str) -> Playbook:
        playbook = self._require_playbook(db, tenant_id, playbook_id)
        playbook.status = PlaybookStatus.DISABLED
        db.commit()
        db.refresh(playbook)
        return playbook

    def create_version(
        self,
        db: Session,
        tenant_id: str,
        user_id: str,
        playbook_id: str,
        version_data: PlaybookVersionCreate,
    ) -> PlaybookVersion:
        playbook = self._require_playbook(db, tenant_id, playbook_id)
        version = self._create_version_record(db, playbook, tenant_id, user_id, version_data)
        db.commit()
        db.refresh(version)
        return version

    def list_versions(self, db: Session, tenant_id: str, playbook_id: str) -> list[PlaybookVersion]:
        self._require_playbook(db, tenant_id, playbook_id)
        return db.query(PlaybookVersion).filter(
            PlaybookVersion.tenant_id == tenant_id,
            PlaybookVersion.playbook_id == playbook_id,
        ).order_by(PlaybookVersion.version_number.desc()).all()

    def publish_version(
        self,
        db: Session,
        tenant_id: str,
        playbook_id: str,
        version_id: str,
        user_id: str,
    ) -> PlaybookVersion:
        playbook = self._require_playbook(db, tenant_id, playbook_id)
        version = db.query(PlaybookVersion).filter(
            PlaybookVersion.id == version_id,
            PlaybookVersion.tenant_id == tenant_id,
            PlaybookVersion.playbook_id == playbook_id,
        ).first()
        if not version:
            raise ValueError("Playbook version not found")
        version.status = PlaybookStatus.ACTIVE
        version.published_by = user_id
        version.published_at = self._utcnow()
        playbook.active_version_id = version.id
        db.commit()
        db.refresh(version)
        return version

    def add_step(
        self,
        db: Session,
        tenant_id: str,
        playbook_id: str,
        step_data: PlaybookStepCreate,
    ) -> PlaybookStep:
        playbook = self._require_playbook(db, tenant_id, playbook_id)
        last_step = db.query(PlaybookStep).filter(
            PlaybookStep.playbook_id == playbook_id,
        ).order_by(PlaybookStep.order.desc()).first()
        next_order = (last_step.order + 1) if last_step else 0
        step = PlaybookStep(
            playbook_id=playbook_id,
            name=step_data.name,
            type=step_data.type,
            order=next_order,
            config=step_data.config,
        )
        db.add(step)
        self._append_step_to_active_definition(playbook, step_data, next_order)
        db.commit()
        db.refresh(step)
        return step

    def get_steps(self, db: Session, playbook_id: str) -> list[PlaybookStep]:
        return db.query(PlaybookStep).filter(PlaybookStep.playbook_id == playbook_id).order_by(PlaybookStep.order).all()

    def execute_playbook(
        self,
        db: Session,
        tenant_id: str,
        incident_id: Optional[str] = None,
        playbook_id: Optional[str] = None,
        triggered_by: Optional[str] = None,
        alert_id: Optional[str] = None,
        trigger_type: PlaybookTriggerType = PlaybookTriggerType.MANUAL_RUN,
        context: Optional[dict[str, Any]] = None,
    ) -> PlaybookExecution:
        if not playbook_id:
            raise ValueError("playbook_id is required")
        playbook = self._require_playbook(db, tenant_id, playbook_id)
        version = self._resolve_execution_version(db, playbook)
        execution = PlaybookExecution(
            tenant_id=tenant_id,
            incident_id=incident_id,
            alert_id=alert_id,
            playbook_id=playbook.id,
            version_id=version.id if version else None,
            trigger_type=trigger_type,
            status=PlaybookExecutionStatus.PENDING,
            triggered_by=triggered_by,
            context=context or {},
        )
        db.add(execution)
        db.flush()
        self._materialize_execution_steps(db, execution, version)
        self._log(db, execution, None, "info", "Playbook execution created", {"playbook_id": playbook.id})
        db.commit()
        db.refresh(execution)
        self._run_execution(db, execution)
        db.refresh(execution)
        return execution

    def pause_execution(self, db: Session, tenant_id: str, execution_id: str) -> PlaybookExecution:
        execution = self._require_execution(db, tenant_id, execution_id)
        if execution.status not in {PlaybookExecutionStatus.RUNNING, PlaybookExecutionStatus.PENDING}:
            raise ValueError("Only pending or running executions can be paused")
        execution.status = PlaybookExecutionStatus.PAUSED
        execution.paused_at = self._utcnow()
        self._log(db, execution, None, "info", "Playbook execution paused")
        db.commit()
        db.refresh(execution)
        return execution

    def resume_execution(self, db: Session, tenant_id: str, execution_id: str) -> PlaybookExecution:
        execution = self._require_execution(db, tenant_id, execution_id)
        if execution.status not in {PlaybookExecutionStatus.PAUSED, PlaybookExecutionStatus.AWAITING_APPROVAL}:
            raise ValueError("Execution is not resumable")
        execution.paused_at = None
        execution.status = PlaybookExecutionStatus.RUNNING
        self._log(db, execution, None, "info", "Playbook execution resumed")
        db.commit()
        self._run_execution(db, execution)
        db.refresh(execution)
        return execution

    def cancel_execution(self, db: Session, tenant_id: str, execution_id: str) -> PlaybookExecution:
        execution = self._require_execution(db, tenant_id, execution_id)
        if execution.status in {PlaybookExecutionStatus.COMPLETED, PlaybookExecutionStatus.FAILED, PlaybookExecutionStatus.CANCELLED}:
            raise ValueError("Execution is already terminal")
        now = self._utcnow()
        execution.status = PlaybookExecutionStatus.CANCELLED
        execution.cancelled_at = now
        execution.completed_at = now
        for step in execution.steps:
            if step.status in {PlaybookStepStatus.PENDING, PlaybookStepStatus.RUNNING, PlaybookStepStatus.AWAITING_APPROVAL}:
                step.status = PlaybookStepStatus.CANCELLED
                step.completed_at = now
        self._log(db, execution, None, "info", "Playbook execution cancelled")
        db.commit()
        db.refresh(execution)
        return execution

    def approve_execution(
        self,
        db: Session,
        tenant_id: str,
        execution_id: str,
        user_id: str,
        comment: Optional[str] = None,
    ) -> PlaybookExecution:
        execution = self._require_execution(db, tenant_id, execution_id)
        approval = self._pending_approval_for_execution(db, execution)
        if not approval:
            raise ValueError("Execution is not awaiting approval")
        self._decide_approval(db, approval, user_id, PlaybookApprovalStatus.APPROVED, comment)
        if approval.execution_step:
            approval.execution_step.status = PlaybookStepStatus.COMPLETED
            approval.execution_step.completed_at = self._utcnow()
            approval.execution_step.result = {"approved_by": user_id, "comment": comment}
        execution.status = PlaybookExecutionStatus.RUNNING
        self._log(db, execution, approval.execution_step, "info", "Playbook approval granted", {"approved_by": user_id})
        db.commit()
        self._run_execution(db, execution)
        db.refresh(execution)
        return execution

    def reject_approval(
        self,
        db: Session,
        tenant_id: str,
        approval_id: str,
        user_id: str,
        comment: Optional[str] = None,
    ) -> PlaybookApproval:
        approval = self._require_approval(db, tenant_id, approval_id)
        self._decide_approval(db, approval, user_id, PlaybookApprovalStatus.REJECTED, comment)
        if approval.execution_step:
            approval.execution_step.status = PlaybookStepStatus.FAILED
            approval.execution_step.error = "Approval rejected"
            approval.execution_step.completed_at = self._utcnow()
        approval.execution.status = PlaybookExecutionStatus.FAILED
        approval.execution.completed_at = self._utcnow()
        approval.execution.result = {"error": "Approval rejected", "approval_id": approval.id}
        self._log(db, approval.execution, approval.execution_step, "warning", "Playbook approval rejected", {"approved_by": user_id})
        db.commit()
        db.refresh(approval)
        return approval

    def approve_by_id(
        self,
        db: Session,
        tenant_id: str,
        approval_id: str,
        user_id: str,
        comment: Optional[str] = None,
    ) -> PlaybookApproval:
        approval = self._require_approval(db, tenant_id, approval_id)
        execution = self.approve_execution(db, tenant_id, approval.execution_id, user_id, comment)
        return self._require_approval(db, tenant_id, approval_id)

    def list_executions(
        self,
        db: Session,
        tenant_id: str,
        incident_id: Optional[str] = None,
        playbook_id: Optional[str] = None,
        status: Optional[PlaybookExecutionStatus] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[PlaybookExecution]:
        query = db.query(PlaybookExecution).filter(PlaybookExecution.tenant_id == tenant_id)
        if incident_id:
            query = query.filter(PlaybookExecution.incident_id == incident_id)
        if playbook_id:
            query = query.filter(PlaybookExecution.playbook_id == playbook_id)
        if status:
            query = query.filter(PlaybookExecution.status == status)
        return query.order_by(PlaybookExecution.created_at.desc()).offset(offset).limit(min(limit, 500)).all()

    def get_execution(self, db: Session, tenant_id: str, execution_id: str) -> PlaybookExecution:
        return self._require_execution(db, tenant_id, execution_id)

    def list_execution_steps(self, db: Session, tenant_id: str, execution_id: str) -> list[PlaybookExecutionStep]:
        self._require_execution(db, tenant_id, execution_id)
        return db.query(PlaybookExecutionStep).filter(
            PlaybookExecutionStep.execution_id == execution_id,
        ).order_by(PlaybookExecutionStep.order).all()

    def list_approvals(
        self,
        db: Session,
        tenant_id: str,
        execution_id: Optional[str] = None,
        status: Optional[PlaybookApprovalStatus] = None,
    ) -> list[PlaybookApproval]:
        query = db.query(PlaybookApproval).filter(PlaybookApproval.tenant_id == tenant_id)
        if execution_id:
            query = query.filter(PlaybookApproval.execution_id == execution_id)
        if status:
            query = query.filter(PlaybookApproval.status == status)
        return query.order_by(PlaybookApproval.created_at.desc()).all()

    def list_logs(self, db: Session, tenant_id: str, execution_id: str) -> list[PlaybookRunLog]:
        self._require_execution(db, tenant_id, execution_id)
        return db.query(PlaybookRunLog).filter(
            PlaybookRunLog.tenant_id == tenant_id,
            PlaybookRunLog.execution_id == execution_id,
        ).order_by(PlaybookRunLog.created_at.asc()).all()

    def list_variables(
        self,
        db: Session,
        tenant_id: str,
        playbook_id: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> list[PlaybookVariable]:
        query = db.query(PlaybookVariable).filter(PlaybookVariable.tenant_id == tenant_id)
        if playbook_id:
            query = query.filter(PlaybookVariable.playbook_id == playbook_id)
        if scope:
            query = query.filter(PlaybookVariable.scope == scope)
        return query.order_by(PlaybookVariable.key.asc()).all()

    def create_variable(
        self,
        db: Session,
        tenant_id: str,
        user_id: str,
        data: PlaybookVariableCreate,
    ) -> PlaybookVariable:
        if data.playbook_id:
            self._require_playbook(db, tenant_id, data.playbook_id)
        variable = PlaybookVariable(
            tenant_id=tenant_id,
            playbook_id=data.playbook_id,
            key=data.key,
            value=data.value,
            scope=data.scope,
            is_secret=data.is_secret,
            created_by=user_id,
            updated_by=user_id,
        )
        db.add(variable)
        db.commit()
        db.refresh(variable)
        return variable

    def update_variable(
        self,
        db: Session,
        tenant_id: str,
        variable_id: str,
        user_id: str,
        data: PlaybookVariableUpdate,
    ) -> PlaybookVariable:
        variable = self._require_variable(db, tenant_id, variable_id)
        if data.value is not None:
            variable.value = data.value
        if data.scope is not None:
            variable.scope = data.scope
        if data.is_secret is not None:
            variable.is_secret = data.is_secret
        variable.updated_by = user_id
        db.commit()
        db.refresh(variable)
        return variable

    def delete_variable(self, db: Session, tenant_id: str, variable_id: str) -> None:
        variable = self._require_variable(db, tenant_id, variable_id)
        db.delete(variable)
        db.commit()

    def _run_execution(self, db: Session, execution: PlaybookExecution) -> None:
        if execution.status == PlaybookExecutionStatus.CANCELLED:
            return
        now = self._utcnow()
        if not execution.started_at:
            execution.started_at = now
        execution.status = PlaybookExecutionStatus.RUNNING
        db.commit()

        steps = db.query(PlaybookExecutionStep).filter(
            PlaybookExecutionStep.execution_id == execution.id,
        ).order_by(PlaybookExecutionStep.order.asc()).all()
        index_by_key = {step.step_key: index for index, step in enumerate(steps)}
        index = self._next_pending_index(steps)

        while index < len(steps):
            db.refresh(execution)
            if execution.status in {PlaybookExecutionStatus.CANCELLED, PlaybookExecutionStatus.PAUSED}:
                return
            step = steps[index]
            if step.status in {PlaybookStepStatus.COMPLETED, PlaybookStepStatus.SKIPPED}:
                index += 1
                continue

            execution.current_step_key = step.step_key
            try:
                result = self._execute_step_with_retries(db, execution, step)
                db.refresh(step)
                if step.status == PlaybookStepStatus.AWAITING_APPROVAL:
                    execution.status = PlaybookExecutionStatus.AWAITING_APPROVAL
                    db.commit()
                    return
                if result.get("end_execution"):
                    break
                next_step_key = result.get("next_step_key")
                if next_step_key:
                    if next_step_key not in index_by_key:
                        raise PlaybookExecutionError(f"Branch target '{next_step_key}' was not found")
                    index = index_by_key[next_step_key]
                else:
                    index += 1
            except Exception as exc:
                execution_id = execution.id
                execution_tenant_id = execution.tenant_id
                playbook_id = execution.playbook_id
                step_id = step.id
                step_key = step.step_key
                db.rollback()
                logger.exception(
                    "Playbook execution failed",
                    extra={
                        "execution_id": execution_id,
                        "playbook_id": playbook_id,
                        "step_id": step_id,
                        "step_key": step_key,
                    },
                )
                execution = self._require_execution(db, execution_tenant_id, execution_id)
                step = db.query(PlaybookExecutionStep).filter(PlaybookExecutionStep.id == step_id).first()
                execution.status = PlaybookExecutionStatus.FAILED
                execution.completed_at = self._utcnow()
                execution.result = {"error": str(exc), "step_key": step_key}
                self._log(db, execution, step, "error", "Playbook execution failed", {"error": str(exc)})
                db.commit()
                return

        execution.status = PlaybookExecutionStatus.COMPLETED
        execution.completed_at = self._utcnow()
        execution.current_step_key = None
        execution.result = {"message": "Playbook completed successfully"}
        self._log(db, execution, None, "info", "Playbook execution completed")
        db.commit()

    def _execute_step_with_retries(
        self,
        db: Session,
        execution: PlaybookExecution,
        step: PlaybookExecutionStep,
    ) -> dict[str, Any]:
        config = step.config or {}
        retry_policy = config.get("retry_policy") or {}
        max_attempts = max(1, int(retry_policy.get("max_attempts", step.max_attempts or 1)))
        backoff_seconds = max(0, float(retry_policy.get("backoff_seconds", 0)))
        step.max_attempts = max_attempts
        last_error: Optional[Exception] = None

        for attempt in range(1, max_attempts + 1):
            start = time.perf_counter()
            step.status = PlaybookStepStatus.RUNNING
            step.started_at = self._utcnow()
            step.attempts = attempt
            step.error = None
            db.commit()
            self._log(db, execution, step, "info", "Playbook step started", {"attempt": attempt})
            try:
                result = self._dispatch_step(db, execution, step)
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                step.execution_time_ms = elapsed_ms
                if step.timeout_seconds and elapsed_ms > step.timeout_seconds * 1000:
                    raise TimeoutError(f"Step exceeded timeout of {step.timeout_seconds}s")
                if step.status != PlaybookStepStatus.AWAITING_APPROVAL:
                    step.status = PlaybookStepStatus.COMPLETED
                    step.completed_at = self._utcnow()
                    step.result = result
                self._log(db, execution, step, "info", "Playbook step finished", {"execution_time_ms": elapsed_ms})
                db.commit()
                return result
            except Exception as exc:
                execution_id = execution.id
                execution_tenant_id = execution.tenant_id
                playbook_id = execution.playbook_id
                step_id = step.id
                step_key = step.step_key
                db.rollback()
                logger.exception(
                    "Playbook step attempt failed",
                    extra={
                        "execution_id": execution_id,
                        "playbook_id": playbook_id,
                        "step_id": step_id,
                        "step_key": step_key,
                        "attempt": attempt,
                    },
                )
                execution = self._require_execution(db, execution_tenant_id, execution_id)
                step = db.query(PlaybookExecutionStep).filter(PlaybookExecutionStep.id == step_id).first()
                if step is None:
                    raise PlaybookExecutionError(f"Step '{step_key}' was not found") from exc
                last_error = exc
                step.status = PlaybookStepStatus.FAILED
                step.error = str(exc)
                step.completed_at = self._utcnow()
                step.execution_time_ms = int((time.perf_counter() - start) * 1000)
                self._log(db, execution, step, "warning", "Playbook step attempt failed", {"attempt": attempt, "error": str(exc)})
                db.commit()
                if attempt < max_attempts and backoff_seconds:
                    time.sleep(backoff_seconds)

        raise PlaybookExecutionError(str(last_error) if last_error else "Step failed")

    def _dispatch_step(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        handlers: dict[PlaybookStepType, Callable[[Session, PlaybookExecution, PlaybookExecutionStep], dict[str, Any]]] = {
            PlaybookStepType.ACTION: self._handle_action,
            PlaybookStepType.CONDITION: self._handle_condition,
            PlaybookStepType.DELAY: self._handle_delay,
            PlaybookStepType.APPROVAL: self._handle_approval,
            PlaybookStepType.NOTIFICATION: self._handle_notification,
            PlaybookStepType.AI_ANALYSIS: self._handle_ai_analysis,
            PlaybookStepType.THREAT_INTEL_LOOKUP: self._handle_threat_intel_lookup,
            PlaybookStepType.HTTP_REQUEST: self._handle_http_request,
            PlaybookStepType.WEBHOOK: self._handle_http_request,
            PlaybookStepType.PYTHON_SCRIPT: self._handle_python_expression,
            PlaybookStepType.CREATE_INCIDENT: self._handle_create_incident,
            PlaybookStepType.UPDATE_INCIDENT: self._handle_update_incident,
            PlaybookStepType.CLOSE_INCIDENT: self._handle_close_incident,
            PlaybookStepType.TAG_ALERT: self._handle_tag_alert,
            PlaybookStepType.ASSIGN_ANALYST: self._handle_assign_analyst,
            PlaybookStepType.CREATE_TASK: self._handle_create_task,
            PlaybookStepType.BRANCH: self._handle_branch,
            PlaybookStepType.END: self._handle_end,
        }
        handler = handlers.get(step.type)
        if not handler:
            raise ValueError(f"Unsupported playbook step type: {step.type}")
        return handler(db, execution, step)

    def _handle_condition(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        config = step.config or {}
        matched = self._evaluate_condition(config, self._execution_context(db, execution))
        return {
            "matched": matched,
            "next_step_key": config.get("if_true") if matched else config.get("if_false"),
        }

    def _handle_branch(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        config = step.config or {}
        context = self._execution_context(db, execution)
        for branch in config.get("branches", []):
            if self._evaluate_condition(branch.get("condition", {}), context):
                return {"matched_branch": branch.get("name"), "next_step_key": branch.get("next_step_key")}
        return {"matched_branch": None, "next_step_key": config.get("default_step_key")}

    def _handle_delay(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        seconds = float((step.config or {}).get("seconds", 0))
        if seconds < 0 or seconds > 3600:
            raise ValueError("Delay seconds must be between 0 and 3600")
        time.sleep(seconds)
        return {"delayed_seconds": seconds}

    def _handle_approval(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        approval = PlaybookApproval(
            tenant_id=execution.tenant_id,
            execution_id=execution.id,
            execution_step_id=step.id,
            requested_by=execution.triggered_by,
            status=PlaybookApprovalStatus.PENDING,
            message=(step.config or {}).get("message", f"Approval required for {step.name}"),
        )
        db.add(approval)
        step.status = PlaybookStepStatus.AWAITING_APPROVAL
        execution.status = PlaybookExecutionStatus.AWAITING_APPROVAL
        self._log(db, execution, step, "info", "Playbook approval requested", {"approval_id": approval.id})
        db.commit()
        return {"approval_id": approval.id}

    def _handle_notification(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        config = step.config or {}
        user_id = config.get("user_id") or execution.triggered_by
        title = config.get("title") or f"Playbook notification: {step.name}"
        message = config.get("message")
        if user_id:
            notification = notification_service.create_notification(db, execution.tenant_id, user_id, title, message)
            return {"notification_id": notification.id, "user_id": user_id}
        return {"delivered": False, "reason": "No notification user configured"}

    def _handle_ai_analysis(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        incident = self._require_incident(db, execution)
        alerts = [link.alert for link in incident.incident_alerts]
        analysis = ai_service.analyze_incident(incident, alerts, [], incident.threat_intel_results or [])
        incident.ai_summary = analysis.get("summary")
        incident.why_suspicious = analysis.get("why_suspicious")
        incident.attack_technique = analysis.get("attack_technique")
        incident.recommended_actions = analysis.get("recommended_actions")
        incident.ai_analyzed_at = self._utcnow()
        db.commit()
        return {"analysis": analysis}

    def _handle_threat_intel_lookup(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        incident = self._require_incident(db, execution)
        alerts = [link.alert for link in incident.incident_alerts]
        findings = threat_intel_service.lookup_incident_indicators(db, alerts)
        threat_intel_service.persist_incident_results(db, execution.tenant_id, incident.id, findings)
        incident.threat_intel_results = findings
        db.commit()
        return {"findings_count": len(findings), "findings": findings}

    def _handle_http_request(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        config = step.config or {}
        url = config.get("url")
        if not url:
            raise ValueError("HTTP request step requires a url")
        method = str(config.get("method", "POST")).upper()
        timeout = step.timeout_seconds or int(config.get("timeout_seconds", 30))
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.request(
                    method,
                    url,
                    headers=config.get("headers"),
                    json=config.get("json"),
                    data=config.get("body"),
                )
        except Exception:
            logger.exception(
                "Playbook HTTP request step failed",
                extra={
                    "execution_id": execution.id,
                    "playbook_id": execution.playbook_id,
                    "step_id": step.id,
                    "step_key": step.step_key,
                    "method": method,
                },
            )
            raise
        if response.status_code >= 400:
            raise ValueError(f"HTTP request failed with status {response.status_code}")
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:5000],
        }

    def _handle_python_expression(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        expression = (step.config or {}).get("expression")
        if not expression:
            raise ValueError("Python script step requires a safe expression")
        result = self.expression_evaluator.evaluate(expression, self._execution_context(db, execution))
        return {"result": result}

    def _handle_create_incident(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        config = step.config or {}
        incident = Incident(
            tenant_id=execution.tenant_id,
            title=config.get("title") or "Playbook-created incident",
            description=config.get("description"),
            severity=Severity(config.get("severity", Severity.MEDIUM.value)),
            priority=IncidentPriority(config.get("priority", IncidentPriority.P3.value)),
            status=IncidentStatus.OPEN,
            assigned_to=config.get("assigned_to"),
            creation_source="playbook",
            provenance_status="recorded",
            creation_reason=f"Created by playbook execution {execution.id}.",
        )
        db.add(incident)
        db.flush()
        execution.incident_id = execution.incident_id or incident.id
        return {"incident_id": incident.id}

    def _handle_update_incident(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        incident = self._require_incident(db, execution)
        config = step.config or {}
        allowed = {"title", "description", "assigned_to"}
        for field in allowed:
            if field in config:
                setattr(incident, field, config[field])
        if "status" in config:
            incident.status = IncidentStatus(config["status"])
        if "priority" in config:
            incident.priority = IncidentPriority(config["priority"])
        if "severity" in config:
            incident.severity = Severity(config["severity"])
        incident.updated_at = self._utcnow()
        return {"incident_id": incident.id, "updated_fields": sorted(config.keys())}

    def _handle_close_incident(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        incident = self._require_incident(db, execution)
        incident.status = IncidentStatus.CLOSED
        incident.resolved_at = incident.resolved_at or self._utcnow()
        incident.updated_at = self._utcnow()
        return {"incident_id": incident.id, "status": incident.status.value}

    def _handle_tag_alert(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        alert_id = (step.config or {}).get("alert_id") or execution.alert_id
        tag = (step.config or {}).get("tag")
        if not alert_id or not tag:
            raise ValueError("Tag alert step requires alert_id or execution alert_id and tag")
        alert = db.query(Alert).filter(Alert.id == alert_id, Alert.tenant_id == execution.tenant_id).first()
        if not alert:
            raise ValueError("Alert not found")
        raw_data = dict(alert.raw_data or {})
        tags = list(raw_data.get("tags") or [])
        if tag not in tags:
            tags.append(tag)
        raw_data["tags"] = tags
        alert.raw_data = raw_data
        return {"alert_id": alert.id, "tags": tags}

    def _handle_assign_analyst(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        incident = self._require_incident(db, execution)
        assignee_id = (step.config or {}).get("user_id")
        if not assignee_id:
            raise ValueError("Assign analyst step requires user_id")
        incident.assigned_to = assignee_id
        incident.assigned_at = self._utcnow()
        incident.updated_at = self._utcnow()
        return {"incident_id": incident.id, "assigned_to": assignee_id}

    def _handle_create_task(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        incident = self._require_incident(db, execution)
        action = ResponseAction(
            tenant_id=execution.tenant_id,
            incident_id=incident.id,
            action_type=ActionType.CREATE_TASK,
            status=ActionStatus.PENDING,
            executed_by=execution.triggered_by,
            details=step.config or {},
        )
        db.add(action)
        db.flush()
        return {"task_id": action.id, "incident_id": incident.id}

    def _handle_action(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        config = step.config or {}
        if config.get("connector_id"):
            from src.models.pydantic import ConnectorExecutionCreate

            action_execution = soar_action_service.create_execution(
                db,
                tenant_id=execution.tenant_id,
                user_id=execution.triggered_by,
                data=ConnectorExecutionCreate(
                    connector_id=config["connector_id"],
                    credential_id=config.get("credential_id"),
                    action_name=config.get("action_name") or step.name,
                    request=config.get("request") or config.get("payload") or {},
                    retry_policy=config.get("retry_policy") or {},
                    timeout_seconds=step.timeout_seconds or config.get("timeout_seconds") or 30,
                    requires_approval=config.get("requires_approval"),
                    approval_roles=config.get("approval_roles"),
                ),
                playbook_execution_id=execution.id,
                playbook_step_id=step.id,
            )
            return {"connector_action_execution_id": action_execution.id, "status": action_execution.status.value}

        action_type = ActionType(config.get("action_type", ActionType.ESCALATE_INCIDENT.value))
        incident = self._require_incident(db, execution)
        action = ResponseAction(
            tenant_id=execution.tenant_id,
            incident_id=incident.id,
            action_type=action_type,
            status=ActionStatus.COMPLETED,
            executed_by=execution.triggered_by,
            details=config.get("details") or config,
        )
        db.add(action)
        db.flush()
        return {"response_action_id": action.id, "action_type": action_type.value}

    def _handle_end(self, db: Session, execution: PlaybookExecution, step: PlaybookExecutionStep) -> dict[str, Any]:
        return {"end_execution": True}

    def _create_version_record(
        self,
        db: Session,
        playbook: Playbook,
        tenant_id: str,
        user_id: str,
        version_data: PlaybookVersionCreate,
    ) -> PlaybookVersion:
        max_version = db.query(func.max(PlaybookVersion.version_number)).filter(
            PlaybookVersion.playbook_id == playbook.id,
        ).scalar() or 0
        version = PlaybookVersion(
            playbook_id=playbook.id,
            tenant_id=tenant_id,
            version_number=max_version + 1,
            status=PlaybookStatus.DRAFT,
            definition={"steps": [self._serialize_step_definition(step, idx) for idx, step in enumerate(version_data.steps)]},
            changelog=version_data.changelog,
            created_by=user_id,
        )
        db.add(version)
        return version

    def _append_step_to_active_definition(self, playbook: Playbook, step_data: PlaybookStepCreate, order: int) -> None:
        version = playbook.active_version
        if not version:
            return
        definition = dict(version.definition or {})
        steps = list(definition.get("steps") or [])
        steps.append(
            self._serialize_step_definition(
                PlaybookStepDefinition(
                    step_key=f"step_{order + 1}",
                    name=step_data.name,
                    type=step_data.type,
                    config=step_data.config,
                    timeout_seconds=step_data.timeout_seconds,
                    retry_policy=step_data.retry_policy,
                ),
                order,
            )
        )
        definition["steps"] = steps
        version.definition = definition

    def _serialize_step_definition(self, step: PlaybookStepDefinition, index: int) -> dict[str, Any]:
        config = dict(step.config or {})
        if step.retry_policy:
            config["retry_policy"] = step.retry_policy
        return {
            "step_key": step.step_key or f"step_{index + 1}",
            "name": step.name,
            "type": step.type.value if hasattr(step.type, "value") else step.type,
            "order": index,
            "config": config,
            "timeout_seconds": step.timeout_seconds,
            "on_success": step.on_success,
            "on_failure": step.on_failure,
        }

    def _resolve_execution_version(self, db: Session, playbook: Playbook) -> Optional[PlaybookVersion]:
        if playbook.active_version_id:
            return db.query(PlaybookVersion).filter(PlaybookVersion.id == playbook.active_version_id).first()
        return db.query(PlaybookVersion).filter(
            PlaybookVersion.playbook_id == playbook.id,
        ).order_by(PlaybookVersion.version_number.desc()).first()

    def _materialize_execution_steps(
        self,
        db: Session,
        execution: PlaybookExecution,
        version: Optional[PlaybookVersion],
    ) -> None:
        steps = ((version.definition if version else {}) or {}).get("steps") or []
        for index, step in enumerate(steps):
            config = dict(step.get("config") or {})
            retry_policy = config.get("retry_policy") or {}
            execution_step = PlaybookExecutionStep(
                execution_id=execution.id,
                playbook_id=execution.playbook_id,
                version_id=execution.version_id,
                step_key=step.get("step_key") or f"step_{index + 1}",
                name=step.get("name") or f"Step {index + 1}",
                type=PlaybookStepType(step.get("type")),
                order=int(step.get("order", index)),
                status=PlaybookStepStatus.PENDING,
                config=config,
                max_attempts=max(1, int(retry_policy.get("max_attempts", 1))),
                timeout_seconds=step.get("timeout_seconds"),
            )
            db.add(execution_step)

    def _evaluate_condition(self, config: dict[str, Any], context: dict[str, Any]) -> bool:
        expression = config.get("expression")
        if expression:
            return bool(self.expression_evaluator.evaluate(expression, context))
        field = config.get("field")
        operator_name = config.get("operator", "equals")
        expected = config.get("value")
        actual = self._get_path(context, field) if field else None
        operations = {
            "equals": operator.eq,
            "not_equals": operator.ne,
            "gt": operator.gt,
            "gte": operator.ge,
            "lt": operator.lt,
            "lte": operator.le,
            "contains": lambda a, b: b in a if a is not None else False,
            "in": lambda a, b: a in b if b is not None else False,
            "exists": lambda a, b: a is not None,
        }
        if operator_name not in operations:
            raise ValueError(f"Unsupported condition operator: {operator_name}")
        return bool(operations[operator_name](actual, expected))

    def _execution_context(self, db: Session, execution: PlaybookExecution) -> dict[str, Any]:
        context = dict(execution.context or {})
        context.update(
            {
                "tenant_id": execution.tenant_id,
                "incident_id": execution.incident_id,
                "alert_id": execution.alert_id,
                "playbook_id": execution.playbook_id,
                "trigger_type": execution.trigger_type.value if execution.trigger_type else None,
            }
        )
        if execution.incident_id:
            incident = db.query(Incident).filter(Incident.id == execution.incident_id).first()
            if incident:
                context["incident"] = {
                    "id": incident.id,
                    "title": incident.title,
                    "status": incident.status.value if incident.status else None,
                    "severity": incident.severity.value if incident.severity else None,
                    "priority": incident.priority.value if incident.priority else None,
                    "risk_score": incident.risk_score,
                    "assigned_to": incident.assigned_to,
                }
        return context

    def _get_path(self, data: dict[str, Any], path: Optional[str]) -> Any:
        if not path:
            return None
        value: Any = data
        for part in path.split("."):
            if isinstance(value, dict):
                value = value.get(part)
            else:
                value = getattr(value, part, None)
        return value

    def _next_pending_index(self, steps: list[PlaybookExecutionStep]) -> int:
        for index, step in enumerate(steps):
            if step.status == PlaybookStepStatus.PENDING:
                return index
        return len(steps)

    def _pending_approval_for_execution(self, db: Session, execution: PlaybookExecution) -> Optional[PlaybookApproval]:
        return db.query(PlaybookApproval).filter(
            PlaybookApproval.execution_id == execution.id,
            PlaybookApproval.status == PlaybookApprovalStatus.PENDING,
        ).order_by(PlaybookApproval.created_at.asc()).first()

    def _decide_approval(
        self,
        db: Session,
        approval: PlaybookApproval,
        user_id: str,
        status: PlaybookApprovalStatus,
        comment: Optional[str],
    ) -> None:
        if approval.status != PlaybookApprovalStatus.PENDING:
            raise ValueError("Approval has already been decided")
        approval.status = status
        approval.approved_by = user_id
        approval.decision_comment = comment
        approval.decided_at = self._utcnow()

    def _require_playbook(self, db: Session, tenant_id: str, playbook_id: str) -> Playbook:
        playbook = self.get_playbook(db, tenant_id, playbook_id)
        if not playbook:
            raise ValueError("Playbook not found")
        return playbook

    def _normalize_playbook_defaults(self, playbook: Playbook) -> Playbook:
        if playbook.status is None:
            playbook.status = PlaybookStatus.DRAFT
        if playbook.trigger_type is None:
            playbook.trigger_type = PlaybookTriggerType.MANUAL_RUN
        return playbook

    def _require_execution(self, db: Session, tenant_id: str, execution_id: str) -> PlaybookExecution:
        execution = db.query(PlaybookExecution).filter(
            PlaybookExecution.id == execution_id,
            PlaybookExecution.tenant_id == tenant_id,
        ).first()
        if not execution:
            raise ValueError("Execution not found")
        return execution

    def _require_approval(self, db: Session, tenant_id: str, approval_id: str) -> PlaybookApproval:
        approval = db.query(PlaybookApproval).filter(
            PlaybookApproval.id == approval_id,
            PlaybookApproval.tenant_id == tenant_id,
        ).first()
        if not approval:
            raise ValueError("Approval not found")
        return approval

    def _require_variable(self, db: Session, tenant_id: str, variable_id: str) -> PlaybookVariable:
        variable = db.query(PlaybookVariable).filter(
            PlaybookVariable.id == variable_id,
            PlaybookVariable.tenant_id == tenant_id,
        ).first()
        if not variable:
            raise ValueError("Variable not found")
        return variable

    def _require_incident(self, db: Session, execution: PlaybookExecution) -> Incident:
        if not execution.incident_id:
            raise ValueError("Execution is not associated with an incident")
        incident = db.query(Incident).filter(
            Incident.id == execution.incident_id,
            Incident.tenant_id == execution.tenant_id,
        ).first()
        if not incident:
            raise ValueError("Incident not found")
        return incident

    def _log(
        self,
        db: Session,
        execution: PlaybookExecution,
        step: Optional[PlaybookExecutionStep],
        level: str,
        message: str,
        data: Optional[dict[str, Any]] = None,
    ) -> None:
        db.add(
            PlaybookRunLog(
                tenant_id=execution.tenant_id,
                execution_id=execution.id,
                execution_step_id=step.id if step else None,
                level=level,
                message=message,
                data=data,
            )
        )

    def _utcnow(self) -> datetime:
        return datetime.now(timezone.utc)


playbook_service = PlaybookService()
