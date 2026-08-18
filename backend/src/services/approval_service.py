from __future__ import annotations

import hashlib
import hmac
import json
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy.orm import Session

from src.core.config import get_settings
from src.core.permissions import Permission, membership_permissions
from src.models.sqlalchemy import (
    SensitiveActionApproval,
    SensitiveActionApprovalDecision,
    Tenant,
    User,
)
from src.utils.datetime_utils import ensure_utc, get_utc_now


settings = get_settings()
SENSITIVE_METADATA_KEYS = {"password", "pin", "token", "secret", "credential", "api_key", "authorization"}
ACTION_APPROVAL_PERMISSION = {
    "organization.delete": Permission.ORGANIZATION_SECURITY_MANAGE.value,
    "owner.assign": Permission.ORGANIZATION_SECURITY_MANAGE.value,
    "owner.replace": Permission.ORGANIZATION_SECURITY_MANAGE.value,
    "soar.high_risk.execute": Permission.SOAR_APPROVE.value,
    "credentials.replace": Permission.SOAR_CREDENTIALS_MANAGE.value,
    "audit.export.sensitive": Permission.AUDIT_EXPORT.value,
    "security.disable": Permission.ORGANIZATION_SECURITY_MANAGE.value,
    "ioc.response.execute": Permission.IOC_RESPONSE_APPROVE.value,
}
ACTION_REQUEST_PERMISSION = {
    "organization.delete": Permission.ORGANIZATION_DELETE.value,
    "owner.assign": Permission.ROLES_ASSIGN.value,
    "owner.replace": Permission.ROLES_ASSIGN.value,
    "soar.high_risk.execute": Permission.SOAR_EXECUTE.value,
    "credentials.replace": Permission.SOAR_CREDENTIALS_MANAGE.value,
    "audit.export.sensitive": Permission.AUDIT_EXPORT.value,
    "security.disable": Permission.ORGANIZATION_SECURITY_MANAGE.value,
    "ioc.response.execute": Permission.IOC_RESPONSE_RECOMMEND.value,
}


class ApprovalService:
    def safe_metadata(self, value: dict) -> dict:
        def inspect(item) -> None:
            if isinstance(item, dict):
                for key, nested in item.items():
                    if any(word in str(key).casefold() for word in SENSITIVE_METADATA_KEYS):
                        raise HTTPException(
                            status_code=422,
                            detail={
                                "error_code": "APPROVAL_INVALID",
                                "message": "Sensitive approval metadata is not allowed",
                            },
                        )
                    inspect(nested)
            elif isinstance(item, list):
                for nested in item:
                    inspect(nested)

        inspect(value)
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        if len(encoded) > 4096:
            raise HTTPException(status_code=422, detail={"error_code": "APPROVAL_INVALID", "message": "Approval metadata is too large"})
        return json.loads(encoded)

    def fingerprint(
        self,
        tenant_id: str,
        requester_id: str,
        action_type: str,
        target_type: str,
        target_id: str,
        metadata: dict,
    ) -> str:
        canonical = json.dumps(
            [tenant_id, requester_id, action_type, target_type, target_id, metadata],
            sort_keys=True,
            separators=(",", ":"),
        )
        return hmac.new(settings.REFRESH_TOKEN_SECRET.encode(), canonical.encode(), hashlib.sha256).hexdigest()

    def create(self, db: Session, requester: User, data) -> SensitiveActionApproval:
        if data.action_type not in ACTION_APPROVAL_PERMISSION:
                raise HTTPException(status_code=422, detail={"error_code": "APPROVAL_INVALID", "message": "Unsupported sensitive action"})
        if ACTION_REQUEST_PERMISSION[data.action_type] not in membership_permissions(db, requester):
            raise HTTPException(status_code=403, detail={"error_code": "PERMISSION_DENIED", "message": "Permission denied"})
        metadata = self.safe_metadata(data.safe_metadata)
        fingerprint = self.fingerprint(
            requester.tenant_id, requester.id, data.action_type,
            data.target_resource_type, data.target_resource_id, metadata,
        )
        existing = db.query(SensitiveActionApproval).filter_by(
            tenant_id=requester.tenant_id, request_fingerprint=fingerprint
        ).first()
        if existing:
            return existing
        tenant = db.get(Tenant, requester.tenant_id)
        mode = tenant.sensitive_action_approval_mode if tenant else "none"
        required = 2 if mode == "two_person" else 1
        approval = SensitiveActionApproval(
            tenant_id=requester.tenant_id,
            requester_id=requester.id,
            action_type=data.action_type,
            target_resource_type=data.target_resource_type,
            target_resource_id=data.target_resource_id,
            request_fingerprint=fingerprint,
            required_approvals=required,
            safe_metadata=metadata,
            expires_at=get_utc_now() + timedelta(minutes=data.expires_in_minutes),
        )
        db.add(approval)
        db.commit()
        db.refresh(approval)
        return approval

    def decide(self, db: Session, actor: User, approval_id: str, decision: str) -> SensitiveActionApproval:
        approval = db.query(SensitiveActionApproval).filter_by(
            id=approval_id, tenant_id=actor.tenant_id
        ).with_for_update().first()
        if not approval:
            raise HTTPException(status_code=404, detail={"error_code": "APPROVAL_INVALID", "message": "Approval not found"})
        if approval.requester_id == actor.id:
            raise HTTPException(status_code=403, detail={"error_code": "APPROVAL_INVALID", "message": "Requester cannot approve this action"})
        if ensure_utc(approval.expires_at) <= get_utc_now():
            approval.status = "expired"
            db.commit()
            raise HTTPException(status_code=409, detail={"error_code": "APPROVAL_EXPIRED", "message": "Approval has expired"})
        if approval.status not in {"pending", "approved"} or approval.executed_at:
            raise HTTPException(status_code=409, detail={"error_code": "APPROVAL_INVALID", "message": "Approval cannot be changed"})
        permission = ACTION_APPROVAL_PERMISSION[approval.action_type]
        if permission not in membership_permissions(db, actor):
            raise HTTPException(status_code=403, detail={"error_code": "PERMISSION_DENIED", "message": "Approval permission is required"})
        existing = db.query(SensitiveActionApprovalDecision).filter_by(
            approval_id=approval.id, approver_id=actor.id
        ).first()
        if existing:
            return approval
        db.add(SensitiveActionApprovalDecision(
            approval_id=approval.id, approver_id=actor.id, decision=decision,
        ))
        if decision == "reject":
            approval.status = "rejected"
            approval.rejected_at = get_utc_now()
        else:
            approvals = db.query(SensitiveActionApprovalDecision).filter_by(
                approval_id=approval.id, decision="approve"
            ).count()
            if approvals >= approval.required_approvals:
                approval.status = "approved"
                approval.approved_at = get_utc_now()
        db.commit()
        db.refresh(approval)
        return approval

    def require_and_consume(
        self,
        db: Session,
        actor: User,
        approval_id: str | None,
        *,
        action_type: str,
        target_type: str,
        target_id: str,
        tenant_id: str | None = None,
    ) -> None:
        approval_tenant_id = tenant_id or actor.tenant_id
        tenant = db.get(Tenant, approval_tenant_id)
        if not tenant or tenant.sensitive_action_approval_mode == "none":
            return
        if not approval_id:
            raise HTTPException(status_code=409, detail={"error_code": "APPROVAL_REQUIRED", "message": "Approval is required"})
        approval = db.query(SensitiveActionApproval).filter_by(
            id=approval_id, tenant_id=approval_tenant_id
        ).with_for_update().first()
        if not approval or approval.action_type != action_type or approval.target_resource_type != target_type or approval.target_resource_id != target_id:
            raise HTTPException(status_code=403, detail={"error_code": "APPROVAL_INVALID", "message": "Approval does not match this request"})
        if approval.requester_id != actor.id:
            raise HTTPException(
                status_code=403,
                detail={"error_code": "APPROVAL_INVALID", "message": "Approval belongs to a different requester"},
            )
        if ensure_utc(approval.expires_at) <= get_utc_now():
            approval.status = "expired"
            db.commit()
            raise HTTPException(status_code=409, detail={"error_code": "APPROVAL_EXPIRED", "message": "Approval has expired"})
        if approval.status != "approved" or approval.executed_at:
            raise HTTPException(status_code=409, detail={"error_code": "APPROVAL_INVALID", "message": "Approval is not executable"})
        approval.executed_at = get_utc_now()
        approval.status = "executed"
        db.commit()


approval_service = ApprovalService()
