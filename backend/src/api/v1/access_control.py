from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from src.api.deps import get_current_user, get_db
from src.core.permissions import (
    PERMISSION_CATALOG,
    Permission,
    active_membership,
    membership_permissions,
    require_permission,
)
from src.models.pydantic import (
    APIKeyCreate,
    APIKeyResponse,
    ApprovalDecisionRequest,
    ApprovalRequestCreate,
    ApprovalResponse,
    CustomRole,
    CustomRoleCreate,
    CustomRoleUpdate,
    EffectivePermissions,
    PermissionCatalog,
    PermissionDescriptor,
)
from src.models.sqlalchemy import OrganizationAPIKey, OrganizationCustomRole, SensitiveActionApproval, User
from src.services.access_control_service import access_control_service
from src.services.api_key_service import api_key_service
from src.services.approval_service import approval_service
from src.services.audit_service import audit_service
from src.utils.datetime_utils import get_utc_now


router = APIRouter(prefix="/access-control", tags=["Access control"])


def _audit(db: Session, request: Request, action: str, user: User, resource_type: str, resource_id: str, details=None):
    audit_service.record(
        db,
        action=action,
        user=user,
        resource_type=resource_type,
        resource_id=resource_id,
        request_id=getattr(request.state, "request_id", None),
        details=details or {},
    )


@router.get("/effective", response_model=EffectivePermissions)
def effective_permissions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    membership = active_membership(db, current_user)
    revision = (
        membership.custom_role.permission_revision
        if membership.custom_role
        else membership.tenant.permission_revision
    ) or 1
    return EffectivePermissions(
        organization_id=current_user.tenant_id,
        membership_id=membership.id,
        role=membership.role,
        custom_role_id=membership.custom_role_id,
        permissions=sorted(membership_permissions(db, current_user)),
        permission_revision=revision,
    )


@router.get("/permissions", response_model=PermissionCatalog)
def permissions(_: User = Depends(require_permission(Permission.ROLES_VIEW))):
    return PermissionCatalog(permissions=[
        PermissionDescriptor(**metadata.__dict__)
        for metadata in sorted(PERMISSION_CATALOG.values(), key=lambda item: (item.category, item.identifier))
    ])


@router.get("/roles", response_model=list[CustomRole])
def roles(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ROLES_VIEW)),
):
    return db.query(OrganizationCustomRole).filter_by(
        tenant_id=current_user.tenant_id
    ).order_by(OrganizationCustomRole.name).all()


@router.post("/roles", response_model=CustomRole, status_code=201)
def create_role(
    data: CustomRoleCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ROLES_CREATE)),
):
    role = access_control_service.create_role(db, current_user, current_user.tenant_id, data)
    _audit(
        db, request, "role_created", current_user, "role", role.id,
        {"after": {"name": role.name, "permissions": role.permissions}},
    )
    return role


@router.patch("/roles/{role_id}", response_model=CustomRole)
def update_role(
    role_id: str,
    data: CustomRoleUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ROLES_UPDATE)),
):
    existing = db.query(OrganizationCustomRole).filter_by(
        id=role_id, tenant_id=current_user.tenant_id
    ).first()
    before = {"name": existing.name, "permissions": list(existing.permissions or [])} if existing else {}
    role = access_control_service.update_role(db, current_user, current_user.tenant_id, role_id, data)
    _audit(
        db, request, "role_updated", current_user, "role", role.id,
        {"before": before, "after": {"name": role.name, "permissions": role.permissions}},
    )
    return role


@router.delete("/roles/{role_id}", status_code=204)
def delete_role(
    role_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ROLES_DELETE)),
):
    access_control_service.delete_role(db, current_user, current_user.tenant_id, role_id)
    _audit(db, request, "role_deleted", current_user, "role", role_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/api-keys", response_model=list[APIKeyResponse])
def list_api_keys(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.API_KEYS_VIEW)),
):
    return db.query(OrganizationAPIKey).filter_by(tenant_id=current_user.tenant_id).order_by(
        OrganizationAPIKey.created_at.desc()
    ).all()


@router.post("/api-keys", response_model=APIKeyResponse, status_code=201)
def create_api_key(
    data: APIKeyCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.API_KEYS_MANAGE)),
):
    record, raw = api_key_service.create(db, current_user, data.name, data.scopes, data.expires_in_days)
    response = APIKeyResponse.model_validate(record).model_copy(update={"api_key": raw})
    _audit(db, request, "api_key_created", current_user, "api_key", record.id, {"scopes": record.scopes})
    return response


@router.delete("/api-keys/{key_id}", status_code=204)
def revoke_api_key(
    key_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.API_KEYS_MANAGE)),
):
    record = db.query(OrganizationAPIKey).filter_by(
        id=key_id, tenant_id=current_user.tenant_id
    ).first()
    if not record:
        return Response(status_code=204)
    record.revoked_at = get_utc_now()
    record.revocation_reason = "user_revoked"
    db.commit()
    _audit(db, request, "api_key_revoked", current_user, "api_key", record.id)
    return Response(status_code=204)


@router.get("/approvals", response_model=list[ApprovalResponse])
def list_approvals(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ORGANIZATION_VIEW)),
):
    return db.query(SensitiveActionApproval).filter_by(
        tenant_id=current_user.tenant_id
    ).order_by(SensitiveActionApproval.created_at.desc()).limit(100).all()


@router.post("/approvals", response_model=ApprovalResponse, status_code=201)
def request_approval(
    data: ApprovalRequestCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ORGANIZATION_VIEW)),
):
    approval = approval_service.create(db, current_user, data)
    _audit(db, request, "approval_requested", current_user, "approval", approval.id, {
        "action_type": approval.action_type,
        "target_resource_type": approval.target_resource_type,
        "target_resource_id": approval.target_resource_id,
    })
    return approval


@router.post("/approvals/{approval_id}/decision", response_model=ApprovalResponse)
def decide_approval(
    approval_id: str,
    data: ApprovalDecisionRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ORGANIZATION_VIEW)),
):
    approval = approval_service.decide(db, current_user, approval_id, data.decision)
    audit_action = "approval_approved" if data.decision == "approve" else "approval_rejected"
    _audit(db, request, audit_action, current_user, "approval", approval.id)
    return approval
