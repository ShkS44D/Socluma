from __future__ import annotations

from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from src.api.deps import get_current_user, get_db
from src.models.pydantic import (
    InvitationDecision,
    Organization,
    OrganizationCreate,
    OrganizationInvitation,
    OrganizationInvitationCreate,
    OrganizationInvitationResponse,
    OrganizationMemberUpdate,
    OrganizationMembership,
    OrganizationUpdate,
    DeletionPinRequest,
    OrganizationDeleteRequest,
    OrganizationUsage,
    OrganizationUsageHistoryItem,
    SubscriptionInfo,
    TenantSwitchRequest,
    Token,
)
from src.models.sqlalchemy import AlertSource, Collector, User
from src.services.audit_service import audit_service
from src.services.auth_service import auth_service
from src.services.organization_service import organization_service
from src.services.approval_service import approval_service
from src.core.validation import validate_uuid
from src.core.permissions import Permission, require_all_permissions, require_permission, require_tenant_permission


router = APIRouter(prefix="/organizations", tags=["Organizations"])


def _client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


def _raise(error: ValueError) -> None:
    message = str(error)
    normalized = message.lower()
    if "not found" in normalized:
        code = status.HTTP_404_NOT_FOUND
    elif "already exists" in normalized:
        code = status.HTTP_409_CONFLICT
    else:
        code = status.HTTP_400_BAD_REQUEST
    raise HTTPException(status_code=code, detail=message)


@router.get("", response_model=list[Organization])
def list_organizations(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ORGANIZATION_VIEW)),
):
    return [Organization.model_validate(org) for org in organization_service.list_organizations(db, current_user)]


@router.post("", response_model=Organization, status_code=status.HTTP_201_CREATED)
def create_organization(
    data: OrganizationCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        org = organization_service.create_organization(db, current_user, data)
        audit_service.record(
            db,
            action="organization_created",
            user=current_user,
            tenant_id=org.id,
            resource_type="organization",
            resource_id=org.id,
            ip_address=_client_ip(request),
            details={"slug": org.slug},
            commit=False,
            strict=True,
        )
        db.commit()
        db.refresh(org)
        return Organization.model_validate(org)
    except ValueError as exc:
        _raise(exc)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Organization could not be created because a unique value already exists",
        ) from exc


@router.get("/current", response_model=Organization)
def get_current_organization(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ORGANIZATION_VIEW)),
):
    try:
        return Organization.model_validate(organization_service.get_organization(db, current_user, current_user.tenant_id))
    except ValueError as exc:
        _raise(exc)


@router.post("/switch", response_model=Token)
def switch_organization(
    data: TenantSwitchRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    switched = organization_service.switch_organization(db, current_user, data.organization_id)
    token_pair = auth_service.create_token_pair(db, switched, request=request)
    audit_service.record(
        db,
        action="organization_switched",
        user=switched,
        tenant_id=switched.tenant_id,
        resource_type="organization",
        resource_id=switched.tenant_id,
        ip_address=_client_ip(request),
    )
    return token_pair


@router.get("/{organization_id}", response_model=Organization)
def get_organization(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_tenant_permission(Permission.ORGANIZATION_VIEW)),
):
    validate_uuid(organization_id, "organization_id")
    try:
        return Organization.model_validate(organization_service.get_organization(db, current_user, organization_id))
    except ValueError as exc:
        _raise(exc)


@router.patch("/{organization_id}", response_model=Organization)
def update_organization(
    organization_id: str,
    data: OrganizationUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_tenant_permission(Permission.ORGANIZATION_UPDATE)),
):
    validate_uuid(organization_id, "organization_id")
    try:
        org = organization_service.update_organization(db, current_user, organization_id, data)
        audit_service.record(
            db,
            action="organization_updated",
            user=current_user,
            tenant_id=organization_id,
            resource_type="organization",
            resource_id=organization_id,
            ip_address=_client_ip(request),
            details=data.model_dump(exclude_unset=True),
        )
        return Organization.model_validate(org)
    except ValueError as exc:
        _raise(exc)


@router.put("/{organization_id}/deletion-pin", status_code=status.HTTP_204_NO_CONTENT)
def set_deletion_pin(
    organization_id: str, data: DeletionPinRequest, request: Request,
    db: Session = Depends(get_db), current_user: User = Depends(require_tenant_permission(Permission.ORGANIZATION_SECURITY_MANAGE)),
):
    validate_uuid(organization_id, "organization_id")
    try:
        organization_service.set_deletion_pin(db, current_user, organization_id, data.pin, data.current_password)
        audit_service.record(db, action="deletion_pin_changed", user=current_user, tenant_id=organization_id,
                             resource_type="organization", resource_id=organization_id, ip_address=_client_ip(request),
                             strict=True)
    except (ValueError, HTTPException) as exc:
        audit_service.record(db, action="deletion_pin_change_failed", user=current_user, tenant_id=organization_id,
                             resource_type="organization", resource_id=organization_id, ip_address=_client_ip(request),
                             status="failure", failure_reason="verification_failed")
        if isinstance(exc, HTTPException):
            raise
        _raise(exc)


@router.delete("/{organization_id}", response_model=Organization)
def delete_organization(
    organization_id: str,
    data: OrganizationDeleteRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_tenant_permission(Permission.ORGANIZATION_DELETE)),
):
    validate_uuid(organization_id, "organization_id")
    try:
        approval_service.require_and_consume(
            db,
            current_user,
            data.approval_id,
            action_type="organization.delete",
            target_type="organization",
            target_id=organization_id,
            tenant_id=organization_id,
        )
        return Organization.model_validate(
            organization_service.delete_organization(db, current_user, organization_id, data.pin)
        )
    except HTTPException:
        raise
    except ValueError as exc:
        _raise(exc)


@router.post("/{organization_id}/deletion/cancel", response_model=Organization)
def cancel_organization_deletion(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_tenant_permission(
        Permission.ORGANIZATION_DELETE_CANCEL, allow_pending_deletion=True
    )),
):
    validate_uuid(organization_id, "organization_id")
    return Organization.model_validate(
        organization_service.cancel_deletion(db, current_user, organization_id)
    )


@router.get("/{organization_id}/deletion/status", response_model=Organization)
def organization_deletion_status(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_tenant_permission(
        Permission.ORGANIZATION_DELETE, allow_pending_deletion=True
    )),
):
    validate_uuid(organization_id, "organization_id")
    _, org = organization_service._require_lifecycle_owner(db, current_user, organization_id)
    return Organization.model_validate(org)


@router.get("/{organization_id}/members", response_model=list[OrganizationMembership])
def list_members(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_tenant_permission(Permission.USERS_VIEW)),
):
    validate_uuid(organization_id, "organization_id")
    try:
        return [
            OrganizationMembership.model_validate(member)
            for member in organization_service.list_members(db, current_user, organization_id)
        ]
    except ValueError as exc:
        _raise(exc)


@router.patch("/{organization_id}/members/{membership_id}", response_model=OrganizationMembership)
def update_member(
    organization_id: str,
    membership_id: str,
    data: OrganizationMemberUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    validate_uuid(organization_id, "organization_id")
    validate_uuid(membership_id, "membership_id")
    try:
        member = organization_service.update_member(
            db, current_user, organization_id, membership_id, data.role, data.is_active, data.custom_role_id
        )
        audit_service.record(
            db,
            action="organization_membership_updated",
            user=current_user,
            tenant_id=organization_id,
            resource_type="organization_membership",
            resource_id=membership_id,
            ip_address=_client_ip(request),
            details=data.model_dump(exclude_unset=True),
        )
        return OrganizationMembership.model_validate(member)
    except ValueError as exc:
        _raise(exc)


@router.get("/{organization_id}/invitations", response_model=list[OrganizationInvitation])
def list_invitations(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_tenant_permission(Permission.USERS_VIEW)),
):
    validate_uuid(organization_id, "organization_id")
    try:
        return [
            OrganizationInvitation.model_validate(invitation)
            for invitation in organization_service.list_invitations(db, current_user, organization_id)
        ]
    except ValueError as exc:
        _raise(exc)


@router.post("/{organization_id}/invitations", response_model=OrganizationInvitationResponse, status_code=status.HTTP_201_CREATED)
def invite_member(
    organization_id: str,
    data: OrganizationInvitationCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    validate_uuid(organization_id, "organization_id")
    try:
        invitation, token = organization_service.invite_member(db, current_user, organization_id, data)
        audit_service.record(
            db,
            action="organization_invitation_created",
            user=current_user,
            tenant_id=organization_id,
            resource_type="organization_invitation",
            resource_id=invitation.id,
            ip_address=_client_ip(request),
            details={"email": invitation.email, "role": invitation.role.value},
        )
        response = OrganizationInvitationResponse.model_validate(invitation)
        response.token = token
        return response
    except ValueError as exc:
        _raise(exc)


@router.post("/invitations/accept", response_model=OrganizationInvitation)
def accept_invitation(
    data: InvitationDecision,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        invitation = organization_service.accept_invitation(db, current_user, data.token)
        audit_service.record(
            db,
            action="organization_invitation_accepted",
            user=current_user,
            tenant_id=invitation.tenant_id,
            resource_type="organization_invitation",
            resource_id=invitation.id,
            ip_address=_client_ip(request),
        )
        return OrganizationInvitation.model_validate(invitation)
    except ValueError as exc:
        _raise(exc)


@router.post("/invitations/reject", response_model=OrganizationInvitation)
def reject_invitation(
    data: InvitationDecision,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        invitation = organization_service.reject_invitation(db, current_user, data.token)
        audit_service.record(
            db,
            action="organization_invitation_rejected",
            user=current_user,
            tenant_id=invitation.tenant_id,
            resource_type="organization_invitation",
            resource_id=invitation.id,
            ip_address=_client_ip(request),
        )
        return OrganizationInvitation.model_validate(invitation)
    except ValueError as exc:
        _raise(exc)


@router.get("/{organization_id}/usage", response_model=OrganizationUsage)
def get_usage(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_tenant_permission(Permission.USAGE_VIEW)),
):
    validate_uuid(organization_id, "organization_id")
    try:
        return OrganizationUsage(**organization_service.usage(db, current_user, organization_id))
    except ValueError as exc:
        _raise(exc)


@router.get("/{organization_id}/usage/history", response_model=list[OrganizationUsageHistoryItem])
def get_usage_history(
    organization_id: str,
    start_date: date = Query(default_factory=lambda: date.today() - timedelta(days=30)),
    end_date: date = Query(default_factory=date.today),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_tenant_permission(Permission.USAGE_VIEW)),
):
    validate_uuid(organization_id, "organization_id")
    if start_date > end_date:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error_code": "usage_date_range_invalid", "message": "start_date must not be after end_date"},
        )
    if (end_date - start_date).days > 366:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error_code": "usage_date_range_too_large", "message": "Usage history range cannot exceed 366 days"},
        )
    return [
        OrganizationUsageHistoryItem.model_validate(row)
        for row in organization_service.usage_history(db, current_user, organization_id, start_date, end_date)
    ]


@router.get("/{organization_id}/subscription", response_model=SubscriptionInfo)
def get_subscription(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_tenant_permission(Permission.SUBSCRIPTIONS_VIEW)),
):
    validate_uuid(organization_id, "organization_id")
    try:
        org = organization_service.get_organization(db, current_user, organization_id)
        usage = OrganizationUsage(**organization_service.usage(db, current_user, organization_id))
        return SubscriptionInfo(plan=org.subscription_plan, limits=usage.limits, usage=usage)
    except ValueError as exc:
        _raise(exc)


@router.get("/{organization_id}/api-keys")
def list_api_key_inventory(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_tenant_permission(Permission.API_KEYS_VIEW)),
):
    validate_uuid(organization_id, "organization_id")
    organization_service.require_membership(db, current_user, organization_id)
    collectors = db.query(Collector).filter(Collector.tenant_id == organization_id).all()
    alert_sources = db.query(AlertSource).filter(AlertSource.tenant_id == organization_id).all()
    return {
        "collectors": [
            {
                "id": collector.id,
                "name": collector.name,
                "type": collector.type,
                "status": collector.status,
                "last_seen": collector.last_seen,
                "has_token": bool(collector.token),
            }
            for collector in collectors
        ],
        "alert_sources": [
            {
                "id": source.id,
                "name": source.name,
                "type": source.type,
                "enabled": source.enabled,
                "has_api_key": bool(source.api_key_hash),
            }
            for source in alert_sources
        ],
    }
