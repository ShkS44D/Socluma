from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

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
    OrganizationUsage,
    SubscriptionInfo,
    TenantSwitchRequest,
    Token,
)
from src.models.sqlalchemy import AlertSource, Collector, User
from src.services.audit_service import audit_service
from src.services.auth_service import auth_service
from src.services.organization_service import organization_service
from src.core.validation import validate_uuid


router = APIRouter(prefix="/organizations", tags=["Organizations"])


def _client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


def _raise(error: ValueError) -> None:
    message = str(error)
    code = status.HTTP_404_NOT_FOUND if "not found" in message.lower() else status.HTTP_400_BAD_REQUEST
    raise HTTPException(status_code=code, detail=message)


@router.get("", response_model=list[Organization])
def list_organizations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    organization_service.ensure_primary_membership(db, current_user)
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
        )
        return Organization.model_validate(org)
    except ValueError as exc:
        _raise(exc)


@router.get("/current", response_model=Organization)
def get_current_organization(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
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
    current_user: User = Depends(get_current_user),
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
    current_user: User = Depends(get_current_user),
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


@router.delete("/{organization_id}", response_model=Organization)
def delete_organization(
    organization_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    validate_uuid(organization_id, "organization_id")
    try:
        org = organization_service.delete_organization(db, current_user, organization_id)
        audit_service.record(
            db,
            action="organization_deleted",
            user=current_user,
            tenant_id=organization_id,
            resource_type="organization",
            resource_id=organization_id,
            ip_address=_client_ip(request),
        )
        return Organization.model_validate(org)
    except ValueError as exc:
        _raise(exc)


@router.get("/{organization_id}/members", response_model=list[OrganizationMembership])
def list_members(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
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
        member = organization_service.update_member(db, current_user, organization_id, membership_id, data.role, data.is_active)
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
    current_user: User = Depends(get_current_user),
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
    current_user: User = Depends(get_current_user),
):
    validate_uuid(organization_id, "organization_id")
    try:
        return OrganizationUsage(**organization_service.usage(db, current_user, organization_id))
    except ValueError as exc:
        _raise(exc)


@router.get("/{organization_id}/subscription", response_model=SubscriptionInfo)
def get_subscription(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
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
    current_user: User = Depends(get_current_user),
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
