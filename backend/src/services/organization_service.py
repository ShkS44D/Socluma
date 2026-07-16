from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from typing import Iterable

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from src.models.pydantic import OrganizationCreate, OrganizationInvitationCreate, OrganizationUpdate
from src.models.sqlalchemy import (
    Alert,
    Collector,
    ConnectorActionExecution,
    InvitationStatus,
    OrganizationInvitation,
    OrganizationMembership,
    OrganizationRole,
    OrganizationStatus,
    Playbook,
    SecurityEvent,
    Tenant,
    User,
    UserRole,
)
from src.utils.datetime_utils import get_utc_now


ROLE_TO_USER_ROLE = {
    OrganizationRole.OWNER: UserRole.ADMIN,
    OrganizationRole.ADMINISTRATOR: UserRole.ADMIN,
    OrganizationRole.SOC_MANAGER: UserRole.ANALYST,
    OrganizationRole.ANALYST: UserRole.ANALYST,
    OrganizationRole.VIEWER: UserRole.VIEWER,
}


class OrganizationService:
    def list_organizations(self, db: Session, user: User) -> list[Tenant]:
        return (
            db.query(Tenant)
            .join(OrganizationMembership, OrganizationMembership.tenant_id == Tenant.id)
            .filter(
                OrganizationMembership.user_id == user.id,
                OrganizationMembership.is_active == True,
                Tenant.status != OrganizationStatus.DELETED,
                Tenant.is_active == True,
            )
            .order_by(Tenant.name.asc())
            .all()
        )

    def create_organization(self, db: Session, user: User, data: OrganizationCreate) -> Tenant:
        existing = db.query(Tenant).filter(Tenant.slug == data.slug).first()
        if existing:
            raise ValueError("Organization slug already exists")
        org = Tenant(**data.model_dump(), status=OrganizationStatus.ACTIVE, is_active=True)
        db.add(org)
        db.flush()
        membership = OrganizationMembership(
            tenant_id=org.id,
            user_id=user.id,
            role=OrganizationRole.OWNER,
            is_active=True,
        )
        db.add(membership)
        db.commit()
        db.refresh(org)
        return org

    def get_organization(self, db: Session, user: User, organization_id: str) -> Tenant:
        self.require_membership(db, user, organization_id)
        org = db.query(Tenant).filter(Tenant.id == organization_id, Tenant.status != OrganizationStatus.DELETED).first()
        if not org:
            raise ValueError("Organization not found")
        return org

    def update_organization(self, db: Session, user: User, organization_id: str, data: OrganizationUpdate) -> Tenant:
        self.require_org_roles(db, user, organization_id, [OrganizationRole.OWNER, OrganizationRole.ADMINISTRATOR])
        org = self.get_organization(db, user, organization_id)
        for field, value in data.model_dump(exclude_unset=True).items():
            setattr(org, field, value)
        org.is_active = org.status == OrganizationStatus.ACTIVE
        db.commit()
        db.refresh(org)
        return org

    def delete_organization(self, db: Session, user: User, organization_id: str) -> Tenant:
        self.require_org_roles(db, user, organization_id, [OrganizationRole.OWNER])
        if user.tenant_id == organization_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Switch to another organization before deleting the current organization",
            )
        org = self.get_organization(db, user, organization_id)
        org.status = OrganizationStatus.DELETED
        org.is_active = False
        db.commit()
        db.refresh(org)
        return org

    def switch_organization(self, db: Session, user: User, organization_id: str) -> User:
        membership = self.require_membership(db, user, organization_id)
        persistent_user = db.get(User, user.id)
        if not persistent_user:
            raise ValueError("User not found")
        persistent_user.tenant_id = organization_id
        persistent_user.role = ROLE_TO_USER_ROLE[membership.role]
        db.commit()
        db.refresh(persistent_user)
        return persistent_user

    def list_members(self, db: Session, user: User, organization_id: str) -> list[OrganizationMembership]:
        self.require_org_roles(
            db,
            user,
            organization_id,
            [OrganizationRole.OWNER, OrganizationRole.ADMINISTRATOR, OrganizationRole.SOC_MANAGER],
        )
        return (
            db.query(OrganizationMembership)
            .options(joinedload(OrganizationMembership.user))
            .filter(OrganizationMembership.tenant_id == organization_id)
            .order_by(OrganizationMembership.created_at.asc())
            .all()
        )

    def update_member(
        self,
        db: Session,
        user: User,
        organization_id: str,
        membership_id: str,
        role: OrganizationRole | None,
        is_active: bool | None,
    ) -> OrganizationMembership:
        self.require_org_roles(db, user, organization_id, [OrganizationRole.OWNER, OrganizationRole.ADMINISTRATOR])
        membership = (
            db.query(OrganizationMembership)
            .filter(OrganizationMembership.id == membership_id, OrganizationMembership.tenant_id == organization_id)
            .first()
        )
        if not membership:
            raise ValueError("Membership not found")
        if membership.user_id == user.id and (role is not None or is_active is False):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot remove or downgrade your own membership")
        if role is not None:
            membership.role = role
        if is_active is not None:
            membership.is_active = is_active
        if user.tenant_id == organization_id and membership.user_id == user.id:
            user.role = ROLE_TO_USER_ROLE[membership.role]
        db.commit()
        db.refresh(membership)
        return membership

    def invite_member(
        self,
        db: Session,
        user: User,
        organization_id: str,
        data: OrganizationInvitationCreate,
    ) -> tuple[OrganizationInvitation, str]:
        self.require_org_roles(
            db,
            user,
            organization_id,
            [OrganizationRole.OWNER, OrganizationRole.ADMINISTRATOR, OrganizationRole.SOC_MANAGER],
        )
        self.enforce_limit(db, organization_id, "users")
        token = secrets.token_urlsafe(32)
        invited_user = db.query(User).filter(User.email == data.email).first()
        invitation = OrganizationInvitation(
            tenant_id=organization_id,
            email=data.email,
            role=data.role,
            token_hash=self.hash_invitation_token(token),
            invited_by=user.id,
            invited_user_id=invited_user.id if invited_user else None,
            expires_at=get_utc_now() + timedelta(days=data.expires_in_days),
        )
        db.add(invitation)
        db.commit()
        db.refresh(invitation)
        return invitation, token

    def list_invitations(self, db: Session, user: User, organization_id: str) -> list[OrganizationInvitation]:
        self.require_org_roles(
            db,
            user,
            organization_id,
            [OrganizationRole.OWNER, OrganizationRole.ADMINISTRATOR, OrganizationRole.SOC_MANAGER],
        )
        self.expire_invitations(db)
        return (
            db.query(OrganizationInvitation)
            .filter(OrganizationInvitation.tenant_id == organization_id)
            .order_by(OrganizationInvitation.created_at.desc())
            .all()
        )

    def accept_invitation(self, db: Session, user: User, token: str) -> OrganizationInvitation:
        invitation = self._get_pending_invitation(db, token)
        if invitation.email.lower() != user.email.lower():
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invitation is for a different email address")
        self.enforce_limit(db, invitation.tenant_id, "users")
        membership = (
            db.query(OrganizationMembership)
            .filter(OrganizationMembership.tenant_id == invitation.tenant_id, OrganizationMembership.user_id == user.id)
            .first()
        )
        if not membership:
            membership = OrganizationMembership(
                tenant_id=invitation.tenant_id,
                user_id=user.id,
                role=invitation.role,
                invited_by=invitation.invited_by,
                is_active=True,
            )
            db.add(membership)
        else:
            membership.role = invitation.role
            membership.is_active = True
        invitation.status = InvitationStatus.ACCEPTED
        invitation.accepted_at = get_utc_now()
        invitation.invited_user_id = user.id
        db.commit()
        db.refresh(invitation)
        return invitation

    def reject_invitation(self, db: Session, user: User, token: str) -> OrganizationInvitation:
        invitation = self._get_pending_invitation(db, token)
        if invitation.email.lower() != user.email.lower():
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invitation is for a different email address")
        invitation.status = InvitationStatus.REJECTED
        invitation.rejected_at = get_utc_now()
        db.commit()
        db.refresh(invitation)
        return invitation

    def usage(self, db: Session, user: User, organization_id: str) -> dict:
        self.require_membership(db, user, organization_id)
        org = db.query(Tenant).filter(Tenant.id == organization_id).first()
        if not org:
            raise ValueError("Organization not found")
        values = self.calculate_usage(db, organization_id)
        values["limits"] = {
            "max_users": org.max_users,
            "max_collectors": org.max_collectors,
            "max_storage": org.max_storage,
        }
        return values

    def calculate_usage(self, db: Session, organization_id: str) -> dict:
        return {
            "organization_id": organization_id,
            "user_count": db.query(OrganizationMembership).filter_by(tenant_id=organization_id, is_active=True).count(),
            "collector_count": db.query(Collector).filter_by(tenant_id=organization_id).count(),
            "event_count": db.query(SecurityEvent).filter_by(tenant_id=organization_id).count(),
            "alert_count": db.query(Alert).filter_by(tenant_id=organization_id).count(),
            "playbook_count": db.query(Playbook).filter_by(tenant_id=organization_id).count(),
            "soar_execution_count": db.query(ConnectorActionExecution).filter_by(tenant_id=organization_id).count(),
            "storage_bytes": 0,
            "api_request_count": 0,
        }

    def enforce_limit(self, db: Session, organization_id: str, resource: str) -> None:
        org = db.query(Tenant).filter(Tenant.id == organization_id).first()
        if not org:
            raise ValueError("Organization not found")
        usage = self.calculate_usage(db, organization_id)
        limits = {
            "users": ("user_count", org.max_users, "User limit reached for this organization"),
            "collectors": ("collector_count", org.max_collectors, "Collector limit reached for this organization"),
            "storage": ("storage_bytes", org.max_storage, "Storage limit reached for this organization"),
        }
        if resource not in limits:
            return
        field, limit, message = limits[resource]
        if limit is not None and usage[field] >= limit:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=message)

    def require_membership(self, db: Session, user: User, organization_id: str) -> OrganizationMembership:
        membership = (
            db.query(OrganizationMembership)
            .join(Tenant, Tenant.id == OrganizationMembership.tenant_id)
            .filter(
                OrganizationMembership.user_id == user.id,
                OrganizationMembership.tenant_id == organization_id,
                OrganizationMembership.is_active == True,
                Tenant.is_active == True,
                Tenant.status == OrganizationStatus.ACTIVE,
            )
            .first()
        )
        if not membership:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Organization membership required")
        return membership

    def require_org_roles(
        self,
        db: Session,
        user: User,
        organization_id: str,
        roles: Iterable[OrganizationRole],
    ) -> OrganizationMembership:
        membership = self.require_membership(db, user, organization_id)
        if membership.role not in set(roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient organization permissions")
        return membership

    def ensure_primary_membership(
        self,
        db: Session,
        user: User,
        role: OrganizationRole | None = None,
        *,
        commit: bool = True,
    ) -> OrganizationMembership:
        membership = (
            db.query(OrganizationMembership)
            .filter(OrganizationMembership.user_id == user.id, OrganizationMembership.tenant_id == user.tenant_id)
            .first()
        )
        if not membership:
            candidate = OrganizationMembership(
                user_id=user.id,
                tenant_id=user.tenant_id,
                role=role or self.user_role_to_org_role(user.role),
                is_active=True,
            )
            try:
                with db.begin_nested():
                    db.add(candidate)
                    db.flush()
                membership = candidate
                if commit:
                    db.commit()
                db.refresh(membership)
            except IntegrityError:
                if commit:
                    db.rollback()
                membership = (
                    db.query(OrganizationMembership)
                    .filter(
                        OrganizationMembership.user_id == user.id,
                        OrganizationMembership.tenant_id == user.tenant_id,
                    )
                    .first()
                )
                if membership is None:
                    raise
        return membership

    def user_role_to_org_role(self, role: UserRole) -> OrganizationRole:
        if role == UserRole.ADMIN:
            return OrganizationRole.OWNER
        if role == UserRole.VIEWER:
            return OrganizationRole.VIEWER
        return OrganizationRole.ANALYST

    def hash_invitation_token(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def expire_invitations(self, db: Session) -> None:
        now = get_utc_now()
        expired = (
            db.query(OrganizationInvitation)
            .filter(OrganizationInvitation.status == InvitationStatus.PENDING, OrganizationInvitation.expires_at < now)
            .all()
        )
        if expired:
            for invitation in expired:
                invitation.status = InvitationStatus.EXPIRED
            db.commit()

    def _get_pending_invitation(self, db: Session, token: str) -> OrganizationInvitation:
        self.expire_invitations(db)
        invitation = (
            db.query(OrganizationInvitation)
            .filter(
                OrganizationInvitation.token_hash == self.hash_invitation_token(token),
                OrganizationInvitation.status == InvitationStatus.PENDING,
            )
            .first()
        )
        if not invitation:
            raise ValueError("Invitation not found or expired")
        return invitation


organization_service = OrganizationService()
