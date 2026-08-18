from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from typing import Iterable

from fastapi import HTTPException, status
from sqlalchemy import and_, exists, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.orm.attributes import set_committed_value

from src.core.config import get_settings
from src.core.database import Base
from src.models.pydantic import OrganizationCreate, OrganizationInvitationCreate, OrganizationUpdate
from src.models.sqlalchemy import (
    Alert,
    Collector,
    ConnectorActionExecution,
    InvitationStatus,
    OrganizationInvitation,
    OrganizationCustomRole,
    OrganizationMembership,
    OrganizationRole,
    OrganizationStatus,
    Playbook,
    SecurityEvent,
    Tenant,
    User,
    UserRole,
)
from src.services.audit_service import audit_service
from src.services.usage_service import usage_service
from src.utils.datetime_utils import ensure_utc, get_utc_now
from src.core.security import get_password_hash, verify_password
from src.core.permissions import Permission, active_membership, membership_permissions
from src.services.authorization_policy import authorization_policy

settings = get_settings()

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
                or_(Tenant.is_active == True, Tenant.status == OrganizationStatus.PENDING_DELETION),
            )
            .order_by(Tenant.name.asc())
            .all()
        )

    def create_organization(self, db: Session, user: User, data: OrganizationCreate) -> Tenant:
        existing = db.query(Tenant).filter(Tenant.slug == data.slug).first()
        if existing:
            if existing.status != OrganizationStatus.DELETED:
                raise ValueError("Organization slug already exists")
            # Preserve the deleted record for audit/retention while releasing
            # its human-friendly slug for a newly created organization.
            existing.slug = f"{existing.slug[:54]}--deleted--{existing.id}"
            db.flush()
        values = data.model_dump(exclude={"deletion_pin"})
        org = Tenant(
            **values,
            deletion_pin_hash=get_password_hash(data.deletion_pin),
            deletion_pin_failed_attempts=0,
            status=OrganizationStatus.ACTIVE,
            is_active=True,
        )
        db.add(org)
        db.flush()
        membership = OrganizationMembership(
            tenant_id=org.id,
            user_id=user.id,
            role=OrganizationRole.OWNER,
            is_active=True,
        )
        db.add(membership)
        db.flush()
        return org

    def get_organization(self, db: Session, user: User, organization_id: str) -> Tenant:
        self.require_membership(db, user, organization_id)
        org = db.query(Tenant).filter(Tenant.id == organization_id, Tenant.status != OrganizationStatus.DELETED).first()
        if not org:
            raise ValueError("Organization not found")
        return org

    def update_organization(self, db: Session, user: User, organization_id: str, data: OrganizationUpdate) -> Tenant:
        active_membership(db, user, organization_id)
        if Permission.ORGANIZATION_UPDATE.value not in membership_permissions(db, user, organization_id):
            raise HTTPException(status_code=403, detail={"error_code": "PERMISSION_DENIED", "message": "Permission denied"})
        if (
            data.sensitive_action_approval_mode is not None
            and Permission.ORGANIZATION_SECURITY_MANAGE.value
            not in membership_permissions(db, user, organization_id)
        ):
            raise HTTPException(
                status_code=403,
                detail={"error_code": "OWNER_REQUIRED", "message": "Owner authority is required for approval policy changes"},
            )
        org = self.get_organization(db, user, organization_id)
        for field, value in data.model_dump(exclude_unset=True).items():
            if field == "status" and value in {
                OrganizationStatus.PENDING_DELETION,
                OrganizationStatus.DELETED,
            }:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Use the organization deletion workflow to change deletion state",
                )
            setattr(org, field, value)
        org.is_active = org.status == OrganizationStatus.ACTIVE
        db.commit()
        db.refresh(org)
        return org

    def set_deletion_pin(self, db: Session, user: User, organization_id: str, pin: str, current_password: str) -> Tenant:
        membership = active_membership(db, user, organization_id)
        authorization_policy.require_owner(membership)
        if not verify_password(current_password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unable to update deletion PIN")
        org = self.get_organization(db, user, organization_id)
        org.deletion_pin_hash = get_password_hash(pin)
        org.deletion_pin_failed_attempts = 0
        org.deletion_pin_locked_until = None
        db.flush()
        return org

    def verify_deletion_pin(self, db: Session, org: Tenant, pin: str) -> bool:
        now = get_utc_now()
        if org.deletion_pin_locked_until and ensure_utc(org.deletion_pin_locked_until) > now:
            return False
        valid = bool(org.deletion_pin_hash and verify_password(pin, org.deletion_pin_hash))
        if valid:
            org.deletion_pin_failed_attempts = 0
            org.deletion_pin_locked_until = None
        else:
            org.deletion_pin_failed_attempts = (org.deletion_pin_failed_attempts or 0) + 1
            if org.deletion_pin_failed_attempts >= 5:
                org.deletion_pin_locked_until = now + timedelta(minutes=15)
                org.deletion_pin_failed_attempts = 0
        db.flush()
        return valid

    def delete_organization(self, db: Session, user: User, organization_id: str, pin: str) -> Tenant:
        membership, org = self._require_lifecycle_owner(db, user, organization_id)
        if org.status == OrganizationStatus.PENDING_DELETION:
            return org
        if org.deletion_pin_locked_until and ensure_utc(org.deletion_pin_locked_until) > get_utc_now():
            audit_service.record(
                db,
                action="organization_deletion_verification_failed",
                user=user,
                tenant_id=organization_id,
                resource_type="organization",
                resource_id=organization_id,
                status="failure",
                failure_reason="pin_locked",
                commit=False,
                strict=True,
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail={"error_code": "deletion_pin_locked", "message": "Deletion PIN is temporarily locked"},
            )
        if not self.verify_deletion_pin(db, org, pin):
            audit_service.record(
                db,
                action="organization_deletion_verification_failed",
                user=user,
                tenant_id=organization_id,
                resource_type="organization",
                resource_id=organization_id,
                status="failure",
                failure_reason="invalid_or_locked_pin",
                commit=False,
                strict=True,
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error_code": "deletion_pin_invalid", "message": "Unable to verify deletion request"},
            )
        now = get_utc_now()
        org.status = OrganizationStatus.PENDING_DELETION
        org.is_active = False
        org.deletion_requested_at = now
        org.scheduled_purge_at = now + timedelta(days=settings.ORGANIZATION_DELETION_COOLING_OFF_DAYS)
        org.deletion_requested_by_id = user.id
        audit_service.record(
            db,
            action="organization_deletion_requested",
            user=user,
            tenant_id=organization_id,
            resource_type="organization",
            resource_id=organization_id,
            details={"scheduled_purge_at": org.scheduled_purge_at.isoformat()},
            commit=False,
            strict=True,
        )
        db.commit()
        db.refresh(org)
        return org

    def cancel_deletion(self, db: Session, user: User, organization_id: str) -> Tenant:
        _, org = self._require_lifecycle_owner(db, user, organization_id)
        if org.status == OrganizationStatus.ACTIVE:
            return org
        if org.status != OrganizationStatus.PENDING_DELETION:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error_code": "deletion_not_pending", "message": "Organization deletion is not pending"},
            )
        org.status = OrganizationStatus.ACTIVE
        org.is_active = True
        org.deletion_requested_at = None
        org.scheduled_purge_at = None
        org.deletion_requested_by_id = None
        audit_service.record(
            db,
            action="organization_deletion_cancelled",
            user=user,
            tenant_id=organization_id,
            resource_type="organization",
            resource_id=organization_id,
            commit=False,
            strict=True,
        )
        db.commit()
        db.refresh(org)
        return org

    def purge_organization(self, db: Session, organization_id: str, *, force: bool = False) -> Tenant:
        org = db.query(Tenant).filter(Tenant.id == organization_id).with_for_update().first()
        if not org:
            raise ValueError("Organization not found")
        if org.status == OrganizationStatus.DELETED:
            return org
        now = get_utc_now()
        if org.status != OrganizationStatus.PENDING_DELETION:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error_code": "deletion_not_pending", "message": "Organization deletion is not pending"},
            )
        if not force and (
            not org.scheduled_purge_at or ensure_utc(org.scheduled_purge_at) > now
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error_code": "deletion_cooling_off_active", "message": "Organization cooling-off period has not ended"},
            )

        # Delete tenant-owned operational data in dependency order. Users and
        # audit logs are retained as immutable deletion evidence; primary users
        # are disabled below. The tenant row remains as a lifecycle tombstone.
        retained_tables = {
            "tenants", "users", "audit_logs", "audit_chain_states",
            "audit_retention_policies", "audit_legal_holds",
            "audit_archive_jobs", "audit_export_jobs",
        }
        for table in reversed(Base.metadata.sorted_tables):
            if table.name in retained_tables:
                continue
            predicate = self._tenant_owned_predicate(
                table,
                organization_id,
                retained_tables=retained_tables,
            )
            if predicate is not None:
                db.execute(table.delete().where(predicate))
        db.query(User).filter(User.tenant_id == organization_id).update(
            {User.is_active: False}, synchronize_session=False
        )
        org.status = OrganizationStatus.DELETED
        org.is_active = False
        org.deleted_at = now
        org.deletion_pin_hash = None
        org.deletion_pin_failed_attempts = 0
        org.deletion_pin_locked_until = None
        audit_service.record(
            db,
            action="organization_purged",
            tenant_id=organization_id,
            resource_type="organization",
            resource_id=organization_id,
            details={"purged_at": now.isoformat()},
            commit=False,
            strict=True,
        )
        db.commit()
        db.refresh(org)
        return org

    def purge_due_organizations(self, db: Session, *, limit: int = 100) -> list[str]:
        now = get_utc_now()
        ids = [
            row[0]
            for row in (
                db.query(Tenant.id)
                .filter(
                    Tenant.status == OrganizationStatus.PENDING_DELETION,
                    Tenant.scheduled_purge_at.isnot(None),
                    Tenant.scheduled_purge_at <= now,
                )
                .order_by(Tenant.scheduled_purge_at.asc())
                .limit(limit)
                .all()
            )
        ]
        purged = []
        for organization_id in ids:
            self.purge_organization(db, organization_id)
            purged.append(organization_id)
        return purged

    def _tenant_owned_predicate(
        self,
        table,
        organization_id: str,
        *,
        retained_tables: set[str],
        visited: set[str] | None = None,
    ):
        """Resolve direct and dependent tenant ownership without loading rows.

        This lets purge remove child rows that do not repeat ``tenant_id``
        (for example execution steps and logs) before their tenant-owned
        parents. Traversal never crosses retained users/audit/tombstones,
        preventing a multi-organization user's unrelated data from being
        selected through the user foreign key.
        """
        visited = set(visited or ())
        if table.name in visited or table.name in retained_tables:
            return None
        visited.add(table.name)
        if "tenant_id" in table.c:
            return table.c.tenant_id == organization_id

        ownership_paths = []
        for constraint in table.foreign_key_constraints:
            parent = constraint.referred_table
            parent_predicate = self._tenant_owned_predicate(
                parent,
                organization_id,
                retained_tables=retained_tables,
                visited=visited,
            )
            if parent_predicate is None:
                continue
            join_terms = [
                element.parent == element.column
                for element in constraint.elements
            ]
            ownership_paths.append(
                exists(select(1).select_from(parent).where(and_(parent_predicate, *join_terms)))
            )
        return or_(*ownership_paths) if ownership_paths else None

    def switch_organization(self, db: Session, user: User, organization_id: str) -> User:
        membership = self.require_membership(db, user, organization_id)
        persistent_user = db.get(User, user.id)
        if not persistent_user:
            raise ValueError("User not found")
        # Active organization belongs to the new session/token, not the global
        # user record. Mark the selected context as committed for this request
        # without persisting it.
        set_committed_value(persistent_user, "tenant_id", organization_id)
        set_committed_value(persistent_user, "tenant", membership.tenant)
        return persistent_user

    def list_members(self, db: Session, user: User, organization_id: str) -> list[OrganizationMembership]:
        active_membership(db, user, organization_id)
        if Permission.USERS_VIEW.value not in membership_permissions(db, user, organization_id):
            raise HTTPException(status_code=403, detail={"error_code": "PERMISSION_DENIED", "message": "Permission denied"})
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
        custom_role_id: str | None = None,
    ) -> OrganizationMembership:
        actor = active_membership(db, user, organization_id)
        membership = (
            db.query(OrganizationMembership)
            .filter(OrganizationMembership.id == membership_id, OrganizationMembership.tenant_id == organization_id)
            .first()
        )
        if not membership:
            raise ValueError("Membership not found")
        custom_role = None
        if custom_role_id is not None:
            custom_role = db.query(OrganizationCustomRole).filter_by(id=custom_role_id, tenant_id=organization_id).first()
            if not custom_role:
                raise ValueError("Custom role not found")
        authorization_policy.require_member_management(
            db,
            user,
            actor,
            membership,
            role=role,
            custom_permissions=set(custom_role.permissions or []) if custom_role else None,
            disabling=is_active is False,
        )
        if role is not None:
            if role == OrganizationRole.OWNER:
                if actor.role != OrganizationRole.OWNER:
                    raise HTTPException(status_code=403, detail={"error_code": "ROLE_ASSIGNMENT_DENIED", "message": "Only owners can assign owner authority"})
            if membership.role == OrganizationRole.OWNER and role != OrganizationRole.OWNER:
                owners = db.query(OrganizationMembership).filter_by(
                    tenant_id=organization_id, role=OrganizationRole.OWNER, is_active=True
                ).count()
                if owners <= 1:
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"error_code": "FINAL_OWNER_PROTECTED", "message": "The final organization owner cannot be removed"})
            membership.role = role
            membership.custom_role_id = None
        if custom_role_id is not None:
            membership.custom_role_id = custom_role.id
        if is_active is not None:
            if membership.role == OrganizationRole.OWNER and not is_active:
                owners = db.query(OrganizationMembership).filter_by(
                    tenant_id=organization_id, role=OrganizationRole.OWNER, is_active=True
                ).count()
                if owners <= 1:
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"error_code": "FINAL_OWNER_PROTECTED", "message": "The final organization owner cannot be disabled"})
            membership.is_active = is_active
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
        actor = active_membership(db, user, organization_id)
        permissions = membership_permissions(db, user, organization_id)
        if Permission.USERS_INVITE.value not in permissions:
            raise HTTPException(status_code=403, detail={"error_code": "PERMISSION_DENIED", "message": "Permission denied"})
        if not authorization_policy.can_assign_role(
            db, user, actor, target_membership=None, role=data.role,
        ):
            raise HTTPException(status_code=403, detail={"error_code": "ROLE_ASSIGNMENT_DENIED", "message": "Invitation role exceeds your authority"})
        self.enforce_limit(db, organization_id, "users")
        token = secrets.token_urlsafe(32)
        invited_user = db.query(User).filter(User.email == data.email).first()
        invitation = db.query(OrganizationInvitation).filter(
            OrganizationInvitation.tenant_id == organization_id,
            OrganizationInvitation.email == data.email,
            OrganizationInvitation.status == InvitationStatus.PENDING,
        ).first()
        if invitation:
            invitation.role = data.role
            invitation.token_hash = self.hash_invitation_token(token)
            invitation.expires_at = get_utc_now() + timedelta(days=data.expires_in_days)
        else:
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
        active_membership(db, user, organization_id)
        permissions = membership_permissions(db, user, organization_id)
        if not permissions.intersection({Permission.USERS_VIEW.value, Permission.USERS_INVITE.value}):
            raise HTTPException(status_code=403, detail={"error_code": "PERMISSION_DENIED", "message": "Permission denied"})
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
        usage_service.snapshot_current(db, organization_id, values)
        db.commit()
        values["limits"] = {
            "max_users": org.max_users,
            "max_collectors": org.max_collectors,
            "max_storage": org.max_storage,
        }
        return values

    def calculate_usage(self, db: Session, organization_id: str) -> dict:
        return usage_service.calculate_current(db, organization_id)

    def usage_history(self, db: Session, user: User, organization_id: str, start_date, end_date):
        self.require_membership(db, user, organization_id)
        return usage_service.history(db, organization_id, start_date, end_date)

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

    def _require_lifecycle_owner(
        self, db: Session, user: User, organization_id: str
    ) -> tuple[OrganizationMembership, Tenant]:
        membership = (
            db.query(OrganizationMembership)
            .filter(
                OrganizationMembership.user_id == user.id,
                OrganizationMembership.tenant_id == organization_id,
                OrganizationMembership.is_active == True,
                OrganizationMembership.role == OrganizationRole.OWNER,
            )
            .first()
        )
        org = db.query(Tenant).filter(Tenant.id == organization_id).with_for_update().first()
        if not membership or not org or org.status == OrganizationStatus.DELETED:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Organization owner permission required")
        return membership, org

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
