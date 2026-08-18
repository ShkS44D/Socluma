from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from src.core.permissions import (
    OWNER_ONLY_PERMISSIONS,
    Permission,
    membership_permissions,
)
from src.models.sqlalchemy import OrganizationMembership, OrganizationRole, User


def policy_error(code: str, message: str, *, hide: bool = False) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND if hide else status.HTTP_403_FORBIDDEN,
        detail={"error_code": code, "message": message},
    )


class AuthorizationPolicy:
    def permissions_for_membership(self, db: Session, membership: OrganizationMembership) -> set[str]:
        if membership.custom_role:
            from src.core.permissions import ALL_PERMISSIONS, LEGACY_PERMISSION_MAP
            return {
                LEGACY_PERMISSION_MAP.get(item, item)
                for item in (membership.custom_role.permissions or [])
                if LEGACY_PERMISSION_MAP.get(item, item) in ALL_PERMISSIONS
            }
        from src.core.permissions import ROLE_PERMISSIONS
        return set(ROLE_PERMISSIONS.get(membership.role, set()))

    def can_assign_role(
        self,
        db: Session,
        actor: User,
        actor_membership: OrganizationMembership,
        *,
        target_membership: OrganizationMembership | None,
        role: OrganizationRole | None,
        custom_permissions: set[str] | None = None,
    ) -> bool:
        actor_permissions = membership_permissions(db, actor, actor_membership.tenant_id)
        proposed = custom_permissions or set()
        if role:
            from src.core.permissions import ROLE_PERMISSIONS
            proposed = set(ROLE_PERMISSIONS.get(role, set()))
        if Permission.ROLES_ASSIGN.value not in actor_permissions:
            return False
        if proposed - actor_permissions:
            return False
        if proposed.intersection(OWNER_ONLY_PERMISSIONS) and actor_membership.role != OrganizationRole.OWNER:
            return False
        if target_membership:
            target_permissions = self.permissions_for_membership(db, target_membership)
            if target_permissions - actor_permissions:
                return False
        return True

    def require_member_management(
        self,
        db: Session,
        actor: User,
        actor_membership: OrganizationMembership,
        target: OrganizationMembership,
        *,
        role: OrganizationRole | None,
        custom_permissions: set[str] | None = None,
        disabling: bool = False,
    ) -> None:
        if actor_membership.tenant_id != target.tenant_id:
            raise policy_error("TENANT_MISMATCH", "Resource is not available", hide=True)
        if actor.id == target.user_id and (
            role is not None or custom_permissions is not None or disabling
        ):
            raise policy_error("PRIVILEGE_ESCALATION_BLOCKED", "You cannot change your own authority")
        if target.role == OrganizationRole.OWNER and actor_membership.role != OrganizationRole.OWNER:
            raise policy_error("ROLE_ASSIGNMENT_DENIED", "Only an owner can manage another owner")
        if not self.can_assign_role(
            db,
            actor,
            actor_membership,
            target_membership=target,
            role=role or target.role,
            custom_permissions=custom_permissions,
        ):
            raise policy_error("PRIVILEGE_ESCALATION_BLOCKED", "Role assignment exceeds your authority")

    def require_owner(self, membership: OrganizationMembership) -> None:
        if membership.role != OrganizationRole.OWNER:
            raise policy_error("OWNER_REQUIRED", "Organization owner authority is required")

    def can_revoke_session(self, actor: User, session_user_id: str, permissions: set[str]) -> bool:
        return actor.id == session_user_id or Permission.ORGANIZATION_SECURITY_MANAGE.value in permissions

    def can_access_tenant_resource(self, active_tenant_id: str, resource_tenant_id: str) -> bool:
        return bool(active_tenant_id and resource_tenant_id and active_tenant_id == resource_tenant_id)


authorization_policy = AuthorizationPolicy()
