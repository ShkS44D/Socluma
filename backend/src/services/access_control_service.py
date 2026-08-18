from __future__ import annotations

import re

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.core.permissions import (
    ALL_PERMISSIONS,
    LEGACY_PERMISSION_MAP,
    OWNER_ONLY_PERMISSIONS,
    Permission,
    active_membership,
    membership_permissions,
)
from src.models.sqlalchemy import OrganizationCustomRole, OrganizationMembership, OrganizationRole, User


RESERVED_ROLE_NAMES = {
    "owner", "administrator", "admin", "soc manager", "soc_manager", "analyst", "viewer",
}


class AccessControlService:
    def normalize_name(self, name: str) -> tuple[str, str]:
        display = re.sub(r"\s+", " ", name.strip())
        normalized = display.casefold()
        if normalized in RESERVED_ROLE_NAMES:
            raise HTTPException(
                status_code=422,
                detail={"error_code": "ROLE_PROTECTED", "message": "This role name is reserved"},
            )
        return display, normalized

    def validate_permissions(
        self,
        db: Session,
        actor: User,
        permissions: list[str],
        *,
        allow_owner_only: bool = False,
    ) -> list[str]:
        normalized = {LEGACY_PERMISSION_MAP.get(item, item) for item in permissions}
        unknown = sorted(item for item in normalized if item not in ALL_PERMISSIONS)
        if unknown:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error_code": "UNKNOWN_PERMISSION", "message": "Permission selection contains unknown identifiers"},
            )
        actor_permissions = membership_permissions(db, actor)
        if normalized - actor_permissions:
            raise HTTPException(
                status_code=403,
                detail={"error_code": "PRIVILEGE_ESCALATION_BLOCKED", "message": "You cannot grant permissions you do not possess"},
            )
        # Custom roles deliberately cannot carry protected owner semantics.
        if normalized.intersection(OWNER_ONLY_PERMISSIONS) and not allow_owner_only:
            raise HTTPException(
                status_code=403,
                detail={"error_code": "OWNER_ONLY_PERMISSION", "message": "Owner-only permissions cannot be assigned to a custom role"},
            )
        return sorted(normalized)

    def create_role(self, db: Session, user: User, tenant_id: str, data):
        membership = active_membership(db, user, tenant_id)
        if Permission.ROLES_CREATE.value not in membership_permissions(db, user, tenant_id):
            raise HTTPException(status_code=403, detail={"error_code": "PERMISSION_DENIED", "message": "Permission denied"})
        name, normalized_name = self.normalize_name(data.name)
        role = OrganizationCustomRole(
            tenant_id=tenant_id,
            name=name,
            normalized_name=normalized_name,
            description=data.description,
            permissions=self.validate_permissions(db, user, data.permissions),
            is_system=False,
            is_protected=False,
        )
        db.add(role)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail={"error_code": "ROLE_NAME_CONFLICT", "message": "A role with this name already exists"},
            ) from exc
        db.refresh(role)
        return role

    def update_role(self, db: Session, user: User, tenant_id: str, role_id: str, data):
        membership = active_membership(db, user, tenant_id)
        if Permission.ROLES_UPDATE.value not in membership_permissions(db, user, tenant_id):
            raise HTTPException(status_code=403, detail={"error_code": "PERMISSION_DENIED", "message": "Permission denied"})
        role = db.query(OrganizationCustomRole).filter_by(id=role_id, tenant_id=tenant_id).first()
        if not role:
            raise HTTPException(status_code=404, detail={"error_code": "ROLE_NOT_FOUND", "message": "Role not found"})
        if role.is_system or role.is_protected:
            raise HTTPException(status_code=403, detail={"error_code": "ROLE_PROTECTED", "message": "Protected roles cannot be changed"})
        if membership.custom_role_id == role.id and data.permissions is not None:
            removed = set(role.permissions or []) - set(data.permissions)
            if Permission.ROLES_UPDATE.value in removed:
                raise HTTPException(
                    status_code=409,
                    detail={"error_code": "SELF_AUTHORITY_CHANGE_BLOCKED", "message": "Reassign yourself before removing role-management authority"},
                )
        if data.name is not None:
            role.name, role.normalized_name = self.normalize_name(data.name)
        if data.description is not None:
            role.description = data.description
        if data.permissions is not None:
            role.permissions = self.validate_permissions(db, user, data.permissions)
        role.permission_revision = (role.permission_revision or 1) + 1
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail={"error_code": "ROLE_NAME_CONFLICT", "message": "Role name already exists"}) from exc
        db.refresh(role)
        return role

    def delete_role(self, db: Session, user: User, tenant_id: str, role_id: str):
        active_membership(db, user, tenant_id)
        if Permission.ROLES_DELETE.value not in membership_permissions(db, user, tenant_id):
            raise HTTPException(status_code=403, detail={"error_code": "PERMISSION_DENIED", "message": "Permission denied"})
        role = db.query(OrganizationCustomRole).filter_by(id=role_id, tenant_id=tenant_id).first()
        if not role:
            raise HTTPException(status_code=404, detail={"error_code": "ROLE_NOT_FOUND", "message": "Role not found"})
        if role.is_system or role.is_protected:
            raise HTTPException(status_code=403, detail={"error_code": "ROLE_PROTECTED", "message": "Protected roles cannot be deleted"})
        if db.query(OrganizationMembership).filter_by(custom_role_id=role.id, is_active=True).count():
            raise HTTPException(status_code=409, detail={"error_code": "ROLE_IN_USE", "message": "Role is currently assigned"})
        db.delete(role)
        db.commit()


access_control_service = AccessControlService()
