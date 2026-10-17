import os
import tempfile
from datetime import timedelta

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.api.deps import get_current_user, get_db
from src.core.config import get_settings
from src.core.database import Base
from src.core.permissions import (
    ALL_PERMISSIONS,
    OWNER_ONLY_PERMISSIONS,
    Permission,
    ROLE_PERMISSIONS,
)
from src.core.security import get_password_hash
from src.main import app
from src.models.pydantic import (
    ApprovalRequestCreate,
    CustomRoleCreate,
    OrganizationMemberUpdate,
)
from src.models.sqlalchemy import (
    OrganizationAPIKey,
    OrganizationCustomRole,
    OrganizationMembership,
    OrganizationRole,
    Tenant,
    User,
    UserRole,
)
from src.services.access_control_service import access_control_service
from src.services.api_key_service import api_key_service
from src.services.approval_service import approval_service
from src.services.auth_service import auth_service
from src.services.organization_service import organization_service
from src.utils.datetime_utils import get_utc_now


PASSWORD = "Socluma-Test-Passphrase-2026!"


@pytest.fixture()
def phase3():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    factory = sessionmaker(bind=engine)
    Base.metadata.create_all(engine)
    db = factory()
    tenant = Tenant(name="Alpha", slug="alpha")
    other = Tenant(name="Bravo", slug="bravo")
    db.add_all([tenant, other])
    db.flush()

    users = {}
    for role in OrganizationRole:
        user = User(
            tenant_id=tenant.id,
            email=f"{role.value.replace('_', '-')}@example.com",
            hashed_password=get_password_hash(PASSWORD),
            role=UserRole.ADMIN if role in {OrganizationRole.OWNER, OrganizationRole.ADMINISTRATOR} else UserRole.ANALYST,
        )
        db.add(user)
        db.flush()
        db.add(OrganizationMembership(
            tenant_id=tenant.id, user_id=user.id, role=role, is_active=True
        ))
        users[role] = user

    outsider = User(
        tenant_id=other.id,
        email="outsider@example.com",
        hashed_password=get_password_hash(PASSWORD),
        role=UserRole.ADMIN,
    )
    no_membership = User(
        tenant_id=tenant.id,
        email="nomembership@example.com",
        hashed_password=get_password_hash(PASSWORD),
        role=UserRole.ADMIN,
    )
    disabled = User(
        tenant_id=tenant.id,
        email="disabled@example.com",
        hashed_password=get_password_hash(PASSWORD),
        role=UserRole.ADMIN,
    )
    db.add_all([outsider, no_membership, disabled])
    db.flush()
    db.add_all([
        OrganizationMembership(
            tenant_id=other.id, user_id=outsider.id, role=OrganizationRole.OWNER, is_active=True
        ),
        OrganizationMembership(
            tenant_id=tenant.id, user_id=disabled.id, role=OrganizationRole.ADMINISTRATOR, is_active=False
        ),
    ])
    db.commit()

    def override_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app)

    def act_as(user_id):
        def override_user():
            session = factory()
            try:
                return session.get(User, user_id)
            finally:
                session.close()
        app.dependency_overrides[get_current_user] = override_user

    yield {
        "db": db, "factory": factory, "client": client, "tenant": tenant,
        "other": other, "users": users, "outsider": outsider,
        "no_membership": no_membership, "disabled": disabled, "act_as": act_as,
    }
    app.dependency_overrides.clear()
    client.close()
    db.close()
    engine.dispose()
    os.remove(path)


def test_permission_catalog_and_built_in_role_boundaries():
    assert Permission.ORGANIZATION_DELETE.value in ALL_PERMISSIONS
    assert OWNER_ONLY_PERMISSIONS <= ROLE_PERMISSIONS[OrganizationRole.OWNER]
    assert not OWNER_ONLY_PERMISSIONS.intersection(
        ROLE_PERMISSIONS[OrganizationRole.ADMINISTRATOR]
    )
    assert Permission.SOAR_APPROVE.value not in ROLE_PERMISSIONS[OrganizationRole.ADMINISTRATOR]
    assert Permission.ALERTS_UPDATE.value in ROLE_PERMISSIONS[OrganizationRole.ANALYST]
    assert Permission.ALERTS_UPDATE.value not in ROLE_PERMISSIONS[OrganizationRole.VIEWER]


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        (OrganizationRole.OWNER, 200),
        (OrganizationRole.ADMINISTRATOR, 200),
        (OrganizationRole.SOC_MANAGER, 200),
        (OrganizationRole.ANALYST, 403),
        (OrganizationRole.VIEWER, 403),
    ],
)
def test_role_matrix_is_enforced_by_permission(phase3, role, expected):
    phase3["act_as"](phase3["users"][role].id)
    response = phase3["client"].get("/api/v1/access-control/permissions")
    assert response.status_code == expected, response.text
    effective = phase3["client"].get("/api/v1/access-control/effective")
    assert effective.status_code == 200
    assert effective.json()["role"] == role.value


def test_missing_disabled_and_cross_tenant_context_are_denied(phase3):
    for key, code in (("no_membership", "MEMBERSHIP_REQUIRED"), ("disabled", "MEMBERSHIP_DISABLED")):
        phase3["act_as"](phase3[key].id)
        response = phase3["client"].get("/api/v1/access-control/effective")
        assert response.status_code == 403
        assert response.json()["error_code"] == code

    phase3["act_as"](phase3["users"][OrganizationRole.OWNER].id)
    response = phase3["client"].get(
        f"/api/v1/organizations/{phase3['other'].id}/members"
    )
    assert response.status_code == 404
    assert response.json()["error_code"] == "RESOURCE_ACCESS_DENIED"


def test_custom_roles_validate_names_permissions_and_tenant_isolation(phase3):
    db = phase3["db"]
    owner = phase3["users"][OrganizationRole.OWNER]
    role = access_control_service.create_role(
        db, owner, phase3["tenant"].id,
        CustomRoleCreate(name="  Incident   Reviewer ", permissions=["incidents.view"]),
    )
    assert role.name == "Incident Reviewer"
    assert role.normalized_name == "incident reviewer"

    with pytest.raises(HTTPException) as reserved:
        access_control_service.create_role(
            db, owner, phase3["tenant"].id,
            CustomRoleCreate(name="Administrator", permissions=[]),
        )
    assert reserved.value.detail["error_code"] == "ROLE_PROTECTED"

    with pytest.raises(HTTPException) as unknown:
        access_control_service.create_role(
            db, owner, phase3["tenant"].id,
            CustomRoleCreate(name="Unknown Scope", permissions=["platform.superuser"]),
        )
    assert unknown.value.detail["error_code"] == "UNKNOWN_PERMISSION"

    with pytest.raises(HTTPException) as protected:
        access_control_service.create_role(
            db, owner, phase3["tenant"].id,
            CustomRoleCreate(name="Fake Owner", permissions=["organization.delete"]),
        )
    assert protected.value.detail["error_code"] == "OWNER_ONLY_PERMISSION"

    phase3["act_as"](owner.id)
    assert phase3["client"].delete(
        f"/api/v1/access-control/roles/{role.id}"
    ).status_code == 204
    phase3["act_as"](phase3["outsider"].id)
    assert phase3["client"].get("/api/v1/access-control/roles").status_code == 200
    assert phase3["client"].get("/api/v1/access-control/roles").json() == []


def test_member_escalation_and_final_owner_are_protected(phase3):
    db = phase3["db"]
    admin = phase3["users"][OrganizationRole.ADMINISTRATOR]
    owner = phase3["users"][OrganizationRole.OWNER]
    owner_membership = db.query(OrganizationMembership).filter_by(
        tenant_id=phase3["tenant"].id, user_id=owner.id
    ).one()
    with pytest.raises(HTTPException) as escalation:
        organization_service.update_member(
            db, admin, phase3["tenant"].id, owner_membership.id,
            OrganizationRole.VIEWER, None,
        )
    assert escalation.value.detail["error_code"] == "ROLE_ASSIGNMENT_DENIED"

    with pytest.raises(HTTPException) as final_owner:
        organization_service.update_member(
            db, owner, phase3["tenant"].id, owner_membership.id,
            None, False,
        )
    assert final_owner.value.detail["error_code"] in {
        "PRIVILEGE_ESCALATION_BLOCKED", "FINAL_OWNER_PROTECTED"
    }


def test_api_keys_are_hash_only_scoped_expiring_and_tenant_bound(phase3):
    db = phase3["db"]
    owner = phase3["users"][OrganizationRole.OWNER]
    record, raw = api_key_service.create(
        db, owner, "Automation", [Permission.ALERTS_VIEW.value], 30
    )
    assert raw.startswith("tok_")
    assert raw not in record.key_hash
    assert db.query(OrganizationAPIKey).filter_by(key_hash=raw).first() is None
    assert api_key_service.authenticate(db, raw, Permission.ALERTS_VIEW.value).id == record.id

    with pytest.raises(HTTPException) as scope:
        api_key_service.authenticate(db, raw, Permission.ALERTS_CREATE.value)
    assert scope.value.detail["error_code"] == "API_KEY_SCOPE_DENIED"

    record.expires_at = get_utc_now() - timedelta(seconds=1)
    db.commit()
    with pytest.raises(HTTPException):
        api_key_service.authenticate(db, raw, Permission.ALERTS_VIEW.value)


def test_two_person_approval_is_bound_non_reusable_and_requester_excluded(phase3):
    db = phase3["db"]
    tenant = phase3["tenant"]
    tenant.sensitive_action_approval_mode = "two_person"
    requester = phase3["users"][OrganizationRole.OWNER]
    approver_one = User(
        tenant_id=tenant.id, email="approver1@example.com",
        hashed_password=get_password_hash(PASSWORD), role=UserRole.ADMIN,
    )
    approver_two = User(
        tenant_id=tenant.id, email="approver2@example.com",
        hashed_password=get_password_hash(PASSWORD), role=UserRole.ADMIN,
    )
    db.add_all([approver_one, approver_two])
    db.flush()
    db.add_all([
        OrganizationMembership(tenant_id=tenant.id, user_id=approver_one.id, role=OrganizationRole.OWNER),
        OrganizationMembership(tenant_id=tenant.id, user_id=approver_two.id, role=OrganizationRole.OWNER),
    ])
    db.commit()

    data = ApprovalRequestCreate(
        action_type="organization.delete",
        target_resource_type="organization",
        target_resource_id=tenant.id,
        safe_metadata={"reason": "test"},
        expires_in_minutes=30,
    )
    approval = approval_service.create(db, requester, data)
    assert approval.required_approvals == 2
    with pytest.raises(HTTPException):
        approval_service.decide(db, requester, approval.id, "approve")
    assert approval_service.decide(db, approver_one, approval.id, "approve").status == "pending"
    assert approval_service.decide(db, approver_two, approval.id, "approve").status == "approved"

    approval_service.require_and_consume(
        db, requester, approval.id, action_type="organization.delete",
        target_type="organization", target_id=tenant.id,
    )
    with pytest.raises(HTTPException) as reuse:
        approval_service.require_and_consume(
            db, requester, approval.id, action_type="organization.delete",
            target_type="organization", target_id=tenant.id,
        )
    assert reuse.value.detail["error_code"] == "APPROVAL_INVALID"


def test_switch_tokens_bind_tenant_without_mutating_global_user_context(phase3):
    db = phase3["db"]
    user = phase3["users"][OrganizationRole.OWNER]
    original_tenant = user.tenant_id
    db.add(OrganizationMembership(
        tenant_id=phase3["other"].id, user_id=user.id,
        role=OrganizationRole.VIEWER, is_active=True,
    ))
    db.commit()
    switched = organization_service.switch_organization(db, user, phase3["other"].id)
    token_pair = auth_service.create_token_pair(db, switched)
    claims = jwt.decode(
        token_pair["access_token"],
        get_settings().JWT_SECRET_KEY,
        algorithms=[get_settings().ALGORITHM],
        issuer=get_settings().JWT_ISSUER,
    )
    assert claims["tid"] == phase3["other"].id
    db.expire_all()
    assert db.get(User, user.id).tenant_id == original_tenant
