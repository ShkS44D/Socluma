import os
import tempfile
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.api.deps import get_current_user, get_db
from src.core.database import Base
from src.core.security import get_password_hash
from src.main import app
from src.models.sqlalchemy import (
    AuditLog,
    Collector,
    LogSource,
    OrganizationMembership,
    OrganizationRole,
    Tenant,
    User,
    UserRole,
)
from src.services.organization_service import organization_service


class OrganizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fd, cls.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        cls.engine = create_engine(
            f"sqlite:///{cls.db_path}",
            connect_args={"check_same_thread": False},
        )
        cls.SessionTesting = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.clear()
        cls.engine.dispose()
        if os.path.exists(cls.db_path):
            os.remove(cls.db_path)

    def setUp(self):
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=self.engine)
        Base.metadata.create_all(bind=self.engine)

        def override_get_db():
            db = self.SessionTesting()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.owner_id, self.tenant_id = self._create_user("owner@example.com", UserRole.ADMIN)
        self.viewer_id, _ = self._create_user("viewer@example.com", UserRole.VIEWER, tenant_id=self.tenant_id)
        self.outsider_id, self.outsider_tenant_id = self._create_user("outsider@example.com", UserRole.ADMIN, slug="outsider")

    def _create_user(
        self,
        email: str,
        role: UserRole,
        slug: str = "primary",
        tenant_id: str | None = None,
    ) -> tuple[str, str]:
        db = self.SessionTesting()
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first() if tenant_id else None
        if tenant is None:
            tenant = db.query(Tenant).filter(Tenant.slug == slug).first()
        if tenant is None:
            tenant = Tenant(name=f"{slug.title()} Org", slug=slug)
            db.add(tenant)
            db.flush()
        user = User(
            tenant_id=tenant.id,
            email=email,
            hashed_password=get_password_hash("Socluma-Test-Passphrase-2026!"),
            full_name=email.split("@")[0],
            role=role,
        )
        db.add(user)
        db.flush()
        organization_service.ensure_primary_membership(db, user)
        db.commit()
        user_id = user.id
        org_id = tenant.id
        db.close()
        return user_id, org_id

    def _as_user(self, user_id: str) -> None:
        def override_get_current_user():
            db = self.SessionTesting()
            try:
                return db.query(User).filter(User.id == user_id).first()
            finally:
                db.close()

        app.dependency_overrides[get_current_user] = override_get_current_user

    def test_organization_crud_switch_and_audit(self):
        self._as_user(self.owner_id)
        create_response = self.client.post(
            "/api/v1/organizations",
            json={
                "name": "Acme Security",
                "slug": "acme-security",
                "deletion_pin": "1234",
                "description": "Managed SOC",
                "industry": "Technology",
                "country": "US",
            },
        )
        self.assertEqual(create_response.status_code, 201, create_response.text)
        organization_id = create_response.json()["id"]

        switch_response = self.client.post("/api/v1/organizations/switch", json={"organization_id": organization_id})
        self.assertEqual(switch_response.status_code, 200, switch_response.text)
        self.assertIn("access_token", switch_response.json())

        list_response = self.client.get("/api/v1/organizations")
        self.assertEqual(list_response.status_code, 200)
        self.assertIn(organization_id, {org["id"] for org in list_response.json()})

        db = self.SessionTesting()
        actions = {row.action for row in db.query(AuditLog).all()}
        db.close()
        self.assertIn("organization_created", actions)
        self.assertIn("organization_switched", actions)

    def test_cross_tenant_organization_access_is_denied(self):
        self._as_user(self.outsider_id)
        response = self.client.get(f"/api/v1/organizations/{self.tenant_id}")
        self.assertEqual(response.status_code, 404, response.text)

    def test_invitation_acceptance_creates_membership(self):
        self._as_user(self.owner_id)
        invite_response = self.client.post(
            f"/api/v1/organizations/{self.tenant_id}/invitations",
            json={"email": "outsider@example.com", "role": "analyst"},
        )
        self.assertEqual(invite_response.status_code, 201, invite_response.text)
        token = invite_response.json()["token"]

        self._as_user(self.outsider_id)
        accept_response = self.client.post("/api/v1/organizations/invitations/accept", json={"token": token})
        self.assertEqual(accept_response.status_code, 200, accept_response.text)

        db = self.SessionTesting()
        membership = (
            db.query(OrganizationMembership)
            .filter(OrganizationMembership.user_id == self.outsider_id, OrganizationMembership.tenant_id == self.tenant_id)
            .one()
        )
        db.close()
        self.assertEqual(membership.role, OrganizationRole.ANALYST)

    def test_viewer_cannot_manage_members(self):
        self._as_user(self.viewer_id)
        response = self.client.get(f"/api/v1/organizations/{self.tenant_id}/members")
        self.assertEqual(response.status_code, 403, response.text)

    def test_collector_quota_is_enforced(self):
        db = self.SessionTesting()
        tenant = db.query(Tenant).filter(Tenant.id == self.tenant_id).one()
        tenant.max_collectors = 1
        db.add(Collector(tenant_id=self.tenant_id, name="existing", type="windows", token="token"))
        db.commit()
        db.close()

        self._as_user(self.owner_id)
        response = self.client.post(
            "/api/v1/collectors/register",
            json={"name": "blocked", "type": "windows"},
        )
        self.assertEqual(response.status_code, 403, response.text)

    def test_collector_registration_accepts_unassigned_log_source(self):
        self._as_user(self.owner_id)
        response = self.client.post(
            "/api/v1/collectors/register",
            json={
                "name": "Saad-Windows-PC",
                "type": "windows",
                "hostname": "saad-pc",
                "log_source_id": "",
            },
        )
        self.assertEqual(response.status_code, 201, response.text)

        db = self.SessionTesting()
        collector = db.query(Collector).filter(Collector.id == response.json()["id"]).one()
        self.assertIsNone(collector.log_source_id)
        db.close()

    def test_collector_registration_rejects_cross_tenant_log_source(self):
        db = self.SessionTesting()
        outsider_source = LogSource(
            tenant_id=self.outsider_tenant_id,
            name="Outsider source",
        )
        db.add(outsider_source)
        db.commit()
        source_id = outsider_source.id
        db.close()

        self._as_user(self.owner_id)
        response = self.client.post(
            "/api/v1/collectors/register",
            json={
                "name": "Cross-tenant collector",
                "type": "windows",
                "log_source_id": source_id,
            },
        )
        self.assertEqual(response.status_code, 404, response.text)
        self.assertEqual(response.json()["error_code"], "LOG_SOURCE_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
