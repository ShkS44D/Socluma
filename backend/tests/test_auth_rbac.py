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
    Classification,
    OrganizationMembership,
    OrganizationRole,
    Tenant,
    User,
    UserRole,
)


class AuthAndRbacTests(unittest.TestCase):
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

    def _create_user(self, role: UserRole) -> str:
        db = self.SessionTesting()
        tenant = db.query(Tenant).filter(Tenant.slug == "test-tenant").first()
        if tenant is None:
            tenant = Tenant(name="Test Tenant", slug="test-tenant")
            db.add(tenant)
            db.flush()
        user = User(
            tenant_id=tenant.id,
            email=f"{role.value}@example.com",
            hashed_password=get_password_hash("Socluma-Test-Passphrase-2026!"),
            full_name=f"{role.value.title()} User",
            role=role,
        )
        db.add(user)
        db.flush()
        membership_role = {
            UserRole.ADMIN: OrganizationRole.ADMINISTRATOR,
            UserRole.ANALYST: OrganizationRole.ANALYST,
            UserRole.VIEWER: OrganizationRole.VIEWER,
        }[role]
        db.add(OrganizationMembership(
            tenant_id=tenant.id,
            user_id=user.id,
            role=membership_role,
            is_active=True,
        ))
        db.commit()
        db.refresh(user)
        user_id = user.id
        db.close()
        return user_id

    def _override_current_user(self, user_id: str) -> None:
        def override_get_current_user():
            db = self.SessionTesting()
            try:
                return db.query(User).filter(User.id == user_id).first()
            finally:
                db.close()

        app.dependency_overrides[get_current_user] = override_get_current_user

    def _create_correlated_incident(self, source: str, raw_data: dict) -> str:
        base = {
            "hostname": "rbac-host-01",
            "agent_id": "rbac-agent-01",
            "source_ip": "10.0.0.5",
            **raw_data,
        }
        first = self.client.post("/api/v1/alerts", json={"source": source, "raw_data": base})
        self.assertEqual(first.status_code, 201)
        follow_up = {**base, "event_id": "follow-up-alert"}
        if base.get("event_type") == "malware_detection":
            follow_up["file_hash"] = "def456"
        elif base.get("event_type") == "suspicious_network":
            follow_up["event_type"] = "connection"
        second = self.client.post(
            "/api/v1/alerts",
            json={"source": source, "raw_data": follow_up},
        )
        self.assertEqual(second.status_code, 201)
        incidents_response = self.client.get("/api/v1/incidents")
        self.assertEqual(incidents_response.status_code, 200)
        items = incidents_response.json()["items"]
        self.assertEqual(len(items), 1)
        return items[0]["id"]

    def test_register_login_and_me_records_audit_events(self):
        register_response = self.client.post(
            "/api/v1/auth/register",
            json={
                "email": "admin@example.com",
                "password": "Socluma-Test-Passphrase-2026!",
                "full_name": "Admin User",
                "tenant_name": "Test Tenant",
                "tenant_slug": "test-tenant",
            },
        )
        self.assertEqual(register_response.status_code, 201)

        login_response = self.client.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "Socluma-Test-Passphrase-2026!"},
        )
        self.assertEqual(login_response.status_code, 200)
        token = login_response.json()["access_token"]

        me_response = self.client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(me_response.status_code, 200)
        self.assertEqual(me_response.json()["email"], "admin@example.com")
        self.assertEqual(me_response.json()["role"], "admin")

        db = self.SessionTesting()
        actions = [row.action for row in db.query(AuditLog).order_by(AuditLog.created_at).all()]
        db.close()
        self.assertIn("registration", actions)
        self.assertIn("login", actions)

    def test_protected_route_rejects_missing_token(self):
        response = self.client.get("/api/v1/incidents")
        self.assertEqual(response.status_code, 403)

    def test_viewer_can_read_but_cannot_create_alert(self):
        user_id = self._create_user(UserRole.VIEWER)
        self._override_current_user(user_id)

        list_response = self.client.get("/api/v1/alerts")
        self.assertEqual(list_response.status_code, 200)

        create_response = self.client.post(
            "/api/v1/alerts",
            json={
                "source": "ids",
                "raw_data": {
                    "event_type": "suspicious_network",
                    "source_ip": "10.0.0.5",
                    "destination_ip": "198.51.100.25",
                    "severity": "medium",
                },
            },
        )
        self.assertEqual(create_response.status_code, 403)

    def test_analyst_can_create_alert_and_submit_feedback_with_audit(self):
        user_id = self._create_user(UserRole.ANALYST)
        self._override_current_user(user_id)

        incident_id = self._create_correlated_incident(
            "antivirus",
            {
                "event_type": "malware_detection",
                "malware_name": "Trojan.Generic.12345",
                "file_hash": "abc123",
                "severity": "critical",
            },
        )

        feedback_response = self.client.post(
            f"/api/v1/incidents/{incident_id}/feedback",
            json={
                "classification": Classification.TRUE_POSITIVE.value,
                "comment": "Confirmed malicious file.",
            },
        )
        self.assertEqual(feedback_response.status_code, 200)

        db = self.SessionTesting()
        actions = {row.action for row in db.query(AuditLog).all()}
        db.close()
        self.assertIn("alert_created", actions)
        self.assertIn("analyst_feedback_submitted", actions)

    def test_admin_can_assign_incident_and_analyst_can_add_note_with_audit(self):
        admin_id = self._create_user(UserRole.ADMIN)
        analyst_id = self._create_user(UserRole.ANALYST)

        self._override_current_user(admin_id)
        incident_id = self._create_correlated_incident(
            "ids",
            {
                "event_type": "suspicious_network",
                "destination_ip": "198.51.100.25",
                "severity": "high",
            },
        )

        assign_response = self.client.post(
            f"/api/v1/incidents/{incident_id}/assign",
            json={"user_id": analyst_id},
        )
        self.assertEqual(assign_response.status_code, 200)
        self.assertEqual(assign_response.json()["assigned_to"], analyst_id)

        self._override_current_user(analyst_id)
        note_response = self.client.post(
            f"/api/v1/incidents/{incident_id}/notes",
            json={"content": "Started triage and validated network path."},
        )
        self.assertEqual(note_response.status_code, 200)
        self.assertEqual(note_response.json()["user_id"], analyst_id)

        assigned_response = self.client.get("/api/v1/incidents/assigned")
        self.assertEqual(assigned_response.status_code, 200)
        self.assertEqual(len(assigned_response.json()), 1)

        db = self.SessionTesting()
        actions = {row.action for row in db.query(AuditLog).all()}
        db.close()
        self.assertIn("incident_assigned", actions)
        self.assertIn("investigation_note_added", actions)

    def test_viewer_cannot_change_incident_status_or_submit_feedback(self):
        analyst_id = self._create_user(UserRole.ANALYST)
        self._override_current_user(analyst_id)

        incident_id = self._create_correlated_incident(
            "ids",
            {
                "event_type": "suspicious_network",
                "destination_ip": "198.51.100.25",
                "severity": "medium",
            },
        )

        viewer_id = self._create_user(UserRole.VIEWER)
        self._override_current_user(viewer_id)

        status_response = self.client.post(
            f"/api/v1/incidents/{incident_id}/status",
            json={"status": "investigating"},
        )
        self.assertEqual(status_response.status_code, 403)

        feedback_response = self.client.post(
            f"/api/v1/incidents/{incident_id}/feedback",
            json={"classification": Classification.BENIGN.value},
        )
        self.assertEqual(feedback_response.status_code, 403)

    def test_viewer_cannot_assign_incident_or_add_note(self):
        admin_id = self._create_user(UserRole.ADMIN)
        analyst_id = self._create_user(UserRole.ANALYST)

        self._override_current_user(analyst_id)
        incident_id = self._create_correlated_incident(
            "ids",
            {
                "event_type": "suspicious_network",
                "destination_ip": "198.51.100.25",
                "severity": "medium",
            },
        )

        viewer_id = self._create_user(UserRole.VIEWER)
        self._override_current_user(viewer_id)

        assign_response = self.client.post(
            f"/api/v1/incidents/{incident_id}/assign",
            json={"user_id": admin_id},
        )
        self.assertEqual(assign_response.status_code, 403)

        note_response = self.client.post(
            f"/api/v1/incidents/{incident_id}/notes",
            json={"content": "Viewer should not be allowed to add notes."},
        )
        self.assertEqual(note_response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
