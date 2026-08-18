import os
import tempfile
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.api.deps import get_current_user, get_db
from src.connectors.base import ActionConnectorBase, ConnectorRequest, ConnectorResult
from src.connectors.registry import connector_registry
from src.core.crypto import decrypt_json_secret
from src.core.database import Base
from src.core.security import get_password_hash
from src.main import app
from src.models.sqlalchemy import (
    ActionExecutionStatus,
    AuditLog,
    ConnectorActionExecution,
    ConnectorCredential,
    SOARActionApproval,
    Tenant,
    User,
    UserRole,
    OrganizationMembership,
    OrganizationRole,
)


class FakeWebhookConnector(ActionConnectorBase):
    connector_type = "webhook"
    display_name = "Fake Webhook"

    def validate(self, config, credentials=None):
        if not config.get("url"):
            raise ValueError("Missing url")

    def execute(self, request: ConnectorRequest) -> ConnectorResult:
        return ConnectorResult(success=True, status_code=200, response={"received": request.payload})

    def test_connection(self, config, credentials=None) -> ConnectorResult:
        return ConnectorResult(success=True, status_code=200, response={"ok": True})

    def health(self, config, credentials=None) -> ConnectorResult:
        return ConnectorResult(success=True, response={"healthy": True})


class SOARFrameworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fd, cls.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        cls.engine = create_engine(f"sqlite:///{cls.db_path}", connect_args={"check_same_thread": False})
        cls.SessionTesting = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)
        cls.client = TestClient(app)
        cls.original_webhook = connector_registry._connectors["webhook"]
        connector_registry.register(FakeWebhookConnector())

    @classmethod
    def tearDownClass(cls):
        connector_registry.register(cls.original_webhook)
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
        self.admin_id = self._create_user(UserRole.ADMIN)
        self.analyst_id = self._create_user(UserRole.ANALYST)
        self.viewer_id = self._create_user(UserRole.VIEWER)

    def _create_user(self, role: UserRole) -> str:
        db = self.SessionTesting()
        tenant = db.query(Tenant).filter(Tenant.slug == "soar-test").first()
        if tenant is None:
            tenant = Tenant(name="SOAR Test", slug="soar-test")
            db.add(tenant)
            db.flush()
        user = User(
            tenant_id=tenant.id,
            email=f"{role.value}-{os.urandom(2).hex()}@example.com",
            hashed_password=get_password_hash("TriageOps-Test-Passphrase-2026!"),
            full_name=f"{role.value.title()} User",
            role=role,
        )
        db.add(user)
        db.flush()
        db.add(OrganizationMembership(
            tenant_id=tenant.id, user_id=user.id,
            role={
                UserRole.ADMIN: OrganizationRole.ADMINISTRATOR,
                UserRole.ANALYST: OrganizationRole.ANALYST,
                UserRole.VIEWER: OrganizationRole.VIEWER,
            }[role],
            is_active=True,
        ))
        db.commit()
        db.refresh(user)
        user_id = user.id
        db.close()
        return user_id

    def _as_user(self, user_id: str) -> None:
        def override_get_current_user():
            db = self.SessionTesting()
            try:
                return db.query(User).filter(User.id == user_id).first()
            finally:
                db.close()

        app.dependency_overrides[get_current_user] = override_get_current_user

    def _create_connector(self, requires_approval=False) -> dict:
        self._as_user(self.admin_id)
        response = self.client.post(
            "/api/v1/soar/connectors",
            json={
                "name": "Case webhook",
                "type": "webhook",
                "config": {"url": "https://example.com/webhook"},
                "requires_approval": requires_approval,
                "approval_roles": ["admin"] if requires_approval else None,
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def test_credentials_are_encrypted_and_not_returned(self):
        connector = self._create_connector()
        response = self.client.post(
            "/api/v1/soar/credentials",
            json={
                "connector_id": connector["id"],
                "name": "prod webhook",
                "secret": {"bearer_token": "super-secret"},
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.assertNotIn("encrypted_secret", response.json())
        self.assertNotIn("super-secret", response.text)

        db = self.SessionTesting()
        credential = db.query(ConnectorCredential).first()
        decrypted = decrypt_json_secret(credential.encrypted_secret)
        db.close()
        self.assertEqual(decrypted["bearer_token"], "super-secret")
        self.assertNotIn("super-secret", credential.encrypted_secret)

    def test_action_execution_runs_through_worker_path_and_logs_history(self):
        connector = self._create_connector()
        response = self.client.post(
            "/api/v1/soar/executions",
            json={
                "connector_id": connector["id"],
                "action_name": "notify",
                "request": {"message": "hello"},
                "retry_policy": {"max_attempts": 2},
                "timeout_seconds": 5,
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["status"], "completed")

        logs = self.client.get(f"/api/v1/soar/executions/{response.json()['id']}/logs")
        self.assertEqual(logs.status_code, 200)
        self.assertGreaterEqual(len(logs.json()), 2)

        db = self.SessionTesting()
        execution = db.query(ConnectorActionExecution).first()
        db.close()
        self.assertEqual(execution.status, ActionExecutionStatus.COMPLETED)
        self.assertEqual(execution.response["received"]["message"], "hello")

    def test_approval_required_action_waits_then_runs_after_approval(self):
        connector = self._create_connector(requires_approval=True)
        response = self.client.post(
            "/api/v1/soar/executions",
            json={"connector_id": connector["id"], "action_name": "notify", "request": {"message": "approve me"}},
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["status"], "awaiting_approval")

        approvals = self.client.get("/api/v1/soar/approvals")
        self.assertEqual(approvals.status_code, 200)
        approval_id = approvals.json()[0]["id"]
        approve = self.client.post(f"/api/v1/soar/approvals/{approval_id}/approve", json={"comment": "ok"})
        self.assertEqual(approve.status_code, 403)
        db = self.SessionTesting()
        membership = db.query(OrganizationMembership).filter_by(user_id=self.admin_id).one()
        membership.role = OrganizationRole.OWNER
        db.commit()
        db.close()
        approve = self.client.post(f"/api/v1/soar/approvals/{approval_id}/approve", json={"comment": "owner approved"})
        self.assertEqual(approve.status_code, 200, approve.text)

        db = self.SessionTesting()
        execution = db.query(ConnectorActionExecution).filter(ConnectorActionExecution.id == response.json()["id"]).first()
        approval = db.query(SOARActionApproval).first()
        db.close()
        self.assertEqual(approval.status.value, "approved")
        self.assertEqual(execution.status, ActionExecutionStatus.COMPLETED)

    def test_viewer_cannot_manage_connectors_or_credentials(self):
        self._as_user(self.viewer_id)
        response = self.client.post(
            "/api/v1/soar/connectors",
            json={"name": "nope", "type": "webhook", "config": {"url": "https://example.com"}},
        )
        self.assertEqual(response.status_code, 403)

        connector = self._create_connector()
        self._as_user(self.viewer_id)
        credential = self.client.post(
            "/api/v1/soar/credentials",
            json={"connector_id": connector["id"], "name": "secret", "secret": {"bearer_token": "x"}},
        )
        self.assertEqual(credential.status_code, 403)

    def test_audit_events_are_recorded(self):
        connector = self._create_connector()
        self.client.post(
            "/api/v1/soar/executions",
            json={"connector_id": connector["id"], "action_name": "notify", "request": {"message": "audit"}},
        )

        db = self.SessionTesting()
        actions = {row.action for row in db.query(AuditLog).all()}
        db.close()
        self.assertIn("soar_connector_created", actions)
        self.assertIn("soar_action_requested", actions)


if __name__ == "__main__":
    unittest.main()
