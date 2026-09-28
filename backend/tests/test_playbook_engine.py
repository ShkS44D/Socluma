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
    Incident,
    Playbook,
    PlaybookApproval,
    PlaybookExecution,
    PlaybookExecutionStatus,
    PlaybookRunLog,
    Tenant,
    User,
    UserRole,
    OrganizationMembership,
    OrganizationRole,
)


class PlaybookEngineTests(unittest.TestCase):
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
        self.admin_id = self._create_user(UserRole.ADMIN)
        self.analyst_id = self._create_user(UserRole.ANALYST)
        self.viewer_id = self._create_user(UserRole.VIEWER)

    def _create_user(self, role: UserRole) -> str:
        db = self.SessionTesting()
        tenant = db.query(Tenant).filter(Tenant.slug == "playbook-test").first()
        if tenant is None:
            tenant = Tenant(name="Playbook Test", slug="playbook-test")
            db.add(tenant)
            db.flush()
        user = User(
            tenant_id=tenant.id,
            email=f"{role.value}-{len(role.value)}@example.com",
            hashed_password=get_password_hash("VigilantAI-Test-Passphrase-2026!"),
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

    def _create_playbook(self, steps: list[dict]) -> dict:
        self._as_user(self.admin_id)
        response = self.client.post(
            "/api/v1/playbooks",
            json={
                "name": "Containment Review",
                "description": "Analyst-guided containment flow",
                "trigger_type": "manual_run",
                "steps": steps,
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def test_crud_version_publish_activate_and_execute(self):
        playbook = self._create_playbook(
            [
                {
                    "step_key": "notify",
                    "name": "Notify owner",
                    "type": "notification",
                    "config": {"title": "Playbook started"},
                },
                {"step_key": "end", "name": "End", "type": "end", "config": {}},
            ]
        )

        versions_response = self.client.get(f"/api/v1/playbooks/{playbook['id']}/versions")
        self.assertEqual(versions_response.status_code, 200)
        version = versions_response.json()[0]

        publish_response = self.client.post(f"/api/v1/playbooks/{playbook['id']}/versions/{version['id']}/publish")
        self.assertEqual(publish_response.status_code, 200, publish_response.text)
        activate_response = self.client.post(f"/api/v1/playbooks/{playbook['id']}/activate")
        self.assertEqual(activate_response.status_code, 200)
        self.assertEqual(activate_response.json()["status"], "active")

        execution_response = self.client.post(f"/api/v1/playbooks/{playbook['id']}/execute", json={"context": {"source": "test"}})
        self.assertEqual(execution_response.status_code, 201, execution_response.text)
        self.assertEqual(execution_response.json()["status"], "completed")

        steps_response = self.client.get(f"/api/v1/playbooks/executions/{execution_response.json()['id']}/steps")
        self.assertEqual(steps_response.status_code, 200)
        self.assertEqual([step["status"] for step in steps_response.json()], ["completed", "completed"])

        logs_response = self.client.get(f"/api/v1/playbooks/executions/{execution_response.json()['id']}/logs")
        self.assertEqual(logs_response.status_code, 200)
        self.assertGreaterEqual(len(logs_response.json()), 2)

    def test_list_playbooks_handles_legacy_missing_defaults(self):
        self._as_user(self.admin_id)
        db = self.SessionTesting()
        user = db.query(User).filter(User.id == self.admin_id).first()
        playbook = Playbook(
            tenant_id=user.tenant_id,
            name="Legacy Playbook",
            status=None,
            trigger_type=None,
            created_by=user.id,
        )
        db.add(playbook)
        db.commit()
        db.close()

        response = self.client.get("/api/v1/playbooks")
        self.assertEqual(response.status_code, 200, response.text)
        legacy = next(item for item in response.json() if item["name"] == "Legacy Playbook")
        self.assertEqual(legacy["status"], "draft")
        self.assertEqual(legacy["trigger_type"], "manual_run")

    def test_approval_flow_pauses_and_resumes_execution(self):
        playbook = self._create_playbook(
            [
                {
                    "step_key": "approval",
                    "name": "Manager approval",
                    "type": "approval",
                    "config": {"message": "Approve containment"},
                },
                {"step_key": "end", "name": "End", "type": "end", "config": {}},
            ]
        )

        execution_response = self.client.post(f"/api/v1/playbooks/{playbook['id']}/execute", json={})
        self.assertEqual(execution_response.status_code, 201)
        self.assertEqual(execution_response.json()["status"], "awaiting_approval")

        approvals_response = self.client.get("/api/v1/playbooks/approvals", params={"status": "pending"})
        self.assertEqual(approvals_response.status_code, 200)
        approval_id = approvals_response.json()[0]["id"]

        approve_response = self.client.post(f"/api/v1/playbooks/approvals/{approval_id}/approve", json={"comment": "Approved"})
        self.assertEqual(approve_response.status_code, 200, approve_response.text)

        db = self.SessionTesting()
        execution = db.query(PlaybookExecution).filter(PlaybookExecution.id == execution_response.json()["id"]).first()
        db.close()
        self.assertEqual(execution.status, PlaybookExecutionStatus.COMPLETED)

    def test_retry_failure_records_failed_execution_and_logs(self):
        playbook = self._create_playbook(
            [
                {
                    "step_key": "bad_condition",
                    "name": "Bad expression",
                    "type": "condition",
                    "config": {"expression": "missing_value == 1", "retry_policy": {"max_attempts": 2}},
                }
            ]
        )

        response = self.client.post(f"/api/v1/playbooks/{playbook['id']}/execute", json={})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["status"], "failed")

        db = self.SessionTesting()
        execution = db.query(PlaybookExecution).filter(PlaybookExecution.id == response.json()["id"]).first()
        logs = db.query(PlaybookRunLog).filter(PlaybookRunLog.execution_id == execution.id).all()
        db.close()
        self.assertEqual(execution.result["step_key"], "bad_condition")
        self.assertTrue(any(log.level == "warning" for log in logs))

    def test_create_incident_step_records_playbook_provenance(self):
        playbook = self._create_playbook([
            {
                "step_key": "create_incident",
                "name": "Create incident",
                "type": "create_incident",
                "config": {"title": "Playbook provenance test", "severity": "medium"},
            },
            {"step_key": "end", "name": "End", "type": "end", "config": {}},
        ])
        response = self.client.post(f"/api/v1/playbooks/{playbook['id']}/execute", json={})
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["status"], "completed")

        db = self.SessionTesting()
        incident = db.query(Incident).filter(Incident.title == "Playbook provenance test").one()
        self.assertEqual(incident.creation_source, "playbook")
        self.assertEqual(incident.provenance_status, "recorded")
        self.assertIn(response.json()["id"], incident.creation_reason)
        db.close()

    def test_viewer_cannot_create_or_execute_playbooks(self):
        self._as_user(self.viewer_id)
        create_response = self.client.post(
            "/api/v1/playbooks",
            json={"name": "Viewer attempt", "steps": []},
        )
        self.assertEqual(create_response.status_code, 403)

        playbook = self._create_playbook([{"step_key": "end", "name": "End", "type": "end", "config": {}}])
        self._as_user(self.viewer_id)
        execute_response = self.client.post(f"/api/v1/playbooks/{playbook['id']}/execute", json={})
        self.assertEqual(execute_response.status_code, 403)

    def test_audit_events_are_recorded_for_key_actions(self):
        playbook = self._create_playbook([{"step_key": "end", "name": "End", "type": "end", "config": {}}])
        self.client.post(f"/api/v1/playbooks/{playbook['id']}/execute", json={})

        db = self.SessionTesting()
        actions = {row.action for row in db.query(AuditLog).all()}
        db.close()
        self.assertIn("playbook_created", actions)
        self.assertIn("playbook_executed", actions)


if __name__ == "__main__":
    unittest.main()
