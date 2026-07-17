import os
import tempfile
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.api.deps import get_current_user, get_db
from src.core.database import Base
from src.main import app
from src.models.sqlalchemy import Classification, Incident, IncidentStatus, Severity, Tenant, User, UserRole


class IncidentApiTests(unittest.TestCase):
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

        db = self.SessionTesting()
        tenant = Tenant(name="Test Tenant", slug="test-tenant")
        db.add(tenant)
        db.flush()
        user = User(
            tenant_id=tenant.id,
            email="analyst@example.com",
            hashed_password="not-used",
            full_name="Test Analyst",
            role=UserRole.ADMIN,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        self.user_id = user.id
        db.close()

        def override_get_db():
            db = self.SessionTesting()
            try:
                yield db
            finally:
                db.close()

        def override_get_current_user():
            db = self.SessionTesting()
            try:
                user = db.query(User).filter(User.id == self.user_id).first()
                return user
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[get_current_user] = override_get_current_user

    def test_brute_force_then_successful_login_creates_single_incident(self):
        first_response = self.client.post(
            "/api/v1/alerts",
            json={
                "source": "firewall",
                "raw_data": {
                    "source": "firewall",
                    "event_type": "login_failed",
                    "user": "admin",
                    "ip": "192.168.1.10",
                    "timestamp": "2026-06-25T10:00:00",
                    "severity": "high",
                },
            },
        )
        self.assertEqual(first_response.status_code, 201)

        second_response = self.client.post(
            "/api/v1/alerts",
            json={
                "source": "firewall",
                "raw_data": {
                    "source": "firewall",
                    "event_type": "login",
                    "user": "admin",
                    "ip": "192.168.1.10",
                    "timestamp": "2026-06-25T10:05:00",
                    "severity": "medium",
                },
            },
        )
        self.assertEqual(second_response.status_code, 201)
        self.assertIsNotNone(second_response.json()["incident_id"])

        incidents_response = self.client.get("/api/v1/incidents")
        self.assertEqual(incidents_response.status_code, 200)
        incidents_payload = incidents_response.json()
        self.assertEqual(incidents_payload["total"], 1)
        self.assertEqual(incidents_payload["items"][0]["alert_count"], 2)
        self.assertIn("Account Takeover", incidents_payload["items"][0]["title"])
        self.assertGreaterEqual(incidents_payload["items"][0]["risk_score"], 60)

    def test_malware_alert_creates_high_risk_incident(self):
        response = self.client.post(
            "/api/v1/alerts",
            json={
                "source": "antivirus",
                "raw_data": {
                    "source": "antivirus",
                    "event_type": "malware_detection",
                    "malware_name": "Trojan.Generic.12345",
                    "file_hash": "abc123",
                    "severity": "critical",
                    "timestamp": "2026-06-25T11:00:00",
                    "hostname": "malware-host", "agent_id": "edr-01",
                },
            },
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["ocsf_data"]["class_name"], "Malware")
        self.client.post("/api/v1/alerts", json={"source": "antivirus", "raw_data": {
            "source": "antivirus", "event_type": "malware_detection", "malware_name": "Trojan.Generic.12345",
            "file_hash": "def456", "severity": "critical", "timestamp": "2026-06-25T11:02:00",
            "hostname": "malware-host", "agent_id": "edr-01"}})

        incidents_response = self.client.get("/api/v1/incidents")
        self.assertEqual(incidents_response.status_code, 200)
        incident = incidents_response.json()["items"][0]
        self.assertIn("Malware", incident["title"])
        self.assertGreaterEqual(incident["risk_score"], 60)
        self.assertTrue(incident["threat_intel_results"])

    def test_incident_detail_returns_related_alerts_and_reasons(self):
        first_response = self.client.post(
            "/api/v1/alerts",
            json={
                "source": "ids",
                "raw_data": {
                    "source": "ids",
                    "event_type": "suspicious_network",
                    "source_ip": "10.0.0.5",
                    "destination_ip": "198.51.100.25",
                    "hostname": "srv-01",
                    "severity": "medium",
                    "timestamp": "2026-06-25T12:00:00",
                },
            },
        )
        second_response = self.client.post(
            "/api/v1/alerts",
            json={
                "source": "ids",
                "raw_data": {
                    "source": "ids",
                    "event_type": "connection",
                    "source_ip": "10.0.0.5",
                    "destination_ip": "198.51.100.26",
                    "hostname": "srv-01",
                    "severity": "medium",
                    "timestamp": "2026-06-25T12:05:00",
                },
            },
        )

        incident_id = second_response.json()["incident_id"] or first_response.json()["incident_id"]
        detail_response = self.client.get(f"/api/v1/incidents/{incident_id}")
        self.assertEqual(detail_response.status_code, 200)
        payload = detail_response.json()
        self.assertGreaterEqual(len(payload["related_alerts"]), 2)
        self.assertGreaterEqual(len(payload["correlation_reasons"]), 1)
        self.assertTrue(payload["threat_intel_results"])

    def test_ai_analysis_maps_account_takeover_to_t1110(self):
        self.client.post(
            "/api/v1/alerts",
            json={
                "source": "firewall",
                "raw_data": {
                    "source": "firewall",
                    "event_type": "login_failed",
                    "user": "admin",
                    "ip": "192.168.1.10",
                    "timestamp": "2026-06-25T10:00:00",
                    "severity": "high",
                },
            },
        )
        self.client.post(
            "/api/v1/alerts",
            json={
                "source": "firewall",
                "raw_data": {
                    "source": "firewall",
                    "event_type": "login",
                    "user": "admin",
                    "ip": "192.168.1.10",
                    "timestamp": "2026-06-25T10:05:00",
                    "severity": "medium",
                },
            },
        )

        incidents_response = self.client.get("/api/v1/incidents")
        incident_id = incidents_response.json()["items"][0]["id"]
        analyze_response = self.client.post(f"/api/v1/incidents/{incident_id}/analyze")
        self.assertEqual(analyze_response.status_code, 200)
        payload = analyze_response.json()
        self.assertEqual(payload["attack_technique"]["technique_id"], "T1110")
        self.assertTrue(payload["summary"])
        self.assertTrue(payload["recommended_actions"])

    def test_incident_list_normalizes_legacy_list_attack_technique(self):
        db = self.SessionTesting()
        try:
            user = db.query(User).filter(User.id == self.user_id).first()
            incident = Incident(
                tenant_id=user.tenant_id,
                title="Legacy AI Summary Incident",
                description="Incident with list-shaped MITRE data from older AI summary output.",
                severity=Severity.HIGH,
                risk_score=75,
                status=IncidentStatus.OPEN,
                attack_technique=[
                    {
                        "technique_id": "T1059",
                        "technique_name": "Command and Scripting Interpreter",
                        "confidence": 0.75,
                    }
                ],
                recommended_actions=["Validate process evidence."],
            )
            db.add(incident)
            db.commit()
        finally:
            db.close()

        incidents_response = self.client.get("/api/v1/incidents")
        self.assertEqual(incidents_response.status_code, 200)
        payload = incidents_response.json()["items"][0]
        self.assertEqual(payload["attack_technique"]["technique_id"], "T1059")

    def test_ai_analysis_maps_malware_to_t1204(self):
        self.client.post(
            "/api/v1/alerts",
            json={
                "source": "antivirus",
                "raw_data": {
                    "source": "antivirus",
                    "event_type": "malware_detection",
                    "malware_name": "Trojan.Generic.12345",
                    "file_hash": "abc123",
                    "severity": "critical",
                    "timestamp": "2026-06-25T11:00:00",
                    "hostname": "malware-host", "agent_id": "edr-01",
                },
            },
        )
        self.client.post("/api/v1/alerts", json={"source": "antivirus", "raw_data": {
            "source": "antivirus", "event_type": "malware_detection", "malware_name": "Trojan.Generic.12345",
            "file_hash": "def456", "severity": "critical", "timestamp": "2026-06-25T11:02:00",
            "hostname": "malware-host", "agent_id": "edr-01"}})

        incidents_response = self.client.get("/api/v1/incidents")
        incident_id = incidents_response.json()["items"][0]["id"]
        analyze_response = self.client.post(f"/api/v1/incidents/{incident_id}/analyze")
        self.assertEqual(analyze_response.status_code, 200)
        payload = analyze_response.json()
        self.assertEqual(payload["attack_technique"]["technique_id"], "T1204")
        self.assertIn("risk score", payload["summary"].lower())

    def test_status_workflow_rejects_invalid_transition(self):
        self.client.post(
            "/api/v1/alerts",
            json={
                "source": "antivirus",
                "raw_data": {
                    "source": "antivirus",
                    "event_type": "malware_detection",
                    "malware_name": "Trojan.Generic.12345",
                    "file_hash": "abc123",
                    "severity": "critical",
                    "timestamp": "2026-06-25T11:00:00",
                    "hostname": "malware-host", "agent_id": "edr-01",
                },
            },
        )
        self.client.post("/api/v1/alerts", json={"source": "antivirus", "raw_data": {
            "source": "antivirus", "event_type": "malware_detection", "malware_name": "Trojan.Generic.12345",
            "file_hash": "def456", "severity": "critical", "timestamp": "2026-06-25T11:02:00",
            "hostname": "malware-host", "agent_id": "edr-01"}})

        incident_id = self.client.get("/api/v1/incidents").json()["items"][0]["id"]
        invalid_response = self.client.post(
            f"/api/v1/incidents/{incident_id}/status",
            json={"status": "resolved"},
        )
        self.assertEqual(invalid_response.status_code, 400)
        self.assertIn("Invalid status transition", invalid_response.json()["detail"])

        self.assertEqual(
            self.client.post(
                f"/api/v1/incidents/{incident_id}/status",
                json={"status": "investigating"},
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                f"/api/v1/incidents/{incident_id}/status",
                json={"status": "resolved"},
            ).status_code,
            200,
        )
        closed_response = self.client.post(
            f"/api/v1/incidents/{incident_id}/status",
            json={"status": "closed"},
        )
        self.assertEqual(closed_response.status_code, 200)
        self.assertEqual(closed_response.json()["status"], "closed")
        self.assertIsNotNone(closed_response.json()["resolved_at"])

    def test_timeline_includes_assignment_notes_feedback_and_audit_events(self):
        self.client.post(
            "/api/v1/alerts",
            json={
                "source": "ids",
                "raw_data": {
                    "source": "ids",
                    "event_type": "suspicious_network",
                    "source_ip": "10.0.0.5",
                    "destination_ip": "198.51.100.25",
                    "hostname": "srv-01",
                    "severity": "high",
                    "timestamp": "2026-06-25T12:00:00",
                },
            },
        )
        self.client.post(
            "/api/v1/alerts",
            json={"source": "ids", "raw_data": {
                "source": "ids", "event_type": "connection", "source_ip": "10.0.0.5",
                "destination_ip": "198.51.100.26", "hostname": "srv-01", "severity": "high",
                "timestamp": "2026-06-25T12:03:00",
            }},
        )
        incident_id = self.client.get("/api/v1/incidents").json()["items"][0]["id"]

        self.assertEqual(
            self.client.post(
                f"/api/v1/incidents/{incident_id}/assign",
                json={"user_id": self.user_id},
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                f"/api/v1/incidents/{incident_id}/status",
                json={"status": "investigating"},
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                f"/api/v1/incidents/{incident_id}/notes",
                json={"content": "Collected packet capture and checked impacted host."},
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                f"/api/v1/incidents/{incident_id}/feedback",
                json={"classification": Classification.TRUE_POSITIVE.value, "comment": "Confirmed lateral movement."},
            ).status_code,
            200,
        )

        timeline_response = self.client.get(f"/api/v1/incidents/{incident_id}/timeline")
        self.assertEqual(timeline_response.status_code, 200)
        timeline = timeline_response.json()
        event_types = {item["event_type"] for item in timeline}
        self.assertIn("incident_created", event_types)
        self.assertIn("alert_created", event_types)
        self.assertIn("assignment", event_types)
        self.assertIn("status_changed", event_types)
        self.assertIn("note_added", event_types)
        self.assertIn("feedback_submitted", event_types)
        self.assertIn("audit", event_types)

        created_times = [item["created_at"] for item in timeline]
        self.assertEqual(created_times, sorted(created_times, reverse=True))



if __name__ == "__main__":
    unittest.main()
