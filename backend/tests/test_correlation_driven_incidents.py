import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.api.deps import get_current_user, get_db
from src.core.database import Base
from src.main import app
from src.models.sqlalchemy import (
    Alert, AlertSource, AlertSourceType, AlertStatus, DetectionRule, Incident,
    IncidentAlert, IncidentMitreMapping, MitreTactic, MitreTechnique, RuleType,
    Severity, Tenant, User, UserRole,
)
from src.services.incident_service import incident_service


class CorrelationDrivenIncidentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fd, cls.path = tempfile.mkstemp(suffix=".db"); os.close(fd)
        cls.engine = create_engine(f"sqlite:///{cls.path}", connect_args={"check_same_thread": False})
        cls.Session = sessionmaker(bind=cls.engine, autocommit=False, autoflush=False)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.clear(); cls.client.close(); cls.engine.dispose()
        try:
            os.remove(cls.path)
        except PermissionError:
            pass

    def setUp(self):
        app.dependency_overrides.clear(); Base.metadata.drop_all(self.engine); Base.metadata.create_all(self.engine)
        db = self.Session()
        tenant = Tenant(name="Correlation Tenant", slug="correlation-tenant"); db.add(tenant); db.flush()
        other = Tenant(name="Other Tenant", slug="other-tenant"); db.add(other); db.flush()
        user = User(tenant_id=tenant.id, email="analyst@example.com", hashed_password="unused", role=UserRole.ADMIN)
        source = AlertSource(tenant_id=tenant.id, name="EDR", type=AlertSourceType.API)
        other_source = AlertSource(tenant_id=other.id, name="Other EDR", type=AlertSourceType.API)
        db.add_all([user, source, other_source]); db.flush()
        db.add_all([
            MitreTechnique(technique_id="T1059.001", name="PowerShell", tactic=MitreTactic.EXECUTION),
            MitreTechnique(technique_id="T1110", name="Brute Force", tactic=MitreTactic.CREDENTIAL_ACCESS),
        ]); db.commit()
        self.tenant_id, self.other_tenant_id, self.user_id = tenant.id, other.id, user.id
        self.source_id, self.other_source_id = source.id, other_source.id
        def override_db():
            session = self.Session()
            try: yield session
            finally: session.close()
        def override_user():
            session = self.Session()
            try: return session.query(User).filter(User.id == self.user_id).one()
            finally: session.close()
        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[get_current_user] = override_user

    def _alert(self, db, *, tenant_id=None, source_id=None, technique="T1059.001", minutes=0, **fields):
        observed = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc) + timedelta(minutes=minutes)
        data = {"hostname": "host-01", "agent_id": "agent-01", "source_ip": "192.0.2.10", **fields}
        alert = Alert(
            tenant_id=tenant_id or self.tenant_id, source_id=source_id or self.source_id,
            ocsf_data={"attack_techniques": [technique]}, raw_data=data,
            severity=Severity.HIGH, status=AlertStatus.OPEN, created_at=observed,
            why_matched=f"Synthetic rule evidence for {technique}",
        )
        db.add(alert); db.commit(); db.refresh(alert); return alert

    def test_source_destination_identifiers_correlate_at_window_boundary(self):
        db = self.Session()
        first = self._alert(
            db,
            hostname=None,
            agent_id=None,
            source_ip="203.0.113.10",
            destination_ip="10.0.0.15",
            source_port=4444,
            destination_port=3389,
        )
        self.assertIsNone(incident_service.process_alert(db, first))
        second = self._alert(
            db,
            technique="T1110",
            minutes=15,
            hostname=None,
            agent_id=None,
            source_ip="203.0.113.10",
            destination_ip="10.0.0.15",
            source_port=4444,
            destination_port=3389,
        )
        incident = incident_service.process_alert(db, second)
        self.assertIsNotNone(incident)
        self.assertEqual(db.query(IncidentAlert).filter_by(incident_id=incident.id).count(), 2)
        db.close()

    def test_alert_outside_window_boundary_remains_pending(self):
        db = self.Session()
        first = self._alert(
            db,
            hostname=None,
            agent_id=None,
            source_ip="203.0.113.10",
            destination_ip="10.0.0.15",
            source_port=4444,
            destination_port=3389,
        )
        outside = self._alert(
            db,
            technique="T1110",
            minutes=15.1,
            hostname=None,
            agent_id=None,
            source_ip="203.0.113.10",
            destination_ip="10.0.0.15",
            source_port=4444,
            destination_port=3389,
        )
        self.assertIsNone(incident_service.process_alert(db, first))
        self.assertIsNone(incident_service.process_alert(db, outside))
        self.assertEqual(db.query(Incident).count(), 0)
        db.close()

    def test_single_alert_stays_pending_and_duplicate_processing_is_idempotent(self):
        db = self.Session(); alert = self._alert(db)
        self.assertIsNone(incident_service.process_alert(db, alert))
        self.assertIsNone(incident_service.process_alert(db, alert))
        self.assertEqual(db.query(Incident).count(), 0)
        self.assertIsNone(db.query(Alert).filter(Alert.id == alert.id).one().incident_id); db.close()

    def test_related_alerts_create_one_ordered_incident_with_confidence_and_evidence(self):
        db = self.Session(); first = self._alert(db)
        self.assertIsNone(incident_service.process_alert(db, first))
        second = self._alert(db, technique="T1110", minutes=3)
        incident = incident_service.process_alert(db, second); self.assertIsNotNone(incident)
        links = db.query(IncidentAlert).filter(IncidentAlert.incident_id == incident.id).order_by(IncidentAlert.sequence_order).all()
        self.assertEqual([row.alert_id for row in links], [first.id, second.id])
        self.assertEqual(db.query(Incident).count(), 1)
        mappings = db.query(IncidentMitreMapping).filter(IncidentMitreMapping.incident_id == incident.id).all()
        self.assertEqual({row.technique_id for row in mappings}, {"T1059.001", "T1110"})
        self.assertTrue(all(row.confidence > 0 and row.supporting_evidence and row.source_alert_ids for row in mappings))
        db.close()

    def test_unrelated_window_and_tenant_alerts_do_not_correlate(self):
        db = self.Session(); first = self._alert(db)
        outside = self._alert(db, minutes=16, hostname="other", agent_id="other", source_ip="198.51.100.1")
        other = self._alert(db, tenant_id=self.other_tenant_id, source_id=self.other_source_id, minutes=1)
        self.assertIsNone(incident_service.process_alert(db, first))
        self.assertIsNone(incident_service.process_alert(db, outside))
        self.assertIsNone(incident_service.process_alert(db, other))
        self.assertEqual(db.query(Incident).count(), 0); db.close()

    def test_late_arrival_reorders_links_and_invalidates_stale_ai(self):
        db = self.Session(); later = self._alert(db, minutes=5)
        incident_service.process_alert(db, later); latest = self._alert(db, technique="T1110", minutes=8); incident = incident_service.process_alert(db, latest)
        incident.ai_summary = "stale"; incident.ai_analyzed_at = datetime.now(timezone.utc); db.commit()
        early = self._alert(db, technique="T1110", minutes=1)
        updated = incident_service.process_alert(db, early)
        self.assertEqual(updated.id, incident.id); self.assertIsNone(updated.ai_summary); self.assertIsNone(updated.ai_analyzed_at)
        ordered = db.query(IncidentAlert).filter_by(incident_id=incident.id).order_by(IncidentAlert.sequence_order).all()
        self.assertEqual(ordered[0].alert_id, early.id); self.assertEqual(len({row.alert_id for row in ordered}), 3); db.close()

    def test_matrix_uses_incident_mappings_and_is_tenant_scoped(self):
        db = self.Session(); a = self._alert(db)
        incident_service.process_alert(db, a); b = self._alert(db, technique="T1110", minutes=2); incident = incident_service.process_alert(db, b); db.close()
        response = self.client.get("/api/v1/incidents/mitre-matrix")
        self.assertEqual(response.status_code, 200)
        body = response.json(); self.assertEqual(body["incident_count"], 1)
        self.assertEqual({item["technique_id"] for item in body["techniques"]}, {"T1059.001", "T1110"})
        filtered = self.client.get("/api/v1/incidents/mitre-matrix", params={"incident_id": incident.id}).json()
        self.assertEqual(filtered["incident_count"], 1)


if __name__ == "__main__":
    unittest.main()
