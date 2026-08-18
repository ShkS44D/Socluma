import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from src.api.deps import get_current_user, get_db
from src.core.database import Base
from src.main import app
from src.models.sqlalchemy import (
    Alert, AlertSource, AlertSourceType, AlertStatus, DetectionRule, Incident,
    IncidentAlert, IncidentMitreMapping, IncidentStatus, MitreTactic, MitreTechnique, RuleType,
    SecurityEvent, EventType, Severity, Tenant, User, UserRole,
    OrganizationMembership, OrganizationRole,
)
from src.services.correlation_service import correlation_service
from src.services.incident_service import AlertOwnershipConflict, incident_service


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
        db.add(OrganizationMembership(
            tenant_id=tenant.id, user_id=user.id,
            role=OrganizationRole.ADMINISTRATOR, is_active=True,
        ))
        db.add_all([
            MitreTechnique(technique_id="T1059", name="Command and Scripting Interpreter", tactic=MitreTactic.EXECUTION),
            MitreTechnique(technique_id="T1059.001", name="PowerShell", tactic=MitreTactic.EXECUTION),
            MitreTechnique(technique_id="T1110", name="Brute Force", tactic=MitreTactic.CREDENTIAL_ACCESS),
            MitreTechnique(technique_id="T1071", name="Application Layer Protocol", tactic=MitreTactic.COMMAND_AND_CONTROL),
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
        powershell = next(row for row in mappings if row.technique_id == "T1059.001")
        brute_force = next(row for row in mappings if row.technique_id == "T1110")
        self.assertEqual((powershell.stage_order, brute_force.stage_order), (0, 1))
        self.assertEqual(powershell.parent_technique_id, "T1059")
        self.assertEqual(powershell.parent_technique_name, "Command and Scripting Interpreter")
        self.assertEqual(powershell.sub_technique_name, "PowerShell")
        self.assertEqual(powershell.mapping_source, "correlated")
        incident_id = incident.id; db.close()
        detail = self.client.get(f"/api/v1/incidents/{incident_id}")
        self.assertEqual(detail.status_code, 200)
        api_mapping = next(item for item in detail.json()["mitre_mappings"] if item["technique_id"] == "T1059.001")
        self.assertEqual(api_mapping["parent_technique_id"], "T1059")
        self.assertEqual(api_mapping["sub_technique_id"], "T1059.001")
        self.assertEqual(api_mapping["mapping_source"], "correlated")
        self.assertTrue(api_mapping["supporting_evidence"][0]["alert_id"])

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
        incident_service.process_alert(db, a); b = self._alert(db, technique="T1110", minutes=2); incident = incident_service.process_alert(db, b)
        db.add(IncidentMitreMapping(
            tenant_id=self.tenant_id,
            incident_id=incident.id,
            tactic="Unknown",
            technique_id="T9999",
            technique_name="Historical placeholder",
            parent_technique_id="T9999",
            parent_technique_name="Historical placeholder",
            mapping_source="legacy-derived",
            source_alert_ids=[],
        ))
        db.commit(); incident_id = incident.id; db.close()
        response = self.client.get("/api/v1/incidents/mitre-matrix")
        self.assertEqual(response.status_code, 200)
        body = response.json(); self.assertEqual(body["incident_count"], 1)
        self.assertEqual({item["technique_id"] for item in body["techniques"]}, {"T1059.001", "T1110"})
        self.assertTrue(all(item["mapping_source"] == "correlated" for item in body["techniques"]))
        self.assertTrue(all(item["supporting_alert_count"] >= 1 for item in body["techniques"]))
        filtered = self.client.get("/api/v1/incidents/mitre-matrix", params={"incident_id": incident_id}).json()
        self.assertEqual(filtered["incident_count"], 1)

    def test_repeated_identical_alerts_do_not_create_attack_chain_by_default(self):
        db = self.Session(); first = self._alert(db); second = self._alert(db, minutes=1)
        self.assertIsNone(incident_service.process_alert(db, first))
        self.assertIsNone(incident_service.process_alert(db, second))
        self.assertEqual(db.query(Incident).count(), 0); db.close()

    def test_tactic_casing_matches_standard_matrix_column(self):
        db = self.Session()
        first = self._alert(db, technique="T1110")
        self.assertIsNone(incident_service.process_alert(db, first))
        second = self._alert(db, technique="T1071", minutes=1)
        incident = incident_service.process_alert(db, second)
        mapping = db.query(IncidentMitreMapping).filter_by(
            incident_id=incident.id,
            technique_id="T1071",
        ).one()
        self.assertEqual(mapping.tactic, "Command and Control")
        db.close()

    def test_strong_entity_and_time_without_stage_or_behavior_stays_pending(self):
        db = self.Session()
        first = self._alert(db, technique="", event_type="alpha")
        second = self._alert(db, technique="", minutes=1, event_type="beta")
        self.assertIsNone(incident_service.process_alert(db, first))
        self.assertIsNone(incident_service.process_alert(db, second))
        self.assertEqual(db.query(Incident).count(), 0); db.close()

    def test_more_than_500_old_alerts_do_not_hide_recent_candidates(self):
        db = self.Session()
        old_base = datetime(2025, 1, 1, tzinfo=timezone.utc)
        db.add_all([
            Alert(
                tenant_id=self.tenant_id, source_id=self.source_id,
                ocsf_data={"attack_techniques": ["T1059.001"]},
                raw_data={"hostname": f"old-{index}", "agent_id": f"old-agent-{index}"},
                severity=Severity.LOW, status=AlertStatus.OPEN,
                created_at=old_base + timedelta(seconds=index),
            ) for index in range(525)
        ]); db.commit()
        first = self._alert(db, minutes=0)
        self.assertIsNone(incident_service.process_alert(db, first))
        second = self._alert(db, technique="T1110", minutes=1)
        incident = incident_service.process_alert(db, second)
        self.assertIsNotNone(incident)
        self.assertEqual(db.query(IncidentAlert).filter_by(incident_id=incident.id).count(), 2); db.close()

    def test_more_than_500_eligible_window_alerts_are_keyset_paged(self):
        db = self.Session()
        target = self._alert(db, minutes=0)
        base = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
        db.add_all([
            Alert(
                tenant_id=self.tenant_id,
                source_id=self.source_id,
                ocsf_data={"attack_techniques": ["T1059.001"]},
                raw_data={
                    "hostname": f"distractor-{index}",
                    "agent_id": f"distractor-agent-{index}",
                    "source_ip": f"198.51.{index // 250}.{index % 250 + 1}",
                },
                severity=Severity.LOW,
                status=AlertStatus.OPEN,
                created_at=base + timedelta(seconds=60 + index),
            )
            for index in range(525)
        ])
        db.commit()
        incoming = self._alert(db, technique="T1110", minutes=15)

        candidate = correlation_service.correlate_alert(db, incoming)

        self.assertTrue(candidate.qualified)
        self.assertEqual(candidate.candidate_alert_ids, [target.id])
        self.assertEqual(candidate.evaluated_candidate_count, 526)
        self.assertGreater(candidate.query_duration_ms, 0)
        incident = incident_service.process_alert(db, incoming)
        self.assertIsNotNone(incident)
        self.assertEqual(
            {row.alert_id for row in db.query(IncidentAlert).filter_by(incident_id=incident.id).all()},
            {target.id, incoming.id},
        )
        db.close()

    def test_candidate_order_is_deterministic(self):
        db = self.Session()
        first = self._alert(db, minutes=0)
        second = self._alert(db, minutes=0)
        incoming = self._alert(db, technique="T1110", minutes=1)
        candidate = correlation_service.correlate_alert(db, incoming)
        self.assertTrue(candidate.qualified)
        self.assertEqual(candidate.candidate_alert_ids, [max(first.id, second.id)])
        db.close()

    def test_linked_alert_with_missing_direct_owner_is_rejected(self):
        db = self.Session(); alert = self._alert(db)
        incident = Incident(tenant_id=self.tenant_id, title="Historical", status=IncidentStatus.OPEN)
        db.add(incident); db.flush()
        db.add(IncidentAlert(incident_id=incident.id, alert_id=alert.id, correlation_score=50)); db.commit()
        with self.assertRaises(AlertOwnershipConflict):
            incident_service.process_alert(db, alert)
        db.rollback(); self.assertIsNone(db.query(Alert).filter_by(id=alert.id).one().incident_id); db.close()

    def test_open_and_closed_incident_alerts_are_never_reused(self):
        db = self.Session(); first = self._alert(db); incident_service.process_alert(db, first)
        second = self._alert(db, technique="T1110", minutes=2); incident = incident_service.process_alert(db, second)
        original_links = {row.alert_id for row in db.query(IncidentAlert).filter_by(incident_id=incident.id).all()}
        self.assertEqual(incident_service.process_alert(db, first).id, incident.id)
        incident.status = IncidentStatus.CLOSED; db.commit()
        later = self._alert(db, technique="T1110", minutes=3)
        self.assertIsNone(incident_service.process_alert(db, later))
        self.assertEqual({row.alert_id for row in db.query(IncidentAlert).filter_by(incident_id=incident.id).all()}, original_links)
        self.assertEqual(db.query(Incident).count(), 1); db.close()

    def test_database_prevents_one_alert_linking_to_two_incidents(self):
        db = self.Session(); alert = self._alert(db)
        first = Incident(tenant_id=self.tenant_id, title="First")
        second = Incident(tenant_id=self.tenant_id, title="Second")
        db.add_all([first, second]); db.flush()
        db.add(IncidentAlert(incident_id=first.id, alert_id=alert.id, correlation_score=50)); db.commit()
        db.add(IncidentAlert(incident_id=second.id, alert_id=alert.id, correlation_score=50))
        with self.assertRaises(IntegrityError): db.commit()
        db.rollback()
        self.assertEqual(db.query(IncidentAlert).filter_by(alert_id=alert.id).count(), 1); db.close()

    def test_late_event_time_uses_security_event_not_ingestion_time(self):
        db = self.Session()
        observed = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
        event = SecurityEvent(
            tenant_id=self.tenant_id, source="edr", event_type=EventType.PROCESS,
            raw_event={}, normalized_event={"hostname": "late-host", "agent_id": "late-agent"}, timestamp=observed,
        )
        db.add(event); db.flush()
        first = Alert(
            tenant_id=self.tenant_id, source_id=self.source_id, event_id=event.id,
            ocsf_data={"attack_techniques": ["T1059.001"]}, raw_data={"hostname": "late-host", "agent_id": "late-agent"},
            severity=Severity.HIGH, status=AlertStatus.OPEN, created_at=observed + timedelta(days=2),
        ); db.add(first); db.commit()
        self.assertIsNone(incident_service.process_alert(db, first))
        second = self._alert(db, technique="T1110", minutes=5, hostname="late-host", agent_id="late-agent", source_ip=None)
        incident = incident_service.process_alert(db, second)
        self.assertIsNotNone(incident); db.close()


if __name__ == "__main__":
    unittest.main()
