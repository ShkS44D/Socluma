import os
import tempfile
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.api.deps import AuthContext, get_current_auth_context, get_current_user, get_db
from src.core.database import Base
from src.main import app
from src.models.sqlalchemy import (
    Alert,
    Incident,
    SecurityEvent,
    Tenant,
    User,
    UserRole,
    DetectionRule,
    IncidentAlert,
    IncidentMitreMapping,
    MitreTactic,
    MitreTechnique,
    RuleType,
    Severity,
)
from src.services.default_detection_rules import DEFAULT_DETECTION_RULES
from src.services.mitre_technique_service import mitre_technique_service
from src.services.threat_intel_service import threat_intel_service


class DetectionPipelineTests(unittest.TestCase):
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
        self.tenant_id = tenant.id
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

        def override_get_current_auth_context():
            db = self.SessionTesting()
            try:
                user = db.query(User).filter(User.id == self.user_id).first()
                return AuthContext(user=user, tenant_id=user.tenant_id)
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[get_current_user] = override_get_current_user
        app.dependency_overrides[get_current_auth_context] = override_get_current_auth_context

    def test_full_attack_chain_simulation_uses_real_pipeline_without_external_enrichment(self):
        selected = {"T1059.001", "T1003.001", "T1105"}
        db = self.SessionTesting()
        try:
            mitre_technique_service.bootstrap_catalog(db)
            for definition in DEFAULT_DETECTION_RULES:
                if definition["mitre_technique_id"] not in selected:
                    continue
                values = dict(definition)
                values["created_by"] = self.user_id
                db.add(DetectionRule(tenant_id=self.tenant_id, **values))
            db.commit()
        finally:
            db.close()

        original_lookup = threat_intel_service.lookup_incident_indicators
        threat_intel_service.lookup_incident_indicators = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("simulation attempted external threat-intelligence enrichment")
        )
        try:
            response = self.client.post("/api/v1/events/simulate/full_attack_chain")
            repeated_response = self.client.post("/api/v1/events/simulate/full_attack_chain")
        finally:
            threat_intel_service.lookup_incident_indicators = original_lookup
        self.assertEqual(response.status_code, 201, response.text)
        results = response.json()
        self.assertEqual(len(results), 3)
        self.assertFalse(results[0]["incident_created"])
        incident_ids = {item["incident_id"] for item in results[1:] if item["incident_id"]}
        self.assertEqual(len(incident_ids), 1)
        self.assertEqual(repeated_response.status_code, 201, repeated_response.text)
        repeated = repeated_response.json()
        self.assertFalse(repeated[0]["incident_created"])
        repeated_incident_ids = {item["incident_id"] for item in repeated[1:] if item["incident_id"]}
        self.assertEqual(len(repeated_incident_ids), 1)
        self.assertTrue(incident_ids.isdisjoint(repeated_incident_ids))

        incident_id = incident_ids.pop()
        db = self.SessionTesting()
        try:
            links = db.query(IncidentAlert).filter_by(incident_id=incident_id).order_by(IncidentAlert.sequence_order).all()
            self.assertEqual(len(links), 3)
            self.assertEqual(len({link.alert_id for link in links}), 3)
            self.assertTrue(all(link.alert.incident_id == incident_id for link in links))
            mappings = db.query(IncidentMitreMapping).filter_by(incident_id=incident_id, mapping_source="correlated").all()
            self.assertGreaterEqual(len(mappings), 3)
            self.assertGreaterEqual(len({mapping.tactic for mapping in mappings}), 3)
            self.assertTrue(all(mapping.supporting_evidence and mapping.source_alert_ids for mapping in mappings))
        finally:
            db.close()

        matrix = self.client.get("/api/v1/incidents/mitre-matrix", params={"incident_id": incident_id})
        self.assertEqual(matrix.status_code, 200, matrix.text)
        self.assertEqual(matrix.json()["incident_count"], 1)
        self.assertGreaterEqual(len(matrix.json()["techniques"]), 3)

    def test_sigma_rule_process_powershell_event_matches(self):
        # 1. Create sigma detection rule
        create_rule_response = self.client.post(
            "/api/v1/detection-rules",
            json={
                "name": "Suspicious PowerShell Execution",
                "description": "Detect powershell abuse",
                "rule_type": "sigma",
                "severity": "high",
                "rule_content": {
                    "title": "Suspicious PowerShell Execution",
                    "logsource": {"category": "process_creation"},
                    "detection": {
                        "selection": {"process": "powershell.exe"},
                        "condition": "selection"
                    }
                }
            }
        )
        self.assertEqual(create_rule_response.status_code, 201)
        
        # 2. Ingest test event
        ingest_response = self.client.post(
            "/api/v1/events/ingest",
            json={
                "source": "windows-edr",
                "event_type": "process",
                "raw_event": {"process": "powershell.exe", "command": "powershell -enc SGVsbG8="},
                "normalized_event": {"process": "powershell.exe", "command": "powershell -enc SGVsbG8="}
            }
        )
        self.assertEqual(ingest_response.status_code, 201)
        event = ingest_response.json()
        self.assertTrue(event.get("processed"))
        self.assertEqual(len(event.get("detections")), 1)
        
        # 3. Test manual analysis endpoint as well
        analysis_response = self.client.post(
            f"/api/v1/events/{event['id']}/analyze"
        )
        self.assertEqual(analysis_response.status_code, 200)
        analysis_result = analysis_response.json()
        self.assertTrue(analysis_result.get("processed"))
        self.assertEqual(len(analysis_result.get("matched_rules")), 1)
        self.assertFalse(analysis_result.get("incident_created"))
        self.assertIsNone(analysis_result.get("incident_id"))
        
        
        # 4. Verify with Image key too
        image_rule_response = self.client.post(
            "/api/v1/detection-rules",
            json={
                "name": "Suspicious PowerShell Execution via Image",
                "description": "Detect powershell abuse via Image",
                "rule_type": "sigma",
                "severity": "high",
                "rule_content": {
                    "title": "Suspicious PowerShell Execution",
                    "logsource": {"category": "process_creation"},
                    "detection": {
                        "selection": {"Image": "powershell.exe"},
                        "condition": "selection"
                    }
                }
            }
        )
        self.assertEqual(image_rule_response.status_code, 201)
        
        image_ingest_response = self.client.post(
            "/api/v1/events/ingest",
            json={
                "source": "windows-edr",
                "event_type": "process",
                "raw_event": {"Image": "powershell.exe"},
                "normalized_event": {"image": "powershell.exe"}
            }
        )
        self.assertEqual(image_ingest_response.status_code, 201)
        image_event = image_ingest_response.json()
        self.assertEqual(len(image_event.get("detections")), 2)

    def test_sigma_rule_usb_event_6416_creates_alert(self):
        create_rule_response = self.client.post(
            "/api/v1/detection-rules",
            json={
                "name": "USB storage device connected",
                "description": "Detect Windows Plug and Play storage-device recognition",
                "rule_type": "sigma",
                "severity": "medium",
                "rule_content": {
                    "title": "USB storage device connected",
                    "logsource": {"product": "windows", "service": "security"},
                    "detection": {
                        "selection": {
                            "EventID": 6416,
                            "ClassName": "DiskDrive",
                        },
                        "condition": "selection",
                    },
                },
            },
        )
        self.assertEqual(create_rule_response.status_code, 201, create_rule_response.text)

        ingest_response = self.client.post(
            "/api/v1/events/ingest",
            json={
                "source": "windows-agent",
                "event_type": "file",
                "raw_event": {
                    "EventID": 6416,
                    "event_id": 6416,
                    "DeviceId": r"USBSTOR\DISK&VEN_TEST",
                    "DeviceDescription": "USB Mass Storage Device",
                    "ClassName": "DiskDrive",
                    "Computer": "analyst-workstation",
                    "Channel": "Security",
                },
                "normalized_event": {
                    "event_id": 6416,
                    "device_id": r"USBSTOR\DISK&VEN_TEST",
                    "device_description": "USB Mass Storage Device",
                    "device_class_name": "DiskDrive",
                    "hostname": "analyst-workstation",
                    "channel": "Security",
                    "product": "windows",
                },
            },
        )

        self.assertEqual(ingest_response.status_code, 201, ingest_response.text)
        event = ingest_response.json()
        self.assertTrue(event["processed"])
        self.assertEqual(len(event["detections"]), 1)
        self.assertFalse(event["incident_created"])
        self.assertIsNone(event["incident_id"])

    def test_events_today_stats_counts_beyond_default_page_limit(self):
        for index in range(111):
            response = self.client.post(
                "/api/v1/events/ingest",
                json={
                    "source": "test-source",
                    "event_type": "login",
                    "raw_event": {"user": f"user-{index}", "status": "success"},
                    "normalized_event": {"user": f"user-{index}", "status": "success"},
                },
            )
            self.assertEqual(response.status_code, 201)

        page_response = self.client.get("/api/v1/events")
        self.assertEqual(page_response.status_code, 200)
        self.assertEqual(len(page_response.json()), 100)

        stats_response = self.client.get("/api/v1/events/stats/today")
        self.assertEqual(stats_response.status_code, 200)
        self.assertEqual(stats_response.json()["count"], 111)

    def test_events_today_stats_accepts_browser_timezone_offset(self):
        response = self.client.post(
            "/api/v1/events/ingest",
            json={
                "source": "test-source",
                "event_type": "login",
                "raw_event": {"user": "timezone-user", "status": "success"},
                "normalized_event": {"user": "timezone-user", "status": "success"},
            },
        )
        self.assertEqual(response.status_code, 201)

        stats_response = self.client.get("/api/v1/events/stats/today?timezone_offset_minutes=-300")
        self.assertEqual(stats_response.status_code, 200)
        self.assertGreaterEqual(stats_response.json()["count"], 1)

    def test_windows_4688_powershell_sigma_creates_alert_and_incident(self):
        create_rule_response = self.client.post(
            "/api/v1/detection-rules",
            json={
                "name": "Live Sigma PowerShell Verification",
                "description": "Detects PowerShell process execution.",
                "rule_type": "sigma",
                "severity": "high",
                "rule_content": {
                    "title": "Live Sigma PowerShell Verification",
                    "logsource": {"product": "windows", "category": "process_creation"},
                    "level": "high",
                    "tags": ["attack.t1059.001"],
                    "triage": {
                        "confidence": 88,
                        "recommendations": ["Decode the command line and validate parent process."],
                    },
                    "detection": {
                        "selection": {"Image|endswith": "powershell.exe"},
                        "selection_cli": {"CommandLine|contains": "EncodedCommand"},
                        "condition": "selection and selection_cli",
                    },
                },
            },
        )
        self.assertEqual(create_rule_response.status_code, 201)

        ingest_response = self.client.post(
            "/api/v1/events/ingest",
            json={
                "source": "windows-agent",
                "event_type": "process",
                "timestamp": "2026-07-05T10:55:08Z",
                "raw_event": {
                    "timestamp": 1783264508,
                    "event_id": 4688,
                    "process": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "command_line": "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIAVABlAHMAdAAiAA==",
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "CommandLine": "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIAVABlAHMAdAAiAA==",
                    "ParentImage": r"C:\Windows\explorer.exe",
                    "hostname": "windows-pilot-01",
                    "agent_id": "windows-agent-01",
                },
                "normalized_event": {
                    "process": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "command": "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIAVABlAHMAdAAiAA==",
                    "command_line": "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIAVABlAHMAdAAiAA==",
                    "parent_process": r"C:\Windows\explorer.exe",
                    "hostname": "windows-pilot-01",
                    "agent_id": "windows-agent-01",
                },
                "severity": "high",
            },
        )
        self.assertEqual(ingest_response.status_code, 201)
        payload = ingest_response.json()
        self.assertTrue(payload["processed"])
        self.assertEqual(payload["detection_status"], "matched")
        self.assertEqual(payload["detection_count"], 1)
        self.assertEqual(len(payload["detections"]), 1)
        self.assertFalse(payload["incident_created"])
        self.assertIsNone(payload["incident_id"])

        db = self.SessionTesting()
        try:
            db.add_all([
                MitreTechnique(technique_id="T1059.001", name="PowerShell", tactic=MitreTactic.EXECUTION),
                MitreTechnique(technique_id="T1110", name="Brute Force", tactic=MitreTactic.CREDENTIAL_ACCESS),
            ])
            db.commit()
        finally:
            db.close()

        progression_rule = self.client.post(
            "/api/v1/detection-rules",
            json={
                "name": "Pilot Credential Stage Verification",
                "description": "Adds a distinct ATT&CK stage for the controlled follow-up event.",
                "rule_type": "sigma",
                "severity": "high",
                "rule_content": {
                    "title": "Pilot Credential Stage Verification",
                    "logsource": {"product": "windows", "category": "process_creation"},
                    "level": "high",
                    "tags": ["attack.t1110"],
                    "detection": {
                        "selection": {"pilot_follow_up": True},
                        "condition": "selection",
                    },
                },
            },
        )
        self.assertEqual(progression_rule.status_code, 201)

        follow_up = self.client.post(
            "/api/v1/events/ingest",
            json={
                "source": "windows-agent", "event_type": "process", "timestamp": "2026-07-05T10:55:10Z",
                "raw_event": {"timestamp": 1783264510, "event_id": 4688, "pilot_follow_up": True,
                    "hostname": "windows-pilot-01", "agent_id": "windows-agent-01",
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "CommandLine": "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIAVABlAHMAdAAiAA=="},
                "normalized_event": {"image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "hostname": "windows-pilot-01", "agent_id": "windows-agent-01",
                    "command_line": "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIAVABlAHMAdAAiAA=="},
                "severity": "high",
            },
        )
        self.assertTrue(follow_up.json()["incident_created"])
        self.assertIsNotNone(follow_up.json()["incident_id"])

        db = self.SessionTesting()
        try:
            event = db.query(SecurityEvent).filter(SecurityEvent.id == payload["id"]).first()
            self.assertIsNotNone(event)
            self.assertEqual(event.raw_event["event_id"], 4688)
            self.assertTrue(event.raw_event["process"].lower().endswith("powershell.exe"))
            self.assertIn("EncodedCommand", event.raw_event["command_line"])
            alerts = db.query(Alert).filter(Alert.event_id == payload["id"]).all()
            self.assertEqual(len(alerts), 1)
            alert = alerts[0]
            self.assertEqual(alert.ocsf_data["class_name"], "Process Activity")
            self.assertEqual(alert.ocsf_data["activity_name"], "Process Created")
            self.assertEqual(alert.ocsf_data["category_name"], "System Activity")
            self.assertEqual(alert.ocsf_data["detection_rule"]["name"], "Live Sigma PowerShell Verification")
            self.assertEqual(alert.ocsf_data["process"]["parent_process"], r"C:\Windows\explorer.exe")
            self.assertEqual(alert.ocsf_data["event"]["event_id"], 4688)
            self.assertIn("T1059.001", alert.ocsf_data["attack_techniques"])
            self.assertGreaterEqual(alert.ocsf_data["confidence"], 80)
            self.assertTrue(alert.ocsf_data["recommendations"])
            self.assertIn("Live Sigma PowerShell Verification", alert.ocsf_data["message"])
            self.assertIn("powershell.exe", alert.ocsf_data["message"].lower())
            self.assertIn("EncodedCommand", alert.ocsf_data["message"])
            self.assertIsNotNone(alert.processed_at)
            incident = db.query(Incident).first()
            self.assertIsNotNone(incident)
            self.assertIn("Live Sigma PowerShell Verification", incident.title)
            self.assertIn("powershell.exe", incident.title.lower())
            self.assertEqual(incident.attack_technique["technique_id"], "T1059.001")
            self.assertTrue(incident.recommended_actions)
        finally:
            db.close()

        events_response = self.client.get("/api/v1/events")
        self.assertEqual(events_response.status_code, 200)
        stored_event = next(item for item in events_response.json() if item["id"] == payload["id"])
        self.assertEqual(stored_event["detection_status"], "matched")
        self.assertEqual(stored_event["detection_count"], 1)

        duplicate_response = self.client.post(
            "/api/v1/events/ingest",
            json={
                "source": "windows-agent",
                "event_type": "process",
                "timestamp": "2026-07-05T10:55:08Z",
                "raw_event": {
                    "timestamp": 1783264508,
                    "event_id": 4688,
                    "process": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "command_line": "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIAVABlAHMAdAAiAA==",
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "CommandLine": "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIAVABlAHMAdAAiAA==",
                    "ParentImage": r"C:\Windows\explorer.exe",
                },
                "normalized_event": {
                    "process": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "command": "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIAVABlAHMAdAAiAA==",
                    "command_line": "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIAVABlAHMAdAAiAA==",
                    "parent_process": r"C:\Windows\explorer.exe",
                },
                "severity": "high",
            },
        )
        self.assertEqual(duplicate_response.status_code, 201)
        self.assertEqual(duplicate_response.json()["id"], payload["id"])
        db = self.SessionTesting()
        try:
            self.assertEqual(db.query(SecurityEvent).count(), 2)
            self.assertEqual(db.query(Alert).filter(Alert.event_id == payload["id"]).count(), 1)
        finally:
            db.close()
