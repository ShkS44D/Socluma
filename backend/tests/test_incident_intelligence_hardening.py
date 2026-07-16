import json
import unittest
from datetime import datetime, timezone

from src.models.sqlalchemy import Alert, EventType, SecurityEvent, Severity
from src.models.pydantic import IncidentAlertLink
from src.services.incident_intelligence_service import IncidentIntelligenceService
from src.services.llm_provider import GeminiProvider
from src.services.risk_service import RiskService


class IncidentIntelligenceHardeningTests(unittest.TestCase):
    def setUp(self):
        self.service = IncidentIntelligenceService()

    def test_entity_validation_normalization_and_deduplication(self):
        event = SecurityEvent(
            id="event-1",
            tenant_id="tenant-1",
            source="windows-edr",
            event_type=EventType.PROCESS,
            severity=Severity.HIGH,
            raw_event={
                "source_ip": "2001:0DB8:0:0:0:0:0:1",
                "destination_ip": "not-an-ip",
                "domain": "Example.COM.",
                "email": "Analyst@Example.com",
                "sha256": "A" * 64,
                "url": "https://example.com/path",
                "request_url": "javascript:alert(1)",
                "process": "PowerShell.EXE",
            },
            normalized_event={"source_ip": "2001:db8::1", "process": "powershell.exe"},
        )
        alert = Alert(
            id="alert-1",
            tenant_id="tenant-1",
            event=event,
            event_id=event.id,
            raw_data=event.raw_event,
            ocsf_data={},
            severity=Severity.HIGH,
        )

        entities = self.service.extract_alert_entities(alert)
        values = {(item["type"], item["normalized_value"]) for item in entities}

        self.assertIn(("ip_address", "2001:db8::1"), values)
        self.assertIn(("domain", "example.com"), values)
        self.assertIn(("email_address", "analyst@example.com"), values)
        self.assertIn(("file_hash", "a" * 64), values)
        self.assertIn(("url", "https://example.com/path"), values)
        self.assertIn(("process", "powershell.exe"), values)
        self.assertNotIn(("ip_address", "not-an-ip"), values)
        self.assertNotIn(("url", "javascript:alert(1)"), values)
        self.assertEqual(sum(1 for item in values if item == ("ip_address", "2001:db8::1")), 1)

    def test_provider_failure_categories_are_stable_and_safe(self):
        self.assertEqual(GeminiProvider._classify_error(TimeoutError("request timed out")), "timeout")
        self.assertEqual(GeminiProvider._classify_error(RuntimeError("429 quota exhausted")), "quota_exhausted")
        self.assertEqual(GeminiProvider._classify_error(RuntimeError("invalid API key")), "invalid_api_key")
        self.assertEqual(GeminiProvider._classify_error(ConnectionError("network connection failed")), "network_error")
        self.assertEqual(
            GeminiProvider._classify_error(json.JSONDecodeError("bad", "x", 0)),
            "malformed_response",
        )

    def test_risk_breakdown_reconciles_when_score_is_bounded(self):
        class ControlledRiskService(RiskService):
            def _suspicious_behavior_bonus(self, alerts, reasons):
                return 35

            def _threat_intel_bonus(self, results):
                return 35

            def _asset_criticality_bonus(self, db, tenant_id, alerts):
                return 30

            def _mitre_technique_bonus(self, db, alerts):
                return 25

            def _false_positive_penalty(self, db, tenant_id, title):
                return 0

            def _true_positive_bonus(self, db, tenant_id, title):
                return 15

        result = ControlledRiskService().calculate_risk(
            db=object(),
            tenant_id="tenant-1",
            alerts=[Alert(severity=Severity.CRITICAL), Alert(severity=Severity.HIGH)],
            correlation_reasons=["same user"],
            incident_title="Controlled incident",
            threat_intel_results=[],
        )
        breakdown = result["breakdown"]
        components = [
            "base_severity",
            "multiple_alerts",
            "suspicious_behavior",
            "threat_intelligence",
            "asset_criticality",
            "mitre_techniques",
            "confirmed_true_positive",
            "false_positive_history_penalty",
            "bounding_adjustment",
        ]
        self.assertEqual(result["risk_score"], 100.0)
        self.assertEqual(sum(float(breakdown[key]) for key in components), breakdown["total"])
        self.assertGreater(breakdown["uncapped_total"], breakdown["total"])

    def test_legacy_incident_alert_null_metadata_serializes_as_empty_lists(self):
        now = datetime.now(timezone.utc)
        link = IncidentAlertLink.model_validate(
            {
                "id": "link-1",
                "alert_id": "alert-1",
                "correlation_score": 0,
                "matching_entities": None,
                "matching_indicators": None,
                "created_at": now,
                "alert": {
                    "id": "alert-1",
                    "tenant_id": "tenant-1",
                    "source_id": "source-1",
                    "severity": "high",
                    "status": "open",
                    "raw_data": {},
                    "ocsf_data": {},
                    "created_at": now,
                },
            }
        )

        self.assertEqual(link.matching_entities, [])
        self.assertEqual(link.matching_indicators, [])


if __name__ == "__main__":
    unittest.main()
