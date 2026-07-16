from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence, Any
import hashlib
import json

from sqlalchemy.orm import Session, joinedload

from src.models.sqlalchemy import Alert, AlertStatus, Incident, IncidentStatus, MitreTechnique


@dataclass
class CorrelationCandidate:
    incident: Optional[Incident]
    alerts: list[Alert]
    correlation_score: float
    correlation_reasons: list[str]
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None


class CorrelationService:
    DEFAULT_WINDOW_MINUTES = 15
    DUPLICATE_WINDOW_MINUTES = 60

    def correlate_alert(self, db: Session, alert: Alert) -> CorrelationCandidate:
        # Check for duplicates first
        duplicate_check = self._check_duplicate(db, alert)
        if duplicate_check:
            return duplicate_check

        window_start = self._to_utc(alert.created_at) - timedelta(minutes=self.DEFAULT_WINDOW_MINUTES)

        recent_alerts = (
            db.query(Alert)
            .filter(
                Alert.tenant_id == alert.tenant_id,
                Alert.id != alert.id,
                Alert.created_at >= window_start,
                Alert.status != AlertStatus.DISMISSED,
            )
            .options(joinedload(Alert.incident))
            .order_by(Alert.created_at.asc())
            .limit(500)
            .all()
        )

        best_candidate: Optional[CorrelationCandidate] = None

        for candidate_alert in recent_alerts:
            score, reasons = self._pair_score(db, alert, candidate_alert)
            if score <= 0:
                continue

            candidate_incident = candidate_alert.incident
            if candidate_incident and candidate_incident.status not in (
                IncidentStatus.OPEN,
                IncidentStatus.INVESTIGATING,
            ):
                candidate_incident = None

            if best_candidate is None or score > best_candidate.correlation_score:
                grouped_alerts = [alert, candidate_alert]
                if candidate_incident:
                    for linked_alert in candidate_incident.alerts:
                        if linked_alert.id not in {item.id for item in grouped_alerts}:
                            grouped_alerts.append(linked_alert)
                best_candidate = CorrelationCandidate(
                    incident=candidate_incident,
                    alerts=grouped_alerts,
                    correlation_score=score,
                    correlation_reasons=reasons,
                )

        if best_candidate is None:
            default_reason = self._standalone_reason(alert)
            return CorrelationCandidate(
                incident=None,
                alerts=[alert],
                correlation_score=0,
                correlation_reasons=[default_reason],
            )

        best_candidate.alerts = sorted(
            {item.id: item for item in best_candidate.alerts}.values(),
            key=lambda item: self._to_utc(item.created_at),
        )
        return best_candidate

    def _check_duplicate(self, db: Session, alert: Alert) -> Optional[CorrelationCandidate]:
        alert_fingerprint = self._generate_alert_fingerprint(alert)
        window_start = self._to_utc(alert.created_at) - timedelta(minutes=self.DUPLICATE_WINDOW_MINUTES)
        
        duplicate_alert = (
            db.query(Alert)
            .filter(
                Alert.tenant_id == alert.tenant_id,
                Alert.id != alert.id,
                Alert.created_at >= window_start,
            )
            .options(joinedload(Alert.incident))
            .limit(500)
            .all()
        )

        for candidate in duplicate_alert:
            candidate_fingerprint = self._generate_alert_fingerprint(candidate)
            if alert_fingerprint == candidate_fingerprint:
                candidate_incident = candidate.incident
                return CorrelationCandidate(
                    incident=candidate_incident,
                    alerts=[alert, candidate],
                    correlation_score=100,
                    correlation_reasons=["Duplicate alert detected - same event fingerprint"],
                    is_duplicate=True,
                    duplicate_of=candidate.id,
                )
        return None

    def _generate_alert_fingerprint(self, alert: Alert) -> str:
        raw = alert.raw_data or {}
        ocsf = alert.ocsf_data or {}
        indicators = self._indicators(alert)
        
        fingerprint_data = {
            "source_id": alert.source_id,
            "detection_rule_id": alert.detection_rule_id,
            "event_id": alert.event_id,
            "class_name": ocsf.get("class_name"),
            "activity_name": ocsf.get("activity_name"),
            "process": raw.get("Image") or raw.get("process") or self._field_value(ocsf.get("process"), "name"),
            "command_line": raw.get("CommandLine") or raw.get("command_line") or raw.get("command") or self._field_value(ocsf.get("process"), "cmd_line"),
            "event_timestamp": raw.get("timestamp"),
            "windows_event_id": raw.get("event_id") or raw.get("EventID"),
            "user": indicators["user"],
            "ip": indicators["ip"],
            "hostname": indicators["hostname"],
        }
        
        # Remove None values
        fingerprint_data = {k: v for k, v in fingerprint_data.items() if v is not None}
        
        fingerprint_json = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_json.encode()).hexdigest()

    def _pair_score(self, db: Session, alert: Alert, candidate: Alert) -> tuple[float, list[str]]:
        current = self._indicators(alert)
        existing = self._indicators(candidate)
        reasons: list[str] = []
        score = 0.0

        if current["user"] and current["user"] == existing["user"]:
            score += 30
            reasons.append("Grouped because same user was detected within 15 minutes")

        if current["ip"] and current["ip"] == existing["ip"]:
            score += 25
            reasons.append("Grouped because same IP was detected within 15 minutes")

        if current["hostname"] and current["hostname"] == existing["hostname"]:
            score += 20
            reasons.append("Grouped because same hostname/device was detected within 15 minutes")

        time_delta = abs(self._to_utc(alert.created_at) - self._to_utc(candidate.created_at))
        if time_delta <= timedelta(minutes=self.DEFAULT_WINDOW_MINUTES):
            score += 10
            reasons.append("Grouped because alerts occurred within the 15 minute correlation window")

        if self._is_account_takeover_pattern(alert, candidate):
            score += 25
            reasons.append(
                "Multiple authentication failures followed by successful login from same IP/user"
            )

        attack_chain_score = self._check_attack_chain(db, alert, candidate)
        if attack_chain_score > 0:
            score += attack_chain_score
            reasons.append("Alert matches MITRE ATT&CK attack chain progression pattern")

        return min(score, 100), list(dict.fromkeys(reasons))

    def _check_attack_chain(self, db: Session, alert: Alert, candidate: Alert) -> float:
        # Check for MITRE ATT&CK technique progression
        alert_techniques = self._extract_mitre_techniques(alert)
        candidate_techniques = self._extract_mitre_techniques(candidate)
        
        if not alert_techniques or not candidate_techniques:
            return 0

        technique_ids = set(alert_techniques + candidate_techniques)
        technique_tactics = {
            technique.technique_id: technique.tactic.value
            for technique in db.query(MitreTechnique).filter(MitreTechnique.technique_id.in_(technique_ids)).all()
        }
        tactic_order = [
            "Reconnaissance",
            "Resource Development",
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact",
        ]

        for a_tech in alert_techniques:
            for c_tech in candidate_techniques:
                a_tactic = technique_tactics.get(a_tech)
                c_tactic = technique_tactics.get(c_tech)
                
                if a_tactic and c_tactic and a_tactic in tactic_order and c_tactic in tactic_order:
                    a_index = tactic_order.index(a_tactic)
                    c_index = tactic_order.index(c_tactic)
                    
                    # If tactics are sequential and in order
                    if abs(a_index - c_index) == 1:
                        return 20
        
        return 0

    def _extract_mitre_techniques(self, alert: Alert) -> list[str]:
        ocsf = alert.ocsf_data or {}
        attack_techniques = ocsf.get("attack_techniques", [])
        if not attack_techniques and alert.incident:
            attack_techniques = alert.incident.attack_technique or []
        
        if isinstance(attack_techniques, dict):
            return [str(k) for k in attack_techniques.keys()]
        elif isinstance(attack_techniques, list):
            return [str(t) for t in attack_techniques]
        return []

    def derive_incident_metadata(self, alerts: Sequence[Alert]) -> tuple[str, str]:
        alerts = list(alerts)
        classes = {str((alert.ocsf_data or {}).get("class_name", "")).lower() for alert in alerts}
        activities = [str((alert.ocsf_data or {}).get("activity_name", "")).lower() for alert in alerts]
        event_types = [str((alert.raw_data or {}).get("event_type", "")).lower() for alert in alerts]
        primary_alert = alerts[0] if alerts else None
        if primary_alert and primary_alert.detection_rule:
            raw = primary_alert.raw_data or {}
            ocsf = primary_alert.ocsf_data or {}
            process_name = raw.get("Image") or raw.get("process") or self._field_value(ocsf.get("process"), "name")
            command_line = raw.get("CommandLine") or raw.get("command_line") or self._field_value(ocsf.get("process"), "cmd_line")
            technique = primary_alert.detection_rule.mitre_technique_id
            technique_text = f" mapped to {technique}" if technique else ""
            process_text = f" for {process_name}" if process_name else ""
            title = f"{primary_alert.detection_rule.name}{process_text}"
            description_parts = [
                f"{primary_alert.detection_rule.name} generated a {primary_alert.severity.value if hasattr(primary_alert.severity, 'value') else primary_alert.severity} severity alert{technique_text}.",
            ]
            if command_line:
                description_parts.append(f"Observed command line: {command_line}")
            if primary_alert.why_matched:
                description_parts.append(f"Match reason: {primary_alert.why_matched}")
            return title, " ".join(description_parts)

        if "malware" in classes:
            malware_name = next(
                (
                    (alert.ocsf_data or {}).get("malware", {}).get("name")
                    for alert in alerts
                    if (alert.ocsf_data or {}).get("malware")
                ),
                None,
            )
            title = f"Malware Detection: {malware_name}" if malware_name else "Malware Detection"
            return title, "Potential malware execution or delivery activity requires containment."

        has_failed_login = any(
            "failed" in activity
            or "brute force" in activity
            or activity == "login attempt"
            or event_type in {"login_failed", "failed_login", "brute_force"}
            for activity, event_type in zip(activities, event_types)
        )
        has_successful_login = any(
            activity == "login"
            or "login success" in activity
            or event_type in {"login", "login_success", "successful_login"}
            for activity, event_type in zip(activities, event_types)
        )
        if has_failed_login and has_successful_login:
            return (
                "Possible Account Takeover",
                "Authentication failures were followed by a successful login in the same correlation window.",
            )

        if "network" in classes:
            return (
                "Suspicious Network Activity",
                "Multiple related network alerts were correlated by indicator overlap and time proximity.",
            )

        return (
            "Correlated Security Activity",
            "Related alerts were grouped into a single analyst-facing incident.",
        )

    def _indicators(self, alert: Alert) -> dict:
        raw = alert.raw_data or {}
        ocsf = alert.ocsf_data or {}
        user = ocsf.get("user")
        source = ocsf.get("source")
        destination = ocsf.get("destination")
        device = ocsf.get("device")
        return {
            "user": raw.get("user") or self._field_value(user, "name"),
            "ip": raw.get("ip")
            or raw.get("source_ip")
            or self._field_value(source, "ip")
            or self._field_value(destination, "ip"),
            "hostname": raw.get("hostname")
            or raw.get("device")
            or raw.get("host")
            or self._field_value(device, "hostname"),
        }

    def _field_value(self, value: Any, key: str) -> Any:
        if isinstance(value, dict):
            return value.get(key)
        if isinstance(value, str):
            return value
        return None

    def _is_account_takeover_pattern(self, alert: Alert, candidate: Alert) -> bool:
        activities = [
            str((alert.ocsf_data or {}).get("activity_name", "")).lower(),
            str((candidate.ocsf_data or {}).get("activity_name", "")).lower(),
        ]
        event_types = [
            str((alert.raw_data or {}).get("event_type", "")).lower(),
            str((candidate.raw_data or {}).get("event_type", "")).lower(),
        ]
        has_failed = any(
            "failed" in activity
            or "brute force" in activity
            or activity == "login attempt"
            or event_type in {"login_failed", "failed_login", "brute_force"}
            for activity, event_type in zip(activities, event_types)
        )
        has_success = any(activity == "login" or event_type == "login" for activity, event_type in zip(activities, event_types))
        return has_failed and has_success

    def _standalone_reason(self, alert: Alert) -> str:
        class_name = str((alert.ocsf_data or {}).get("class_name", "Security"))
        return f"Standalone {class_name.lower()} alert created a new incident for analyst review"

    def _to_utc(self, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


correlation_service = CorrelationService()
