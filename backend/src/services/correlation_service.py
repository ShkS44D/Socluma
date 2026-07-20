from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence, Any
import hashlib
import json
from time import perf_counter

from sqlalchemy import and_, exists, func, or_
from sqlalchemy.orm import Session, joinedload

from src.core.config import get_settings
from src.models.sqlalchemy import (
    Alert,
    AlertStatus,
    Incident,
    IncidentAlert,
    IncidentStatus,
    MitreTechnique,
    SecurityEvent,
)


@dataclass
class CorrelationCandidate:
    incident: Optional[Incident]
    alerts: list[Alert]
    correlation_score: float
    correlation_reasons: list[str]
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    qualified: bool = False
    matched_identifiers: list[str] | None = None
    candidate_alert_ids: list[str] | None = None
    correlation_kind: str = "pending"
    evaluated_candidate_count: int = 0
    query_duration_ms: float = 0.0


class CorrelationService:
    DUPLICATE_WINDOW_MINUTES = 60
    CANDIDATE_PAGE_SIZE = 500

    def __init__(self) -> None:
        settings = get_settings()
        self.window_minutes = settings.CORRELATION_WINDOW_MINUTES
        self.minimum_score = settings.CORRELATION_MIN_SCORE
        self.minimum_alerts = settings.CORRELATION_MIN_ALERTS
        self.allow_repeated_alerts = settings.CORRELATION_ALLOW_REPEATED_ALERTS

    def correlate_alert(self, db: Session, alert: Alert) -> CorrelationCandidate:
        query_started_at = perf_counter()
        observed_at = self._observed_at(alert)
        window_start = observed_at - timedelta(minutes=self.window_minutes)
        window_end = observed_at + timedelta(minutes=self.window_minutes)
        observed_expression = func.coalesce(SecurityEvent.timestamp, Alert.created_at)

        # Existing links are considered only for attaching to their current active
        # incident. They can never seed a different incident.
        active_query = (
            db.query(Alert, Incident)
            .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
            .join(Incident, Incident.id == IncidentAlert.incident_id)
            .outerjoin(SecurityEvent, SecurityEvent.id == Alert.event_id)
            .filter(
                Alert.tenant_id == alert.tenant_id,
                Incident.tenant_id == alert.tenant_id,
                Alert.id != alert.id,
                Alert.status != AlertStatus.DISMISSED,
                Incident.status.in_((IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)),
                observed_expression >= window_start,
                observed_expression <= window_end,
            )
            .options(joinedload(Alert.event))
        )

        best_candidate: Optional[CorrelationCandidate] = None
        evaluated_candidate_ids: list[str] = []
        for active_rows in self._paged_candidates(active_query, observed_expression, tuple_rows=True):
            evaluated_candidate_ids.extend(candidate_alert.id for candidate_alert, _ in active_rows)
            for candidate_alert, candidate_incident in active_rows:
                scored = self._qualified_pair(db, alert, candidate_alert)
                if scored is None:
                    continue
                score, reasons, matched, kind = scored
                grouped_alerts = [alert]
                for link in sorted(candidate_incident.incident_alerts, key=lambda row: (row.sequence_order, row.alert_id)):
                    if link.alert and link.alert.id not in {item.id for item in grouped_alerts}:
                        grouped_alerts.append(link.alert)
                proposed = CorrelationCandidate(
                    incident=candidate_incident,
                    alerts=grouped_alerts,
                    correlation_score=score,
                    correlation_reasons=reasons,
                    qualified=True,
                    matched_identifiers=matched,
                    candidate_alert_ids=[item.id for item in grouped_alerts if item.id != alert.id],
                    correlation_kind=kind,
                )
                if self._is_better_candidate(proposed, best_candidate, candidate_alert.id):
                    best_candidate = proposed

        # New incidents may use only pending, completely unassociated alerts.
        linked_alert_exists = exists().where(IncidentAlert.alert_id == Alert.id)
        pending_query = (
            db.query(Alert)
            .outerjoin(SecurityEvent, SecurityEvent.id == Alert.event_id)
            .filter(
                Alert.tenant_id == alert.tenant_id,
                Alert.id != alert.id,
                Alert.status != AlertStatus.DISMISSED,
                Alert.incident_id.is_(None),
                ~linked_alert_exists,
                observed_expression >= window_start,
                observed_expression <= window_end,
            )
            .options(joinedload(Alert.event), joinedload(Alert.detection_rule))
        )
        for pending_alerts in self._paged_candidates(pending_query, observed_expression):
            evaluated_candidate_ids.extend(item.id for item in pending_alerts)
            for candidate_alert in pending_alerts:
                scored = self._qualified_pair(db, alert, candidate_alert)
                if scored is None:
                    continue
                score, reasons, matched, kind = scored
                proposed = CorrelationCandidate(
                    incident=None,
                    alerts=[alert, candidate_alert],
                    correlation_score=score,
                    correlation_reasons=reasons,
                    qualified=True,
                    matched_identifiers=matched,
                    candidate_alert_ids=[candidate_alert.id],
                    correlation_kind=kind,
                )
                if self._is_better_candidate(proposed, best_candidate, candidate_alert.id):
                    best_candidate = proposed

        if best_candidate is None:
            default_reason = self._standalone_reason(alert)
            return CorrelationCandidate(
                incident=None,
                alerts=[alert],
                correlation_score=0,
                correlation_reasons=[default_reason],
                qualified=False,
                matched_identifiers=[],
                candidate_alert_ids=list(dict.fromkeys(evaluated_candidate_ids)),
                correlation_kind="pending",
                evaluated_candidate_count=len(set(evaluated_candidate_ids)),
                query_duration_ms=(perf_counter() - query_started_at) * 1000,
            )

        best_candidate.evaluated_candidate_count = len(set(evaluated_candidate_ids))
        best_candidate.query_duration_ms = (perf_counter() - query_started_at) * 1000
        best_candidate.alerts = sorted(
            {item.id: item for item in best_candidate.alerts}.values(),
            key=lambda item: (self._observed_at(item), item.id),
        )
        return best_candidate

    def _paged_candidates(self, query: Any, observed_expression: Any, *, tuple_rows: bool = False):
        """Keyset-page every eligible row in the bounded event-time window."""
        cursor_time: datetime | None = None
        cursor_id: str | None = None
        while True:
            page_query = query
            if cursor_time is not None and cursor_id is not None:
                page_query = page_query.filter(or_(
                    observed_expression < cursor_time,
                    and_(observed_expression == cursor_time, Alert.id < cursor_id),
                ))
            rows = (
                page_query.order_by(observed_expression.desc(), Alert.id.desc())
                .limit(self.CANDIDATE_PAGE_SIZE)
                .all()
            )
            if not rows:
                return
            yield rows
            last_alert = rows[-1][0] if tuple_rows else rows[-1]
            cursor_time = self._observed_at(last_alert)
            cursor_id = last_alert.id
            if len(rows) < self.CANDIDATE_PAGE_SIZE:
                return

    def _qualified_pair(
        self, db: Session, alert: Alert, candidate: Alert
    ) -> tuple[float, list[str], list[str], str] | None:
        if alert.event_id and alert.event_id == candidate.event_id:
            return None
        score, reasons = self._pair_score(db, alert, candidate)
        matched = self._matched_identifier_names(alert, candidate)
        strong_identifiers = {
            "hostname", "agent_id", "source_ip", "destination_ip", "source_host",
            "destination_host", "source_user", "destination_user",
        }
        has_strong_identity = bool(strong_identifiers.intersection(matched))
        has_progression = self._check_attack_chain(db, alert, candidate) > 0
        behavior_reason = self._behavior_sequence_reason(alert, candidate)
        repeated = self._is_repeated_activity(alert, candidate)
        if repeated and not self.allow_repeated_alerts:
            return None
        if score < self.minimum_score or not has_strong_identity:
            return None
        if has_progression:
            return score, reasons, matched, "attack_chain"
        if behavior_reason:
            return score, reasons + [behavior_reason], matched, "behavior_sequence"
        if repeated and self.allow_repeated_alerts:
            return score, reasons + ["Repeated-alert policy allowed related repeated activity"], matched, "repeated_activity"
        return None

    def _is_better_candidate(
        self, proposed: CorrelationCandidate, current: CorrelationCandidate | None, tie_breaker: str
    ) -> bool:
        if current is None or proposed.correlation_score > current.correlation_score:
            return True
        if proposed.correlation_score < current.correlation_score:
            return False
        if proposed.incident is not None and current.incident is None:
            return True
        if proposed.incident is None and current.incident is not None:
            return False
        current_id = min(current.candidate_alert_ids or [""])
        return tie_breaker > current_id

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
            "mitre_techniques": sorted(self._extract_mitre_techniques(alert)),
            "observed_at": self._observed_at(alert).isoformat(),
        }
        
        # Remove None values
        fingerprint_data = {k: v for k, v in fingerprint_data.items() if v is not None}
        
        fingerprint_json = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_json.encode()).hexdigest()

    def _pair_score(self, db: Session, alert: Alert, candidate: Alert) -> tuple[float, list[str]]:
        current = self._identifiers(alert)
        existing = self._identifiers(candidate)
        reasons: list[str] = []
        score = 0.0

        weights = {
            "hostname": 25, "agent_id": 25, "source_ip": 20, "destination_ip": 20,
            "source_host": 18, "destination_host": 18, "source_user": 18, "destination_user": 18,
            "source_port": 5, "destination_port": 5, "rule_id": 20,
        }
        for name, weight in weights.items():
            if current.get(name) is not None and current.get(name) == existing.get(name):
                score += weight
                reasons.append(f"Matched {name.replace('_', ' ')}")

        current_mitre = set(current["technique_ids"])
        existing_mitre = set(existing["technique_ids"])
        if current_mitre & existing_mitre:
            score += 15
            reasons.append("Matched MITRE technique or sub-technique")
        if current.get("tactics") and set(current["tactics"]) & set(existing["tactics"]):
            score += 10
            reasons.append("Matched MITRE tactic")

        time_delta = abs(self._observed_at(alert) - self._observed_at(candidate))
        if time_delta <= timedelta(minutes=self.window_minutes):
            proximity = max(5.0, 15.0 * (1 - time_delta.total_seconds() / (self.window_minutes * 60)))
            score += proximity
            reasons.append(f"Occurred within the {self.window_minutes}-minute correlation window")

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

        direct_alert_tactics = self._identifiers(alert)["tactics"]
        direct_candidate_tactics = self._identifiers(candidate)["tactics"]
        direct_score = self._distinct_tactic_score(
            direct_alert_tactics, direct_candidate_tactics, alert, candidate, tactic_order
        )
        if direct_score:
            return direct_score
        if not alert_techniques or not candidate_techniques:
            return 0

        technique_ids = set(alert_techniques + candidate_techniques)
        technique_tactics = {
            technique.technique_id: technique.tactic.value
            for technique in db.query(MitreTechnique).filter(MitreTechnique.technique_id.in_(technique_ids)).all()
        }

        for a_tech in alert_techniques:
            for c_tech in candidate_techniques:
                a_tactic = technique_tactics.get(a_tech)
                c_tactic = technique_tactics.get(c_tech)
                
                if a_tactic and c_tactic and a_tactic in tactic_order and c_tactic in tactic_order:
                    a_index = tactic_order.index(a_tactic)
                    c_index = tactic_order.index(c_tactic)
                    
                    if a_index == c_index:
                        continue
                    return self._distinct_tactic_score([a_tactic], [c_tactic], alert, candidate, tactic_order)
        
        return 0

    def _distinct_tactic_score(
        self,
        alert_tactics: Sequence[str],
        candidate_tactics: Sequence[str],
        alert: Alert,
        candidate: Alert,
        tactic_order: Sequence[str],
    ) -> float:
        for alert_tactic in alert_tactics:
            for candidate_tactic in candidate_tactics:
                if alert_tactic == candidate_tactic or alert_tactic not in tactic_order or candidate_tactic not in tactic_order:
                    continue
                alert_index = tactic_order.index(alert_tactic)
                candidate_index = tactic_order.index(candidate_tactic)
                tactics_follow_time = (
                    alert_index > candidate_index and self._observed_at(alert) >= self._observed_at(candidate)
                ) or (
                    candidate_index > alert_index and self._observed_at(candidate) >= self._observed_at(alert)
                )
                return 20 if tactics_follow_time else 12
        return 0

    def _extract_mitre_techniques(self, alert: Alert) -> list[str]:
        ocsf = alert.ocsf_data or {}
        attack_techniques = ocsf.get("attack_techniques", [])
        if not attack_techniques and alert.incident:
            attack_techniques = alert.incident.attack_technique or []
        
        if isinstance(attack_techniques, dict):
            if attack_techniques.get("technique_id"):
                return [str(attack_techniques["technique_id"])]
            return [str(k) for k in attack_techniques.keys() if str(k).startswith("T")]
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
        identifiers = self._identifiers(alert)
        return {"user": identifiers["source_user"], "ip": identifiers["source_ip"] or identifiers["destination_ip"], "hostname": identifiers["hostname"]}

    def _identifiers(self, alert: Alert) -> dict[str, Any]:
        raw = alert.raw_data or {}
        ocsf = alert.ocsf_data or {}
        event_data = (alert.event.normalized_event if alert.event else None) or {}
        combined = {**raw, **event_data}
        user = ocsf.get("user") or {}
        source = ocsf.get("source") or {}
        destination = ocsf.get("destination") or {}
        device = ocsf.get("device")
        technique_ids = self._extract_mitre_techniques(alert)
        tactics = []
        for item in (ocsf.get("attack_tactics") or []):
            tactics.append(str(item.get("name") if isinstance(item, dict) else item))
        return {
            "hostname": combined.get("hostname") or combined.get("machine") or combined.get("device") or combined.get("host")
            or self._field_value(device, "hostname"),
            "agent_id": combined.get("agent_id") or (
                combined.get("agent", {}).get("id") if isinstance(combined.get("agent"), dict) else None
            ),
            "rule_id": alert.detection_rule_id or combined.get("rule_id"),
            "source_ip": combined.get("source_ip") or combined.get("src_ip") or self._field_value(source, "ip"),
            "source_host": combined.get("source_host") or combined.get("src_host") or self._field_value(source, "hostname"),
            "source_user": combined.get("source_user") or combined.get("user") or self._field_value(source, "user") or self._field_value(user, "name"),
            "source_port": combined.get("source_port") or combined.get("src_port") or self._field_value(source, "port"),
            "destination_ip": combined.get("destination_ip") or combined.get("dst_ip") or self._field_value(destination, "ip"),
            "destination_host": combined.get("destination_host") or combined.get("dst_host") or self._field_value(destination, "hostname"),
            "destination_user": combined.get("destination_user") or self._field_value(destination, "user"),
            "destination_port": combined.get("destination_port") or combined.get("dst_port") or self._field_value(destination, "port"),
            "technique_ids": technique_ids,
            "tactics": tactics,
        }

    def _matched_identifier_names(self, alert: Alert, candidate: Alert) -> list[str]:
        left, right = self._identifiers(alert), self._identifiers(candidate)
        names = []
        for key in ("hostname", "agent_id", "rule_id", "source_ip", "source_host", "source_user", "source_port", "destination_ip", "destination_host", "destination_user", "destination_port"):
            if left.get(key) is not None and left.get(key) == right.get(key):
                names.append(key)
        if set(left["technique_ids"]) & set(right["technique_ids"]):
            names.append("mitre_technique")
        return names

    def _observed_at(self, alert: Alert) -> datetime:
        value = alert.event.timestamp if alert.event and alert.event.timestamp else alert.created_at
        return self._to_utc(value)

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

    def _is_repeated_activity(self, alert: Alert, candidate: Alert) -> bool:
        left = self._identifiers(alert)
        right = self._identifiers(candidate)
        alert_raw = alert.raw_data or {}
        candidate_raw = candidate.raw_data or {}
        return (
            alert.detection_rule_id == candidate.detection_rule_id
            and set(left["technique_ids"]) == set(right["technique_ids"])
            and set(left["tactics"]) == set(right["tactics"])
            and alert_raw.get("event_type") == candidate_raw.get("event_type")
            and alert_raw.get("file_hash") == candidate_raw.get("file_hash")
            and alert_raw.get("destination_ip") == candidate_raw.get("destination_ip")
            and any(
                left.get(field) is not None and left.get(field) == right.get(field)
                for field in ("hostname", "agent_id", "source_ip", "destination_ip", "source_user")
            )
        )

    def _behavior_sequence_reason(self, alert: Alert, candidate: Alert) -> str | None:
        if self._is_account_takeover_pattern(alert, candidate):
            return "Correlated as a deterministic failed-login/successful-login sequence"
        alert_raw = alert.raw_data or {}
        candidate_raw = candidate.raw_data or {}
        alert_type = str(alert_raw.get("event_type") or "").lower()
        candidate_type = str(candidate_raw.get("event_type") or "").lower()
        if (
            alert_type == candidate_type == "malware_detection"
            and alert_raw.get("malware_name")
            and alert_raw.get("malware_name") == candidate_raw.get("malware_name")
            and alert_raw.get("file_hash")
            and candidate_raw.get("file_hash")
            and alert_raw.get("file_hash") != candidate_raw.get("file_hash")
        ):
            return "Correlated as multiple distinct artifacts from the same malware family"
        network_types = {alert_type, candidate_type}
        if (
            len(network_types) == 2
            and "suspicious_network" in network_types
            and network_types.intersection({"connection", "network_connection"})
        ):
            return "Correlated as suspicious network activity followed by a related connection"
        return None

    def _standalone_reason(self, alert: Alert) -> str:
        class_name = str((alert.ocsf_data or {}).get("class_name", "Security"))
        return f"Pending {class_name.lower()} alert awaiting a related alert within the correlation window"

    def _to_utc(self, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


correlation_service = CorrelationService()
