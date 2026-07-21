from __future__ import annotations
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session, joinedload
from dataclasses import dataclass
import logging
import yaml

from src.models.sqlalchemy import (
    DetectionRule, RuleType, Severity, SecurityEvent, Alert, AlertSource,
    DetectionMatch as DetectionMatchModel, AlertStatus
)
from src.models.pydantic import AlertCreate
from src.services.incident_service import incident_service
from src.services.sigma_rule_service import sigma_rule_service
from src.services.websocket_service import broadcast_notification_sync, NotificationType
from src.core.config import get_settings
from src.core.observability import ALERTS_CREATED, timed_detection
from src.utils.datetime_utils import get_utc_now, utc_isoformat

settings = get_settings()
logger = logging.getLogger(__name__)


@dataclass
class DetectionMatch:
    rule_id: str
    rule_name: str
    severity: Severity
    event_id: str
    match_details: Dict[str, Any]


@dataclass
class EventAnalysisResult:
    event_id: str
    processed: bool
    matched_rules: List[Dict[str, Any]]
    incident_created: bool
    incident_id: Optional[str] = None


class DetectionEngine:
    def process_event(
        self, 
        db: Session, 
        tenant_id: str, 
        event: SecurityEvent
    ) -> List[DetectionMatchModel]:
        matches: List[DetectionMatchModel] = []
        
        enabled_rules = db.query(DetectionRule).filter(
            DetectionRule.tenant_id == tenant_id,
            DetectionRule.enabled == True
        ).all()
        rule_ids = [rule.id for rule in enabled_rules]
        existing_matches = {}
        if rule_ids:
            existing_matches = {
                existing.rule_id: existing
                for existing in (
                    db.query(DetectionMatchModel)
                    .options(joinedload(DetectionMatchModel.alert))
                    .filter(
                        DetectionMatchModel.tenant_id == tenant_id,
                        DetectionMatchModel.event_id == event.id,
                        DetectionMatchModel.rule_id.in_(rule_ids),
                    )
                    .all()
                )
            }

        for rule in enabled_rules:
            # Skip if rule has event_type and it doesn't match the event
            if rule.event_type and rule.event_type != event.event_type:
                continue

            existing_match = existing_matches.get(rule.id)
            if existing_match:
                existing_alert = existing_match.alert
                matches.append((
                    existing_match,
                    {
                        "matched": True,
                        "matched_condition": existing_alert.matched_condition if existing_alert else None,
                        "why_matched": existing_alert.why_matched if existing_alert else "Existing detection match",
                    },
                ))
                continue
                
            match_result = self._match_rule(rule, event)
            if match_result['matched']:
                match = DetectionMatchModel(
                    tenant_id=tenant_id,
                    event_id=event.id,
                    rule_id=rule.id,
                    matched=True,
                    severity=rule.severity
                )
                db.add(match)
                matches.append((match, match_result))
        
        # Mark event as processed
        event.processed = True
        db.add(event)
        db.commit()
        
        return matches

    def analyze_and_process_event(
        self,
        db: Session,
        tenant_id: str,
        event: SecurityEvent,
        *,
        allow_external_enrichment: bool = True,
    ) -> EventAnalysisResult:
        with timed_detection():
            matches_with_results = self.process_event(db, tenant_id, event)
        matched_rules = []
        incident_created = False
        incident_id = None
        source_id = self._get_detection_source_id(db, tenant_id) if matches_with_results else None

        for match, match_result in matches_with_results:
            # Refresh the match to get the rule relation
            db.refresh(match, attribute_names=["rule"])
            matched_rules.append({
                "rule": match.rule.name, 
                "severity": match.severity.value,
                "mitre_technique_id": match.rule.mitre_technique_id
            })
            
            alert = self.create_alert_from_match(db, tenant_id, match, event, match_result, source_id=source_id)
            
            if settings.USE_REDIS_MOCK:
                incident = incident_service.process_alert(db, alert, allow_external_enrichment=allow_external_enrichment)
                incident_created = incident is not None
                incident_id = incident.id if incident else None
            else:
                from src.workers.tasks import process_alert_for_incident_sync
                try:
                    result = process_alert_for_incident_sync(alert.id, allow_external_enrichment=allow_external_enrichment)
                    incident_created = not result.startswith("pending:")
                    incident_id = result if incident_created else None
                except Exception:
                    logger.exception("Sync incident processing failed; alert was stored", extra={"alert_id": alert.id})
        
        return EventAnalysisResult(
            event_id=event.id,
            processed=True,
            matched_rules=matched_rules,
            incident_created=incident_created,
            incident_id=incident_id
        )

    def _get_detection_source_id(self, db: Session, tenant_id: str) -> str:
        default_source = db.query(AlertSource).filter(
            AlertSource.tenant_id == tenant_id,
            AlertSource.name == "Detection Engine"
        ).first()

        if not default_source:
            default_source = AlertSource(
                tenant_id=tenant_id,
                name="Detection Engine",
                type="MANUAL",
                enabled=True
            )
            db.add(default_source)
            db.commit()
            db.refresh(default_source)

        return default_source.id

    def _match_rule(self, rule: DetectionRule, event: SecurityEvent) -> Dict[str, Any]:
        normalized_event = event.normalized_event or {}
        raw_event = event.raw_event or {}
        
        combined_event = {
            **raw_event,
            **normalized_event,
            "raw_data": raw_event,
            "normalized_event": normalized_event,
        }
        
        result = {'matched': False, 'matched_condition': None, 'why_matched': None}
        
        try:
            # Check if we have the new condition field
            if rule.condition:
                condition = rule.condition
                if isinstance(condition, dict):
                    matched, details = self._evaluate_condition(condition, combined_event)
                    if matched:
                        result['matched'] = True
                        result['matched_condition'] = str(condition)
                        result['why_matched'] = details
                        return result
            
            # Fallback to old format: check query or sigma_rule
            if rule.query:
                matched, details = self._match_query(rule.query, combined_event)
                if matched:
                    result['matched'] = True
                    result['matched_condition'] = rule.query
                    result['why_matched'] = details
                    return result
                
            if rule.rule_type == RuleType.SIGMA and rule.rule_content:
                matched, details = sigma_rule_service.match(rule.rule_content, combined_event)
                if matched:
                    result['matched'] = True
                    result['matched_condition'] = str(rule.rule_content.get("detection", {}))
                    result['why_matched'] = details
                    return result

            if rule.sigma_rule:
                matched, details = self._match_sigma_rule(rule.sigma_rule, combined_event)
                if matched:
                    result['matched'] = True
                    result['matched_condition'] = rule.sigma_rule
                    result['why_matched'] = details
                    return result
            
            # If we have rule_content, check that directly too
            if rule.rule_content:
                # Treat rule_content as a sigma rule (since that's what it is)
                # Convert to YAML and pass to _match_sigma_rule, or evaluate directly
                # Let's just use the detection part of rule_content directly
                if 'detection' in rule.rule_content:
                    matched, details = sigma_rule_service.match(rule.rule_content, combined_event)
                    if matched:
                        result['matched'] = True
                        result['matched_condition'] = str(rule.rule_content['detection'])
                        result['why_matched'] = details
                        return result
        except Exception:
            logger.exception("Exception matching detection rule", extra={"rule_id": rule.id, "rule_name": rule.name, "event_id": event.id})
        
        return result
            
    def _match_query(self, query: str, event: Dict[str, Any]) -> tuple[bool, str]:
        """Fallback matcher for old query format (yaml)"""
        try:
            query_dict = yaml.safe_load(query)
            if isinstance(query_dict, dict):
                return self._evaluate_condition(query_dict, event)
        except Exception:
            logger.exception("Failed to parse legacy query detection rule")
        return False, ""
        
    def _match_sigma_rule(self, sigma_rule: str, event: Dict[str, Any]) -> tuple[bool, str]:
        """Fallback matcher for old sigma_rule format"""
        try:
            sigma_data = yaml.safe_load(sigma_rule)
            if isinstance(sigma_data, dict):
                detection = sigma_data.get("detection", {})
                return self._evaluate_sigma_detection(detection, event)
        except Exception:
            logger.exception("Failed to parse legacy Sigma detection rule")
        return False, ""

    def _evaluate_condition(self, condition: Dict[str, Any], event: Dict[str, Any]) -> tuple[bool, str]:
        """
        Evaluate a condition against an event.
        Supports:
        - Simple key-value matching
        - "contains" operator for string matching
        - Numeric comparison operators (_gte, _gt, _lte, _lt)
        - Existence check (_exists)
        - "AND" and "OR" logical operators
        Returns tuple of (matched, details)
        """
        details = []
        # Handle AND/OR logical operations
        if "AND" in condition:
            and_conditions = condition["AND"]
            if not isinstance(and_conditions, list):
                return False, "Invalid AND condition"
            all_matched = True
            for i, c in enumerate(and_conditions):
                matched, sub_details = self._evaluate_condition(c, event)
                details.append(f"AND[{i}]: {sub_details}")
                if not matched:
                    all_matched = False
            return all_matched, " | ".join(details)
            
        if "OR" in condition:
            or_conditions = condition["OR"]
            if not isinstance(or_conditions, list):
                return False, "Invalid OR condition"
            any_matched = False
            for i, c in enumerate(or_conditions):
                matched, sub_details = self._evaluate_condition(c, event)
                details.append(f"OR[{i}]: {sub_details}")
                if matched:
                    any_matched = True
            return any_matched, " | ".join(details)
        
        # Handle simple conditions
        for key, expected in condition.items():
            # Check if the key has an operator suffix
            if key.endswith("_contains"):
                actual_key = key[:-9]  # Remove "_contains" suffix
                actual_value = self._get_event_value(event, actual_key)
                if actual_value is None:
                    details.append(f"{actual_key} not present")
                    return False, " | ".join(details)
                if not self._value_contains(actual_value, expected):
                    details.append(f"{actual_key} does not contain '{expected}'")
                    return False, " | ".join(details)
                details.append(f"{actual_key} contains '{expected}'")
            elif key.endswith("_gte"):
                actual_key = key[:-4]  # Remove "_gte" suffix
                actual_value = self._get_event_value(event, actual_key)
                if actual_value is None:
                    details.append(f"{actual_key} not present")
                    return False, " | ".join(details)
                try:
                    if float(actual_value) < float(expected):
                        details.append(f"{actual_key} ({actual_value}) < {expected}")
                        return False, " | ".join(details)
                    details.append(f"{actual_key} ({actual_value}) >= {expected}")
                except (ValueError, TypeError):
                    details.append(f"Invalid {actual_key} value")
                    return False, " | ".join(details)
            elif key.endswith("_gt"):
                actual_key = key[:-3]  # Remove "_gt" suffix
                actual_value = self._get_event_value(event, actual_key)
                if actual_value is None:
                    details.append(f"{actual_key} not present")
                    return False, " | ".join(details)
                try:
                    if float(actual_value) <= float(expected):
                        details.append(f"{actual_key} ({actual_value}) <= {expected}")
                        return False, " | ".join(details)
                    details.append(f"{actual_key} ({actual_value}) > {expected}")
                except (ValueError, TypeError):
                    details.append(f"Invalid {actual_key} value")
                    return False, " | ".join(details)
            elif key.endswith("_lte"):
                actual_key = key[:-4]  # Remove "_lte" suffix
                actual_value = self._get_event_value(event, actual_key)
                if actual_value is None:
                    details.append(f"{actual_key} not present")
                    return False, " | ".join(details)
                try:
                    if float(actual_value) > float(expected):
                        details.append(f"{actual_key} ({actual_value}) > {expected}")
                        return False, " | ".join(details)
                    details.append(f"{actual_key} ({actual_value}) <= {expected}")
                except (ValueError, TypeError):
                    details.append(f"Invalid {actual_key} value")
                    return False, " | ".join(details)
            elif key.endswith("_lt"):
                actual_key = key[:-3]  # Remove "_lt" suffix
                actual_value = self._get_event_value(event, actual_key)
                if actual_value is None:
                    details.append(f"{actual_key} not present")
                    return False, " | ".join(details)
                try:
                    if float(actual_value) >= float(expected):
                        details.append(f"{actual_key} ({actual_value}) >= {expected}")
                        return False, " | ".join(details)
                    details.append(f"{actual_key} ({actual_value}) < {expected}")
                except (ValueError, TypeError):
                    details.append(f"Invalid {actual_key} value")
                    return False, " | ".join(details)
            elif key.endswith("_exists"):
                actual_key = key[:-7]  # Remove "_exists" suffix
                actual_value = self._get_event_value(event, actual_key)
                if expected and actual_value is None:
                    details.append(f"{actual_key} does not exist")
                    return False, " | ".join(details)
                if not expected and actual_value is not None:
                    details.append(f"{actual_key} exists")
                    return False, " | ".join(details)
                details.append(f"{actual_key} exists: {expected}")
            else:
                # Direct equality check
                actual_value = self._get_event_value(event, key)
                if actual_value is None:
                    details.append(f"{key} not present")
                    return False, " | ".join(details)
                    
                if isinstance(expected, list):
                    if actual_value not in expected:
                        details.append(f"{key} ({actual_value}) not in {expected}")
                        return False, " | ".join(details)
                    details.append(f"{key} ({actual_value}) in {expected}")
                else:
                    if str(actual_value).lower() != str(expected).lower():
                        details.append(f"{key} ({actual_value}) != {expected}")
                        return False, " | ".join(details)
                    details.append(f"{key} ({actual_value}) == {expected}")
        
        return True, " | ".join(details)

    def _get_event_value(self, event: Dict[str, Any], key: str) -> Any:
        return sigma_rule_service.resolve_field(event, key)

    def _value_contains(self, actual_value: Any, expected: Any) -> bool:
        expected_text = str(expected).lower()
        for value in self._scalar_values(actual_value):
            if expected_text in str(value).lower():
                return True
        return False

    def _scalar_values(self, value: Any) -> list[Any]:
        if isinstance(value, dict):
            values: list[Any] = []
            for nested in value.values():
                values.extend(self._scalar_values(nested))
            return values
        if isinstance(value, list):
            values = []
            for nested in value:
                values.extend(self._scalar_values(nested))
            return values
        return [value]
        
    def _evaluate_sigma_detection(self, detection: Dict[str, Any], event: Dict[str, Any]) -> tuple[bool, str]:
        """Backward compatibility: evaluate sigma detection format"""
        condition = detection.get("condition", "1 of them")
        
        search_identifiers = [k for k in detection.keys() if k not in ("condition", "timeframe")]
        search_results = {}
        search_details = []
        for search_id in search_identifiers:
            matched, details = self._evaluate_sigma_search(detection[search_id], event)
            search_results[search_id] = matched
            search_details.append(f"{search_id}: {details}")
        
        result, condition_details = self._evaluate_sigma_condition(condition, search_results)
        return result, f"Condition: {condition_details} | Searches: {'; '.join(search_details)}"
        
    def _evaluate_sigma_search(self, search: Any, event: Dict[str, Any]) -> tuple[bool, str]:
        """Backward compatibility: evaluate sigma search"""
        if isinstance(search, dict):
            for key, expected in search.items():
                key_lower = key.lower()
                actual = sigma_rule_service.resolve_field(event, key)
                if actual is None:
                    return False, f"Could not find key: {key}"
                
                if isinstance(expected, list):
                    if not any(sigma_rule_service._compare(actual, x, []) for x in expected):
                        return False, f"{key} ({actual}) not in {expected}"
                else:
                    if not sigma_rule_service._compare(actual, expected, []):
                        return False, f"{key} ({actual}) != {expected}"
            return True, "All fields matched"
        elif isinstance(search, list):
            for item in search:
                matched, details = self._evaluate_sigma_search(item, event)
                if matched:
                    return True, f"Matched item: {details}"
            return False, "No items matched"
        return False, "Invalid search format"
        
    def _evaluate_sigma_condition(self, condition: str, search_results: Dict[str, bool]) -> tuple[bool, str]:
        """Backward compatibility: evaluate sigma condition"""
        condition = condition.strip().lower()
        
        if condition == "1 of them":
            return any(search_results.values()), f"1 of them: {any(search_results.values())}"
        elif condition == "all of them":
            return all(search_results.values()), f"all of them: {all(search_results.values())}"
        elif condition in search_results:
            return search_results[condition], f"{condition}: {search_results[condition]}"
        elif condition.startswith("1 of"):
            parts = condition.split("1 of", 1)
            if len(parts) > 1:
                search_id = parts[1].strip()
                return search_results.get(search_id, False), f"1 of {search_id}: {search_results.get(search_id, False)}"
        elif condition.startswith("all of"):
            parts = condition.split("all of", 1)
            if len(parts) > 1:
                search_id = parts[1].strip()
                return search_results.get(search_id, False), f"all of {search_id}: {search_results.get(search_id, False)}"
        
        return False, f"Unknown condition: {condition}"

    def create_alert_from_match(
        self, 
        db: Session, 
        tenant_id: str, 
        match: DetectionMatchModel, 
        event: SecurityEvent,
        match_result: Dict[str, Any],
        source_id: Optional[str] = None
    ) -> Alert:
        source_id = source_id or self._get_detection_source_id(db, tenant_id)

        db.refresh(match, attribute_names=["rule"])
        existing_alert = db.query(Alert).filter(
            Alert.tenant_id == tenant_id,
            Alert.event_id == event.id,
            Alert.detection_rule_id == match.rule_id,
        ).first()
        if existing_alert:
            if not match.alert_id:
                match.alert_id = existing_alert.id
                db.add(match)
                db.commit()
            return existing_alert

        ocsf_data = self._build_detection_ocsf_data(match.rule, event, match_result)
        alert = Alert(
            tenant_id=tenant_id,
            source_id=source_id,
            detection_rule_id=match.rule_id,
            event_id=event.id,
            ocsf_data=ocsf_data,
            raw_data=event.raw_event or {},
            severity=match.severity,
            status=AlertStatus.OPEN,
            matched_condition=match_result.get('matched_condition'),
            why_matched=match_result.get('why_matched'),
            processed_at=get_utc_now(),
        )
        
        db.add(alert)
        db.commit()
        db.refresh(alert)
        ALERTS_CREATED.labels("detection_engine").inc()
        
        # Link the DetectionMatch to the Alert
        match.alert_id = alert.id
        db.add(match)
        db.commit()
        
        # Broadcast new alert
        broadcast_notification_sync(tenant_id, NotificationType.NEW_ALERT, {
            "id": alert.id,
            "severity": alert.severity.value if hasattr(alert.severity, 'value') else str(alert.severity),
            "status": alert.status.value if hasattr(alert.status, 'value') else str(alert.status),
            "event_id": event.id,
            "created_at": utc_isoformat(alert.created_at)
        })
        
        return alert

    def _build_detection_ocsf_data(
        self,
        rule: DetectionRule,
        event: SecurityEvent,
        match_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        raw_event = event.raw_event or {}
        normalized_event = event.normalized_event or {}
        image = (
            normalized_event.get("image")
            or normalized_event.get("process")
            or raw_event.get("Image")
            or raw_event.get("process")
        )
        command_line = (
            normalized_event.get("command_line")
            or normalized_event.get("command")
            or raw_event.get("CommandLine")
            or raw_event.get("command_line")
        )
        parent_image = normalized_event.get("parent_process") or raw_event.get("ParentImage") or raw_event.get("parent_process")
        class_name, activity_name = self._classify_event(event)
        rule_content = rule.rule_content or {}
        tags = rule_content.get("tags") if isinstance(rule_content, dict) else None
        triage = rule_content.get("triage") if isinstance(rule_content, dict) else {}
        if not isinstance(triage, dict):
            triage = {}
        false_positives = rule_content.get("falsepositives") if isinstance(rule_content, dict) else []
        if not isinstance(false_positives, list):
            false_positives = [str(false_positives)]
        recommendations = triage.get("recommendations") or self._default_recommendations(event)
        confidence = triage.get("confidence", self._default_confidence(rule.severity))
        mitre_techniques = []
        if rule.mitre_technique_id:
            mitre_techniques.append(rule.mitre_technique_id)
        if isinstance(tags, list):
            mitre_techniques.extend(str(tag).upper().replace("ATTACK.", "") for tag in tags if str(tag).lower().startswith("attack."))
        mitre_techniques = list(dict.fromkeys(mitre_techniques))

        message_parts = [f"Detection rule '{rule.name}' matched"]
        if image:
            message_parts.append(f"process image '{image}'")
        if command_line:
            message_parts.append(f"command line '{command_line}'")
        if match_result.get("why_matched"):
            message_parts.append(f"because {match_result['why_matched']}")

        return {
            **normalized_event,
            "class_name": class_name,
            "activity_name": activity_name,
            "category_name": self._category_for_class(class_name),
            "message": "; ".join(message_parts),
            "title": f"{rule.name}: {activity_name}",
            "description": rule.description or f"{rule.name} matched {event.event_type.value if hasattr(event.event_type, 'value') else event.event_type} telemetry.",
            "severity": rule.severity.value if hasattr(rule.severity, "value") else str(rule.severity),
            "confidence": confidence,
            "detection_rule": {
                "id": rule.id,
                "name": rule.name,
                "type": rule.rule_type.value if hasattr(rule.rule_type, "value") else str(rule.rule_type),
                "description": rule.description,
                "mitre_technique_id": rule.mitre_technique_id,
            },
            "process": {
                "name": image,
                "cmd_line": command_line,
                "parent_process": parent_image,
            },
            "actor": {
                "user": normalized_event.get("user") or raw_event.get("User") or raw_event.get("SubjectUserName"),
            },
            "device": {
                "hostname": normalized_event.get("hostname") or raw_event.get("Computer") or raw_event.get("host"),
            },
            "event": {
                "id": event.id,
                "event_id": raw_event.get("EventID") or raw_event.get("event_id"),
                "timestamp": utc_isoformat(event.timestamp),
                "created_at": utc_isoformat(event.created_at),
            },
            "attack_techniques": mitre_techniques,
            "mitre_technique": mitre_techniques[0] if mitre_techniques else None,
            "matched_condition": match_result.get("matched_condition"),
            "why_matched": match_result.get("why_matched"),
            "false_positive_considerations": false_positives,
            "recommendations": recommendations,
        }

    def _classify_event(self, event: SecurityEvent) -> tuple[str, str]:
        event_type = event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
        if event_type == "process":
            return "Process Activity", "Process Created"
        if event_type == "login":
            return "Authentication", "Login Activity"
        if event_type == "network":
            return "Network Activity", "Network Connection"
        if event_type == "file":
            return "File System Activity", "File Activity"
        return "Security Finding", "Detection Rule Match"

    def _category_for_class(self, class_name: str) -> str:
        if class_name in {"Process Activity", "File System Activity"}:
            return "System Activity"
        if class_name == "Authentication":
            return "Identity & Access"
        if class_name == "Network Activity":
            return "Network Activity"
        return "Findings"

    def _default_confidence(self, severity: Severity) -> int:
        if severity == Severity.CRITICAL:
            return 90
        if severity == Severity.HIGH:
            return 80
        if severity == Severity.MEDIUM:
            return 65
        return 50

    def _default_recommendations(self, event: SecurityEvent) -> list[str]:
        event_type = event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
        if event_type == "process":
            return [
                "Review the full process command line and parent process.",
                "Validate the executing user and host context.",
                "Search for related process, network, and file activity around the same time.",
            ]
        if event_type == "login":
            return [
                "Validate source IP, target user, and authentication outcome.",
                "Check for repeated failures followed by a success.",
            ]
        return ["Review related telemetry and validate whether the activity is expected."]


detection_engine = DetectionEngine()
