from __future__ import annotations
from typing import Optional, Dict, Any, List
from datetime import timedelta
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import or_
from dataclasses import dataclass
import logging
import yaml

from src.models.sqlalchemy import (
    DetectionRule, RuleType, Severity, SecurityEvent, Alert, AlertSource,
    DetectionMatch as DetectionMatchModel, DetectionRuleVersion, AlertStatus,
    DetectionException, DetectionMaintenanceWindow, DetectionSuppressionPolicy,
)
from src.models.pydantic import AlertCreate
from src.services.incident_service import incident_service
from src.services.sigma_rule_service import sigma_rule_service
from src.services.detection_lifecycle_service import detection_lifecycle_service
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
            DetectionRule.enabled == True,
        ).all()
        # Compatibility for rules created by older releases or fixtures before
        # migration 1800. Persist an explicit immutable production version before
        # evaluating so every new match still has exact provenance.
        for rule in enabled_rules:
            if rule.production_version_id:
                continue
            definition = rule.rule_content or {
                "kind": "event_match",
                "conditions": [
                    {"field": key, "operator": "eq", "value": value}
                    for key, value in (rule.condition or {}).items()
                ],
            }
            version = detection_lifecycle_service.create_version(
                db,
                rule,
                rule.created_by,
                definition,
                original_content=rule.sigma_rule,
                summary="Legacy rule compatibility migration",
            )
            version.lifecycle_status = "production"
            version.test_result = {"status": "passed", "source": "legacy_compatibility"}
            version.published_at = get_utc_now()
            rule.current_version_id = version.id
            rule.production_version_id = version.id
            rule.lifecycle_status = "production"
            rule.enabled = True
        if enabled_rules:
            db.flush()
        versions = {
            version.id: version
            for version in db.query(DetectionRuleVersion).filter(
                DetectionRuleVersion.tenant_id == tenant_id,
                DetectionRuleVersion.id.in_([rule.production_version_id for rule in enabled_rules]),
            ).all()
        } if enabled_rules else {}
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
                
            version = versions.get(rule.production_version_id)
            match_result = self._match_version(db, tenant_id, rule, version, event)
            logger.info(
                "Detection rule evaluated",
                extra={
                    "tenant_id": tenant_id,
                    "event_id": event.id,
                    "collector_id": (event.normalized_event or {}).get("collector_id"),
                    "rule_id": rule.id,
                    "rule_version": utc_isoformat(rule.updated_at or rule.created_at),
                    "match_result": bool(match_result["matched"]),
                    "failure_reason": None if match_result["matched"] else "logsource, field selection, or condition did not match",
                },
            )
            if match_result['matched']:
                version = versions.get(rule.production_version_id)
                control = self._evaluate_controls(db, tenant_id, rule, event)
                match = DetectionMatchModel(
                    tenant_id=tenant_id,
                    event_id=event.id,
                    rule_id=rule.id,
                    matched=True,
                    severity=rule.severity,
                    rule_version_id=version.id if version else None,
                    rule_content_hash=version.content_hash if version else None,
                    detection_type=rule.detection_kind,
                    contributing_event_ids=match_result.get("contributing_event_ids") or [event.id],
                    matched_conditions=[match_result.get("matched_condition")],
                    exceptions_evaluated=control["exceptions"],
                    suppression_result=control["suppression"],
                    confidence=rule.confidence,
                    risk_contribution=rule.risk_contribution,
                    mitre_mappings=rule.mitre_mappings or ([rule.mitre_technique_id] if rule.mitre_technique_id else []),
                    data_source_provenance={"collector_id": event.collector_id, "data_source_id": event.data_source_id,
                                            "parser_version": event.parser_version, "schema_version": event.schema_version},
                    explanation={"why_matched": match_result.get("why_matched"), "controls": control},
                )
                rule.last_triggered_at = get_utc_now()
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
            if (match.suppression_result or {}).get("suppressed"):
                continue
            
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
            "event_data": raw_event.get("EventData") or raw_event.get("event_data") or normalized_event.get("event_data") or {},
            "source": event.source,
            "event_type": event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type),
        }
        
        result = {'matched': False, 'matched_condition': None, 'why_matched': None}
        
        try:
            if rule.condition and isinstance(rule.condition, dict):
                matched, details = self._evaluate_condition(rule.condition, combined_event)
                if matched:
                    return {"matched": True, "matched_condition": str(rule.condition), "why_matched": details}
            if rule.query:
                matched, details = self._match_query(rule.query, combined_event)
                if matched:
                    return {"matched": True, "matched_condition": rule.query, "why_matched": details}
                
            if rule.rule_type == RuleType.SIGMA and rule.rule_content:
                explanation = sigma_rule_service.explain(rule.rule_content, combined_event)
                matched, details = explanation["matched"], explanation["summary"]
                if matched:
                    return {"matched": True, "matched_condition": str(rule.rule_content.get("detection", {})),
                            "why_matched": details, "match_explanation": explanation}

            if rule.sigma_rule:
                matched, details = self._match_sigma_rule(rule.sigma_rule, combined_event)
                if matched:
                    return {"matched": True, "matched_condition": rule.sigma_rule, "why_matched": details}
            
            # If we have rule_content, check that directly too
            if rule.rule_content:
                # Treat rule_content as a sigma rule (since that's what it is)
                # Convert to YAML and pass to _match_sigma_rule, or evaluate directly
                # Let's just use the detection part of rule_content directly
                if 'detection' in rule.rule_content:
                    matched, details = sigma_rule_service.match(rule.rule_content, combined_event)
                    if matched:
                        return {"matched": True, "matched_condition": str(rule.rule_content["detection"]), "why_matched": details}
        except Exception:
            logger.exception("Exception matching detection rule", extra={"rule_id": rule.id, "rule_name": rule.name, "event_id": event.id})
        return result

    def _match_version(
        self,
        db: Session,
        tenant_id: str,
        rule: DetectionRule,
        version: DetectionRuleVersion | None,
        event: SecurityEvent,
    ) -> Dict[str, Any]:
        if not version:
            return self._match_rule(rule, event)
        definition = version.normalized_definition or {}
        if version.rule_language == "sigma" and definition.get("detection"):
            combined = {
                **(event.raw_event or {}), **(event.normalized_event or {}),
                "raw_data": event.raw_event or {}, "normalized_event": event.normalized_event or {},
                "event_data": (event.raw_event or {}).get("EventData") or {},
                "source": event.source,
                "event_type": event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type),
            }
            explanation = sigma_rule_service.explain(definition, combined)
            return {"matched": bool(explanation["matched"]), "matched_condition": str(definition.get("detection", {})),
                    "why_matched": explanation["summary"], "match_explanation": explanation}
        kind = definition.get("kind", "event_match")
        if kind != "event_match":
            window = int(definition.get("window_seconds") or settings.DETECTION_MIN_WINDOW_SECONDS)
            start = event.timestamp - timedelta(seconds=window)
            if kind == "correlation":
                required = definition.get("rule_ids") or []
                historical = db.query(DetectionMatchModel).filter(
                    DetectionMatchModel.tenant_id == tenant_id,
                    DetectionMatchModel.rule_id.in_(required),
                    DetectionMatchModel.triggered_at >= start,
                    DetectionMatchModel.triggered_at <= event.timestamp,
                ).order_by(DetectionMatchModel.triggered_at).limit(
                    settings.DETECTION_MAX_AGGREGATION_CARDINALITY
                ).all()
            else:
                historical = db.query(SecurityEvent).filter(
                    SecurityEvent.tenant_id == tenant_id,
                    SecurityEvent.timestamp >= start,
                    SecurityEvent.timestamp <= event.timestamp,
                ).order_by(SecurityEvent.timestamp).limit(
                    settings.DETECTION_MAX_AGGREGATION_CARDINALITY
                ).all()
            result = detection_lifecycle_service.evaluate_events(definition, historical)
            matched = result["estimated_alert_count"] > 0
            contributing = [
                item.get("event_id")
                for item in result.get("example_matches", [])
                if item.get("event_id")
            ]
            return {
                "matched": matched,
                "matched_condition": str(definition),
                "why_matched": (
                    f"{kind} rule matched {result['matches']} contributing records"
                    if matched else f"{kind} criteria not met"
                ),
                "contributing_event_ids": contributing or [event.id],
                "evaluation": result,
            }
        matched = detection_lifecycle_service._event_matches(definition.get("conditions") or [], event)
        return {"matched": matched, "matched_condition": str(definition.get("conditions") or []),
                "why_matched": "Versioned structured conditions matched" if matched else "Versioned structured conditions did not match"}

    def _evaluate_controls(
        self,
        db: Session,
        tenant_id: str,
        rule: DetectionRule,
        event: SecurityEvent,
    ) -> dict[str, Any]:
        now = get_utc_now()
        evaluated = []
        suppressed, reason = False, None
        exceptions = db.query(DetectionException).filter(
            DetectionException.tenant_id == tenant_id,
            DetectionException.status == "active",
            DetectionException.expires_at > now,
            or_(DetectionException.rule_id.is_(None), DetectionException.rule_id == rule.id),
        ).all()
        for exception in exceptions:
            criteria = exception.criteria or {}
            condition = criteria if "field" in criteria else None
            matched = bool(
                condition and detection_lifecycle_service._event_matches([condition], event)
            )
            evaluated.append({"exception_id": exception.id, "matched": matched})
            if matched:
                suppressed, reason = True, "exception"
        windows = db.query(DetectionMaintenanceWindow).filter(
            DetectionMaintenanceWindow.tenant_id == tenant_id,
            DetectionMaintenanceWindow.status.in_(["scheduled", "active"]),
            DetectionMaintenanceWindow.starts_at <= now,
            DetectionMaintenanceWindow.ends_at >= now,
        ).all()
        for window in windows:
            scope = window.scope or {}
            if not scope.get("rule_ids") or rule.id in scope.get("rule_ids", []):
                suppressed, reason = True, "maintenance_window"
        policy = db.query(DetectionSuppressionPolicy).filter_by(
            tenant_id=tenant_id, rule_id=rule.id, enabled=True
        ).first()
        if policy and not suppressed:
            since = now - timedelta(seconds=policy.window_seconds)
            count = db.query(DetectionMatchModel).filter(
                DetectionMatchModel.tenant_id == tenant_id,
                DetectionMatchModel.rule_id == rule.id,
                DetectionMatchModel.triggered_at >= since,
            ).count()
            if count >= policy.maximum_alerts:
                suppressed, reason = True, "rate_policy"
        return {
            "exceptions": evaluated,
            "suppression": {
                "suppressed": suppressed,
                "reason": reason,
                "match_preserved": True,
            },
        }

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
        logger.info(
            "Detection alert created",
            extra={
                "tenant_id": tenant_id,
                "event_id": event.id,
                "collector_id": (event.normalized_event or {}).get("collector_id"),
                "rule_id": match.rule_id,
                "rule_version": utc_isoformat(match.rule.updated_at or match.rule.created_at),
                "alert_id": alert.id,
                "incident_id": alert.incident_id,
                "match_result": True,
            },
        )
        
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
                "version": utc_isoformat(rule.updated_at or rule.created_at),
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
            "match_explanation": match_result.get("match_explanation"),
            "pending_correlation": {
                "status": "pending",
                "reason": "This alert remains pending until qualifying related alerts satisfy deterministic correlation requirements.",
                "minimum_related_alerts": 2,
                "correlation_keys": {
                    key: normalized_event.get(key) or raw_event.get(key)
                    for key in (
                        "hostname", "agent_id", "rule_id", "source_ip", "destination_ip",
                        "source_host", "destination_host", "user",
                    )
                    if normalized_event.get(key) is not None or raw_event.get(key) is not None
                },
                "correlation_window_minutes": settings.CORRELATION_WINDOW_MINUTES,
            },
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
