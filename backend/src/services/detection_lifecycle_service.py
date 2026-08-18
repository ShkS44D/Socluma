from __future__ import annotations

import hashlib
import json
import re
import time
import regex as safe_regex_engine
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from src.core.config import get_settings
from src.models.sqlalchemy import (
    DetectionRule, DetectionRuleTestCase, DetectionRuleTestResult,
    DetectionRuleVersion, MitreTechnique, OrganizationMembership, User,
)
from src.services.sigma_rule_service import sigma_rule_service
from src.services.search_query_service import SEARCH_FIELDS
from src.utils.datetime_utils import ensure_utc, get_utc_now


TRANSITIONS = {
    "draft": {"validating"},
    "validating": {"draft", "test_failed", "ready_for_review"},
    "test_failed": {"draft", "validating"},
    "ready_for_review": {"under_review"},
    "under_review": {"changes_requested", "approved"},
    "changes_requested": {"draft"},
    "approved": {"production"},
    "production": {"disabled", "retired"},
    "disabled": {"production", "retired"},
    "retired": {"archived"},
    "archived": set(),
}
IMMUTABLE_STATES = {"approved", "production", "disabled", "retired", "archived"}
RULE_KINDS = {"event_match", "threshold", "frequency", "aggregation", "sequence", "correlation"}
ALLOWED_OPERATORS = {"eq", "neq", "contains", "startswith", "endswith", "in", "gt", "gte", "lt", "lte", "exists", "regex"}


class DetectionLifecycleError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


class DetectionLifecycleService:
    def canonical(self, definition: dict[str, Any]) -> str:
        return json.dumps(definition, sort_keys=True, separators=(",", ":"), default=str)

    def content_hash(self, definition: dict[str, Any]) -> str:
        return hashlib.sha256(self.canonical(definition).encode()).hexdigest()

    def validate(self, definition: dict[str, Any], *, sigma_content: str | None = None, db: Session | None = None):
        settings = get_settings()
        errors, warnings, notices = [], [], []
        encoded = self.canonical(definition).encode()
        if len(encoded) > settings.DETECTION_MAX_RULE_BYTES:
            errors.append({"code": "DETECTION_COMPLEXITY_EXCEEDED", "message": "Rule exceeds size limit"})
        kind = str(definition.get("kind") or "event_match")
        if kind not in RULE_KINDS:
            errors.append({"code": "DETECTION_RULE_INVALID", "message": "Unsupported rule type"})
        conditions = definition.get("conditions") or []
        if kind == "sequence":
            steps = definition.get("steps") or []
            if not 2 <= len(steps) <= settings.DETECTION_MAX_SEQUENCE_STEPS:
                errors.append({"code": "DETECTION_COMPLEXITY_EXCEEDED", "message": "Sequence step count is invalid"})
            conditions = [condition for step in steps for condition in (step.get("conditions") or [])]
        if not conditions and kind not in {"correlation"} and not sigma_content:
            errors.append({"code": "DETECTION_RULE_INVALID", "message": "Rule cannot be empty or always true"})
        if len(conditions) > settings.DETECTION_MAX_BOOLEAN_CLAUSES:
            errors.append({"code": "DETECTION_COMPLEXITY_EXCEEDED", "message": "Too many conditions"})
        for index, item in enumerate(conditions):
            field, operator = item.get("field"), item.get("operator")
            if field not in SEARCH_FIELDS:
                errors.append({"code": "DETECTION_FIELD_UNSUPPORTED", "message": f"Unknown field at condition {index}"})
            if operator not in ALLOWED_OPERATORS:
                errors.append({"code": "DETECTION_RULE_INVALID", "message": f"Unsupported operator at condition {index}"})
            if operator == "regex" and not self.safe_regex(str(item.get("value", ""))):
                errors.append({"code": "DETECTION_REGEX_UNSAFE", "message": f"Unsafe regex at condition {index}"})
            field_meta = SEARCH_FIELDS.get(field)
            if field_meta and operator in {"gt", "gte", "lt", "lte"} and field_meta.data_type not in {"integer", "number", "datetime"}:
                errors.append({"code": "DETECTION_RULE_INVALID", "message": f"Operator is incompatible with {field} at condition {index}"})
        window = int(definition.get("window_seconds") or settings.DETECTION_MIN_WINDOW_SECONDS)
        if kind != "event_match" and not settings.DETECTION_MIN_WINDOW_SECONDS <= window <= settings.DETECTION_MAX_WINDOW_SECONDS:
            errors.append({"code": "DETECTION_RULE_INVALID", "message": "Window is outside configured limits"})
        if len(definition.get("group_by") or []) > settings.DETECTION_MAX_GROUP_BY_FIELDS:
            errors.append({"code": "DETECTION_COMPLEXITY_EXCEEDED", "message": "Too many group-by fields"})
        for field in definition.get("group_by") or []:
            if field not in SEARCH_FIELDS:
                errors.append({"code": "DETECTION_FIELD_UNSUPPORTED", "message": f"Unknown group-by field {field}"})
        if kind in {"threshold", "frequency", "aggregation"} and int(definition.get("threshold") or 0) < 1:
            errors.append({"code": "DETECTION_RULE_INVALID", "message": "Threshold must be at least one"})
        if kind == "aggregation":
            aggregation = definition.get("aggregation") or {}
            if aggregation.get("function") not in {"count", "distinct_count", "min", "max", "sum", "avg"}:
                errors.append({"code": "DETECTION_RULE_INVALID", "message": "Aggregation function is unsupported"})
            if aggregation.get("function") != "count" and aggregation.get("field") not in SEARCH_FIELDS:
                errors.append({"code": "DETECTION_FIELD_UNSUPPORTED", "message": "Aggregation field is unsupported"})
        if kind == "correlation":
            rule_ids = definition.get("rule_ids") or []
            if not 2 <= len(rule_ids) <= settings.DETECTION_MAX_SEQUENCE_STEPS or len(set(rule_ids)) != len(rule_ids):
                errors.append({"code": "DETECTION_RULE_INVALID", "message": "Correlation requires unique contributing rule IDs"})
        if sigma_content:
            sigma = sigma_rule_service.validate(sigma_content)
            errors.extend({"code": "SIGMA_INVALID", "message": item} for item in sigma.errors)
            warnings.extend(
                {"code": "SIGMA_UNSUPPORTED_FEATURE", "message": str(item)}
                for item in getattr(sigma, "warnings", getattr(sigma, "unsupported_features", []))
            )
        techniques = definition.get("mitre_mappings") or []
        if db and techniques:
            known = {x[0] for x in db.query(MitreTechnique.technique_id).filter(MitreTechnique.technique_id.in_(techniques)).all()}
            for technique in set(techniques) - known:
                errors.append({"code": "MITRE_TECHNIQUE_INVALID", "message": f"Unknown technique {technique}"})
        complexity = len(conditions) + len(definition.get("group_by") or []) * 2 + (len(definition.get("steps") or []) * 3)
        if complexity > settings.DETECTION_MAX_COMPLEXITY:
            errors.append({"code": "DETECTION_COMPLEXITY_EXCEEDED", "message": "Estimated rule complexity exceeds the configured limit"})
        return {
            "valid": not errors, "errors": errors, "warnings": warnings, "notices": notices,
            "required_data_sources": definition.get("data_sources") or [],
            "searchable_fields": sorted({x.get("field") for x in conditions if x.get("field")}),
            "estimated_complexity": complexity, "normalized": definition,
            "content_hash": self.content_hash(definition),
        }

    def safe_regex(self, pattern: str) -> bool:
        if not pattern or len(pattern) > get_settings().DETECTION_MAX_REGEX_LENGTH:
            return False
        if re.search(r"(\([^)]*[+*][^)]*\))[+*{]", pattern) or re.search(r"([+*])\1", pattern):
            return False
        if pattern.count("(") > 20:
            return False
        try:
            re.compile(pattern)
        except re.error:
            return False
        return True

    def create_version(self, db: Session, rule: DetectionRule, user_id: str, definition: dict[str, Any], *, original_content=None, summary=None):
        latest = db.query(func.max(DetectionRuleVersion.version_number)).filter(DetectionRuleVersion.rule_id == rule.id).scalar() or 0
        validation = self.validate(definition, sigma_content=original_content if rule.rule_type.value == "sigma" else None, db=db)
        version = DetectionRuleVersion(
            tenant_id=rule.tenant_id, rule_id=rule.id, version_number=latest + 1,
            normalized_definition=definition, original_content=original_content,
            rule_language="sigma" if rule.rule_type.value == "sigma" else "structured",
            change_summary=summary, created_by_id=user_id, validation_result=validation,
            content_hash=validation["content_hash"], previous_version_id=rule.current_version_id,
        )
        db.add(version); db.flush()
        rule.current_version_id = version.id
        rule.lifecycle_status = "draft"
        rule.enabled = False
        return version

    def transition(self, db: Session, rule: DetectionRule, version: DetectionRuleVersion, target: str, actor: User, *, comment=None):
        if version.tenant_id != actor.tenant_id or rule.tenant_id != actor.tenant_id:
            raise DetectionLifecycleError("DETECTION_RULE_NOT_FOUND", "Rule not found")
        current = version.lifecycle_status
        if target not in TRANSITIONS.get(current, set()):
            raise DetectionLifecycleError("DETECTION_STATE_INVALID", f"Cannot transition {current} to {target}")
        now = get_utc_now()
        if target == "ready_for_review":
            validation = self.validate(version.normalized_definition, sigma_content=version.original_content if version.rule_language == "sigma" else None, db=db)
            version.validation_result = validation
            if not validation["valid"]:
                raise DetectionLifecycleError("DETECTION_VALIDATION_FAILED", "Rule validation failed")
            if version.test_result.get("status") != "passed":
                raise DetectionLifecycleError("DETECTION_TEST_FAILED", "Passing version tests are required")
        if target == "under_review":
            if not version.reviewer_id:
                raise DetectionLifecycleError("DETECTION_RULE_INVALID", "An active reviewer must be assigned")
            self.assert_member(db, rule.tenant_id, version.reviewer_id)
            version.review_requested_at = now
        if target == "changes_requested" and not (comment or "").strip():
            raise DetectionLifecycleError("DETECTION_RULE_INVALID", "Requested changes require a reason")
        if target == "approved":
            if get_settings().DETECTION_REQUIRE_TWO_PERSON_APPROVAL and version.created_by_id == actor.id:
                raise DetectionLifecycleError("DETECTION_APPROVAL_INVALID", "Author cannot approve this version")
            version.approver_id, version.review_completed_at = actor.id, now
            version.approval_expires_at = now + timedelta(hours=get_settings().DETECTION_REVIEW_EXPIRE_HOURS)
            version.approval_comment = (comment or "")[:2000]
        if target == "production":
            if not version.approval_expires_at or ensure_utc(version.approval_expires_at) < now:
                raise DetectionLifecycleError("DETECTION_APPROVAL_REQUIRED", "Version approval is missing or expired")
            if rule.production_version_id and rule.production_version_id != version.id:
                previous = db.query(DetectionRuleVersion).filter(
                    DetectionRuleVersion.id == rule.production_version_id,
                    DetectionRuleVersion.tenant_id == rule.tenant_id,
                ).first()
                if previous and previous.lifecycle_status == "production":
                    previous.lifecycle_status = "disabled"
            rule.production_version_id, rule.enabled = version.id, True
            version.published_at = now
        if target == "disabled":
            rule.enabled = False
        if target == "retired":
            rule.enabled, rule.retired_at = False, now
        version.lifecycle_status = target
        rule.lifecycle_status = target
        db.flush()
        return version

    def assert_member(self, db: Session, tenant_id: str, user_id: str):
        member = db.query(OrganizationMembership).join(User, User.id == OrganizationMembership.user_id).filter(
            OrganizationMembership.tenant_id == tenant_id, OrganizationMembership.user_id == user_id,
            OrganizationMembership.is_active == True, User.is_active == True,
        ).first()
        if not member:
            raise DetectionLifecycleError("DETECTION_RULE_INVALID", "Owner or reviewer is not an active organization member")
        return member

    def evaluate_events(self, definition: dict[str, Any], events: list[Any]) -> dict[str, Any]:
        """Deterministic dry-run evaluator. It never creates detections or alerts."""
        started = time.perf_counter()
        kind = definition.get("kind", "event_match")
        ordered_events = sorted(events, key=lambda event: getattr(event, "timestamp", datetime.min))
        matched = [event for event in ordered_events if self._event_matches(definition.get("conditions") or [], event)]
        threshold = int(definition.get("threshold") or 1)
        groups: dict[str, list[Any]] = {}
        group_fields = definition.get("group_by") or []
        for event in matched:
            key = "|".join(str(self._field(event, field) or "")[:128] for field in group_fields) or "all"
            groups.setdefault(key, []).append(event)
        aggregates = {}
        if kind in {"threshold", "frequency"}:
            triggering = {key: rows for key, rows in groups.items() if len(rows) >= threshold}
        elif kind == "aggregation":
            aggregation = definition.get("aggregation") or {"function": "count"}
            function, field = aggregation.get("function", "count"), aggregation.get("field")
            triggering = {}
            for key, rows in groups.items():
                values = [self._field(row, field) for row in rows] if field else []
                values = [value for value in values if value is not None]
                if function == "distinct_count":
                    value = len({str(item) for item in values})
                elif function == "min":
                    value = min(values) if values else 0
                elif function == "max":
                    value = max(values) if values else 0
                elif function == "sum":
                    value = sum(values) if values else 0
                elif function == "avg":
                    value = sum(values) / len(values) if values else 0
                else:
                    value = len(rows)
                aggregates[key] = value
                if value >= threshold:
                    triggering[key] = rows
        elif kind == "sequence":
            triggering = self._sequence_matches(definition, ordered_events)
        elif kind == "correlation":
            required = set(definition.get("rule_ids") or [])
            contributing = [
                event for event in ordered_events
                if str(getattr(event, "rule_id", "") or (event.get("rule_id") if isinstance(event, dict) else "")) in required
            ]
            present = {
                str(getattr(event, "rule_id", "") or (event.get("rule_id") if isinstance(event, dict) else ""))
                for event in contributing
            }
            triggering = {"correlation": contributing} if required and required.issubset(present) else {}
        else:
            triggering = groups
        examples = [
            {
                "event_id": getattr(event, "id", None) or (event.get("id") if isinstance(event, dict) else None),
                "timestamp": getattr(event, "timestamp", None) or (event.get("timestamp") if isinstance(event, dict) else None),
                "source": getattr(event, "source", None) or (event.get("source") if isinstance(event, dict) else None),
                "severity": (
                    getattr(event, "severity").value
                    if hasattr(getattr(event, "severity", None), "value")
                    else str(getattr(event, "severity", None) or (event.get("severity") if isinstance(event, dict) else ""))
                ),
            }
            for rows in triggering.values() for event in rows[:5]
        ][:25]
        return {
            "events_scanned": len(events), "matches": sum(len(x) for x in triggering.values()),
            "distinct_grouping_keys": len(triggering), "estimated_alert_count": len(triggering),
            "example_matches": examples, "groups": {key: len(rows) for key, rows in triggering.items()},
            "aggregate_values": aggregates,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "simulated": True, "truncated_examples": sum(len(x) for x in triggering.values()) > len(examples),
        }

    def _event_matches(self, conditions, event):
        for item in conditions:
            actual, expected, operator = self._field(event, item.get("field")), item.get("value"), item.get("operator")
            if operator == "exists":
                ok = actual is not None
            elif operator == "regex":
                settings = get_settings()
                candidate = str(actual or "")[: settings.DETECTION_REGEX_MAX_INPUT_BYTES]
                try:
                    ok = bool(
                        safe_regex_engine.search(
                            str(expected),
                            candidate,
                            timeout=settings.DETECTION_REGEX_TIMEOUT_MS / 1000,
                        )
                    ) if self.safe_regex(str(expected)) else False
                except TimeoutError:
                    ok = False
            elif operator == "contains":
                ok = str(expected).casefold() in str(actual or "").casefold()
            elif operator == "startswith":
                ok = str(actual or "").casefold().startswith(str(expected).casefold())
            elif operator == "endswith":
                ok = str(actual or "").casefold().endswith(str(expected).casefold())
            elif operator == "in":
                ok = actual in (expected or [])
            elif operator in {"gt", "gte", "lt", "lte"}:
                try:
                    ok = {"gt": actual > expected, "gte": actual >= expected, "lt": actual < expected, "lte": actual <= expected}[operator]
                except TypeError:
                    ok = False
            else:
                ok = actual != expected if operator == "neq" else actual == expected
            if not ok:
                return False
        return bool(conditions)

    def _sequence_matches(self, definition: dict[str, Any], events: list[Any]) -> dict[str, list[Any]]:
        steps = definition.get("steps") or []
        if not steps:
            return {}
        group_fields = definition.get("group_by") or []
        window_seconds = int(definition.get("window_seconds") or get_settings().DETECTION_MIN_WINDOW_SECONDS)
        buckets: dict[str, list[Any]] = {}
        for event in events:
            key = "|".join(str(self._field(event, field) or "")[:128] for field in group_fields) or "all"
            buckets.setdefault(key, []).append(event)
        results: dict[str, list[Any]] = {}
        for key, rows in buckets.items():
            matched_rows, step_index, started_at = [], 0, None
            for event in rows:
                if self._event_matches(steps[step_index].get("conditions") or [], event):
                    timestamp = getattr(event, "timestamp", None)
                    if started_at is None:
                        started_at = timestamp
                    if started_at and timestamp and (timestamp - started_at).total_seconds() > window_seconds:
                        matched_rows, step_index, started_at = [], 0, None
                        continue
                    matched_rows.append(event)
                    step_index += 1
                    if step_index == len(steps):
                        results[key] = matched_rows
                        break
        return results

    @staticmethod
    def _field(event, public_name):
        field = SEARCH_FIELDS.get(public_name)
        if not field:
            return None
        current: Any = event
        for part in field.path.split("."):
            if isinstance(current, dict):
                current = current.get(part)
            else:
                current = getattr(current, part, None)
        return current.value if hasattr(current, "value") else current


detection_lifecycle_service = DetectionLifecycleService()
