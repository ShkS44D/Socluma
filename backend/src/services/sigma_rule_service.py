from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import yaml

from src.models.sqlalchemy import EventType, Severity


FIELD_ALIASES: dict[str, list[str]] = {
    "Image": ["process", "process.name", "image", "raw_data.process", "raw_data.Image", "file.path", "file.name"],
    "process": ["process", "process.name", "image", "Image", "raw_data.process", "raw_data.Image", "file.path", "file.name"],
    "CommandLine": ["command", "command_line", "CommandLine", "process.command_line", "raw_data.command_line", "raw_data.CommandLine"],
    "command": ["command", "command_line", "CommandLine", "process.command_line", "raw_data.command_line", "raw_data.CommandLine"],
    "ParentImage": ["parent_process", "parent_process.name", "ParentImage", "raw_data.parent_process", "raw_data.ParentImage"],
    "OriginalFileName": ["original_file_name", "original_filename", "OriginalFileName", "file.original_name", "raw_data.OriginalFileName"],
    "DestinationIp": ["destination_ip", "dst_ip", "destination.ip", "dst_endpoint.ip"],
    "DestinationPort": ["destination_port", "dst_port", "destination.port", "dst_endpoint.port"],
    "SourceIp": ["source_ip", "src_ip", "source.ip", "src_endpoint.ip", "ip"],
    "SourcePort": ["source_port", "src_port", "source.port", "src_endpoint.port", "port"],
    "User": ["user", "user.name", "username", "raw_data.user"],
    "TargetUserName": ["username", "user.name", "user", "target_user.name"],
    "SubjectUserName": ["created_by", "actor.name", "raw_data.created_by"],
    "EventID": ["event_id", "EventID", "event.code", "raw_data.event_id"],
    "Status": ["status", "activity_name", "raw_data.status"],
}

EVENT_TYPE_BY_LOGSOURCE = {
    "process_creation": EventType.PROCESS,
    "process": EventType.PROCESS,
    "network_connection": EventType.NETWORK,
    "network": EventType.NETWORK,
    "authentication": EventType.LOGIN,
    "login": EventType.LOGIN,
}

SEVERITY_BY_LEVEL = {
    "informational": Severity.LOW,
    "info": Severity.LOW,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


@dataclass
class SigmaValidationResult:
    valid: bool
    errors: list[str]
    normalized: dict[str, Any] | None = None


class SigmaRuleService:
    def parse(self, content: str | dict[str, Any]) -> dict[str, Any]:
        if isinstance(content, dict):
            parsed = content
        else:
            parsed = yaml.safe_load(content)
        if not isinstance(parsed, dict):
            raise ValueError("Sigma rule must be a YAML or JSON object")
        return parsed

    def validate(self, content: str | dict[str, Any]) -> SigmaValidationResult:
        errors: list[str] = []
        try:
            parsed = self.parse(content)
        except Exception as exc:
            return SigmaValidationResult(valid=False, errors=[str(exc)])

        detection = parsed.get("detection")
        if not parsed.get("title"):
            errors.append("Sigma rule requires title")
        if not isinstance(detection, dict):
            errors.append("Sigma rule requires detection object")
        elif not detection.get("condition"):
            errors.append("Sigma detection requires condition")
        else:
            search_ids = [key for key in detection.keys() if key not in {"condition", "timeframe"}]
            if not search_ids:
                errors.append("Sigma detection requires at least one selection")

        return SigmaValidationResult(valid=not errors, errors=errors, normalized=parsed if not errors else None)

    def export_yaml(self, rule_content: dict[str, Any]) -> str:
        return yaml.safe_dump(rule_content, sort_keys=False, allow_unicode=False)

    def infer_event_type(self, rule_content: dict[str, Any]) -> EventType | None:
        logsource = rule_content.get("logsource") or {}
        if not isinstance(logsource, dict):
            return None
        for key in ("category", "product", "service"):
            value = logsource.get(key)
            if value and str(value).lower() in EVENT_TYPE_BY_LOGSOURCE:
                return EVENT_TYPE_BY_LOGSOURCE[str(value).lower()]
        return None

    def infer_severity(self, rule_content: dict[str, Any]) -> Severity:
        level = rule_content.get("level")
        return SEVERITY_BY_LEVEL.get(str(level).lower(), Severity.MEDIUM)

    def match(self, rule_content: dict[str, Any], event: dict[str, Any]) -> tuple[bool, str]:
        detection = rule_content.get("detection") or {}
        if not isinstance(detection, dict):
            return False, "Sigma detection is not an object"

        search_ids = [key for key in detection.keys() if key not in {"condition", "timeframe"}]
        search_results: dict[str, bool] = {}
        search_details: list[str] = []
        for search_id in search_ids:
            matched, detail = self._match_search(detection[search_id], event)
            search_results[search_id] = matched
            search_details.append(f"{search_id}: {detail}")

        matched, condition_detail = self._evaluate_condition(str(detection.get("condition", "1 of them")), search_results)
        return matched, f"Condition: {condition_detail} | Searches: {'; '.join(search_details)}"

    def _match_search(self, search: Any, event: dict[str, Any]) -> tuple[bool, str]:
        if isinstance(search, list):
            details: list[str] = []
            for item in search:
                matched, detail = self._match_search(item, event)
                details.append(detail)
                if matched:
                    return True, f"matched list item: {detail}"
            return False, "; ".join(details) or "empty list"

        if not isinstance(search, dict):
            return False, "search is not an object"

        details: list[str] = []
        for field_expr, expected in search.items():
            matched, detail = self._match_field(str(field_expr), expected, event)
            details.append(detail)
            if not matched:
                return False, " | ".join(details)
        return True, " | ".join(details)

    def _match_field(self, field_expr: str, expected: Any, event: dict[str, Any]) -> tuple[bool, str]:
        parts = field_expr.split("|")
        field = parts[0]
        modifiers = [part.lower() for part in parts[1:]]
        actual = self.resolve_field(event, field)
        if actual is None:
            return False, f"{field} not present"

        expected_values = expected if isinstance(expected, list) else [expected]
        for expected_value in expected_values:
            if self._compare(actual, expected_value, modifiers):
                return True, f"{field} matched {expected_value}"
        return False, f"{field} ({actual}) did not match {expected}"

    def _compare(self, actual: Any, expected: Any, modifiers: list[str]) -> bool:
        for actual_value in self._scalar_values(actual):
            actual_text = str(actual_value)
            expected_text = str(expected)
            actual_cmp = actual_text if "case_sensitive" in modifiers else actual_text.lower()
            expected_cmp = expected_text if "case_sensitive" in modifiers else expected_text.lower()
            if "re" in modifiers:
                flags = 0 if "case_sensitive" in modifiers else re.IGNORECASE
                if re.search(expected_text, actual_text, flags=flags):
                    return True
            elif "contains" in modifiers:
                if expected_cmp in actual_cmp:
                    return True
            elif "startswith" in modifiers:
                if actual_cmp.startswith(expected_cmp):
                    return True
            elif "endswith" in modifiers:
                if actual_cmp.endswith(expected_cmp):
                    return True
            elif actual_cmp == expected_cmp:
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

    def _evaluate_condition(self, condition: str, search_results: dict[str, bool]) -> tuple[bool, str]:
        normalized = " ".join(condition.strip().lower().split())
        if normalized == "1 of them":
            return any(search_results.values()), f"1 of them: {any(search_results.values())}"
        if normalized == "all of them":
            return all(search_results.values()), f"all of them: {all(search_results.values())}"
        if normalized in search_results:
            return search_results[normalized], f"{normalized}: {search_results[normalized]}"
        if normalized.startswith("1 of "):
            pattern = normalized.removeprefix("1 of ").rstrip("*")
            values = [value for key, value in search_results.items() if key.lower().startswith(pattern)]
            return any(values), f"1 of {pattern}*: {any(values)}"
        if normalized.startswith("all of "):
            pattern = normalized.removeprefix("all of ").rstrip("*")
            values = [value for key, value in search_results.items() if key.lower().startswith(pattern)]
            return bool(values) and all(values), f"all of {pattern}*: {bool(values) and all(values)}"
        if " and " in normalized:
            parts = [part.strip() for part in normalized.split(" and ")]
            return all(search_results.get(part, False) for part in parts), normalized
        if " or " in normalized:
            parts = [part.strip() for part in normalized.split(" or ")]
            return any(search_results.get(part, False) for part in parts), normalized
        return False, f"Unknown condition: {condition}"

    def resolve_field(self, event: dict[str, Any], field: str) -> Any:
        candidates = [field, field.lower(), self._snake_case(field)]
        candidates.extend(FIELD_ALIASES.get(field, []))
        candidates.extend(FIELD_ALIASES.get(self._canonical_field(field), []))
        for candidate in candidates:
            value = self._get_path(event, candidate)
            if value is not None:
                return value
        return self._find_case_insensitive(event, field)

    def _get_path(self, event: dict[str, Any], path: str) -> Any:
        current: Any = event
        for part in path.split("."):
            if isinstance(current, dict):
                if part in current:
                    current = current[part]
                    continue
                match = next((key for key in current.keys() if key.lower() == part.lower()), None)
                if match is None:
                    return None
                current = current[match]
            else:
                return None
        return current

    def _find_case_insensitive(self, value: Any, field: str) -> Any:
        if isinstance(value, dict):
            for key, nested in value.items():
                if key.lower() == field.lower() or key.lower() == self._snake_case(field):
                    return nested
                found = self._find_case_insensitive(nested, field)
                if found is not None:
                    return found
        if isinstance(value, list):
            for item in value:
                found = self._find_case_insensitive(item, field)
                if found is not None:
                    return found
        return None

    def _canonical_field(self, field: str) -> str:
        return field.split("|", 1)[0]

    def _snake_case(self, value: str) -> str:
        value = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", value)
        return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value).lower()


sigma_rule_service = SigmaRuleService()
