from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any

import yaml

from src.models.sqlalchemy import EventType, Severity


FIELD_ALIASES: dict[str, list[str]] = {
    "EventID": ["EventID", "event_id", "event.code", "winlog.event_id", "raw_data.EventID", "raw_data.event_id", "event_data.EventID", "raw_data.EventData.EventID"],
    "ClassName": ["ClassName", "class_name", "device_class_name", "raw_data.ClassName", "event_data.ClassName", "raw_data.EventData.ClassName"],
    "DeviceId": ["DeviceId", "device_id", "raw_data.DeviceId", "event_data.DeviceId", "raw_data.EventData.DeviceId"],
    "NewProcessName": ["NewProcessName", "process_path", "process.executable", "raw_data.NewProcessName", "event_data.NewProcessName"],
    "ProviderName": ["ProviderName", "provider_name", "event.provider", "winlog.provider_name", "raw_data.ProviderName"],
    "Channel": ["Channel", "channel", "log_name", "winlog.channel", "raw_data.Channel"],
    "Image": ["Image", "image", "process", "process.name", "raw_data.Image", "raw_data.process", "file.path", "file.name"],
    "process": ["process", "process.name", "image", "Image", "raw_data.process", "raw_data.Image", "file.path", "file.name"],
    "CommandLine": ["CommandLine", "command", "command_line", "process.command_line", "raw_data.CommandLine", "raw_data.command_line"],
    "command": ["command", "command_line", "CommandLine", "process.command_line", "raw_data.command_line", "raw_data.CommandLine"],
    "ParentImage": ["ParentImage", "parent_process", "parent_process.name", "raw_data.ParentImage", "raw_data.parent_process"],
    "OriginalFileName": ["OriginalFileName", "original_file_name", "original_filename", "file.original_name", "raw_data.OriginalFileName"],
    "DestinationIp": ["DestinationIp", "destination_ip", "dst_ip", "destination.ip", "dst_endpoint.ip"],
    "DestinationPort": ["DestinationPort", "destination_port", "dst_port", "destination.port", "dst_endpoint.port"],
    "SourceIp": ["SourceIp", "source_ip", "src_ip", "source.ip", "src_endpoint.ip", "ip"],
    "SourcePort": ["SourcePort", "source_port", "src_port", "source.port", "src_endpoint.port", "port"],
    "User": ["User", "user", "user.name", "username", "raw_data.user"],
    "TargetUserName": ["TargetUserName", "username", "user.name", "user", "target_user.name"],
    "SubjectUserName": ["SubjectUserName", "subject_user_name", "created_by", "actor.name", "raw_data.SubjectUserName"],
    "Status": ["Status", "status", "activity_name", "raw_data.status"],
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
    "informational": Severity.LOW, "info": Severity.LOW, "low": Severity.LOW,
    "medium": Severity.MEDIUM, "high": Severity.HIGH, "critical": Severity.CRITICAL,
}
SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "case_sensitive"}
SUPPORTED_LOGSOURCE_KEYS = {"product", "service", "category", "definition"}


@dataclass
class SigmaValidationResult:
    valid: bool
    errors: list[str]
    normalized: dict[str, Any] | None = None


class SigmaRuleService:
    def parse(self, content: str | dict[str, Any]) -> dict[str, Any]:
        parsed = content if isinstance(content, dict) else yaml.safe_load(content)
        if not isinstance(parsed, dict):
            raise ValueError("Sigma rule must be a YAML or JSON object")
        return parsed

    def validate(self, content: str | dict[str, Any]) -> SigmaValidationResult:
        errors: list[str] = []
        try:
            parsed = dict(self.parse(content))
        except Exception as exc:
            return SigmaValidationResult(False, [str(exc)])
        if not parsed.get("title"):
            errors.append("Sigma rule requires title")
        logsource = parsed.get("logsource")
        if not isinstance(logsource, dict) or not any(logsource.get(key) for key in ("product", "service", "category")):
            errors.append("Sigma rule requires logsource product, service, or category")
        elif unsupported := set(logsource) - SUPPORTED_LOGSOURCE_KEYS:
            errors.append(f"Unsupported logsource keys: {', '.join(sorted(unsupported))}")
        detection = parsed.get("detection")
        if not isinstance(detection, dict):
            errors.append("Sigma rule requires detection object")
        else:
            condition = detection.get("condition")
            selections = {key: value for key, value in detection.items() if key not in {"condition", "timeframe"}}
            if not selections:
                errors.append("Sigma detection requires at least one selection")
            if not condition:
                errors.append("Sigma detection requires condition")
            for selection_name, search in selections.items():
                self._validate_search(selection_name, search, errors)
            if condition:
                try:
                    self._evaluate_condition(str(condition), {key: False for key in selections})
                except ValueError as exc:
                    errors.append(str(exc))
        if "id" not in parsed:
            parsed["id"] = str(uuid.uuid4())
        elif not isinstance(parsed["id"], str):
            errors.append("Sigma rule id must be a string")
        return SigmaValidationResult(not errors, errors, parsed if not errors else None)

    def _validate_search(self, name: str, search: Any, errors: list[str]) -> None:
        if isinstance(search, list):
            for item in search:
                self._validate_search(name, item, errors)
            return
        if not isinstance(search, dict):
            errors.append(f"Selection '{name}' must be an object or list of objects")
            return
        for field_expr in search:
            parts = str(field_expr).split("|")
            modifiers = {part.lower() for part in parts[1:]}
            unsupported = modifiers - SUPPORTED_MODIFIERS
            if unsupported:
                errors.append(
                    f"Selection '{name}' field '{field_expr}' uses unsupported modifier(s): "
                    f"{', '.join(sorted(unsupported))}"
                )

    def export_yaml(self, rule_content: dict[str, Any]) -> str:
        return yaml.safe_dump(rule_content, sort_keys=False, allow_unicode=False)

    def infer_event_type(self, rule_content: dict[str, Any]) -> EventType | None:
        logsource = rule_content.get("logsource") or {}
        for key in ("category", "service", "product"):
            value = str(logsource.get(key, "")).lower()
            if value in EVENT_TYPE_BY_LOGSOURCE:
                return EVENT_TYPE_BY_LOGSOURCE[value]
        return None

    def infer_severity(self, rule_content: dict[str, Any]) -> Severity:
        return SEVERITY_BY_LEVEL.get(str(rule_content.get("level")).lower(), Severity.MEDIUM)

    def match(self, rule_content: dict[str, Any], event: dict[str, Any]) -> tuple[bool, str]:
        explanation = self.explain(rule_content, event)
        return explanation["matched"], explanation["summary"]

    def explain(self, rule_content: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
        logsource_result = self._match_logsource(rule_content.get("logsource") or {}, event)
        detection = rule_content.get("detection") or {}
        selections: dict[str, bool] = {}
        selection_details: list[dict[str, Any]] = []
        for name, search in detection.items():
            if name in {"condition", "timeframe"}:
                continue
            matched, fields = self._match_search(search, event)
            selections[name] = matched
            selection_details.append({"name": name, "matched": matched, "fields": fields})
        try:
            condition_matched, condition_detail = self._evaluate_condition(
                str(detection.get("condition", "")), selections
            )
        except ValueError as exc:
            condition_matched, condition_detail = False, str(exc)
        matched = bool(logsource_result["matched"] and condition_matched)
        summary = (
            f"Logsource: {logsource_result['summary']} | Condition: {condition_detail} | "
            + "; ".join(
                f"{item['name']}: {'matched' if item['matched'] else 'not matched'}"
                for item in selection_details
            )
        )
        return {
            "matched": matched,
            "logsource": logsource_result,
            "selections": selection_details,
            "condition": {
                "expression": detection.get("condition"),
                "matched": condition_matched,
                "details": condition_detail,
            },
            "summary": summary,
        }

    def _match_logsource(self, logsource: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
        checks = []
        for key in ("product", "service", "category"):
            expected = logsource.get(key)
            if expected is None:
                continue
            actual, source = self._resolve_logsource_value(key, event)
            matched = actual is not None and self._logsource_values_equal(key, expected, actual)
            checks.append({"field": key, "expected": expected, "actual": actual, "source": source, "matched": matched})
        matched = bool(checks) and all(check["matched"] for check in checks)
        summary = "; ".join(
            f"{check['field']}={check['expected']} "
            f"{'matched' if check['matched'] else 'did not match'}"
            + (f" from {check['source']}={check['actual']}" if check["source"] else "")
            for check in checks
        )
        return {"matched": matched, "checks": checks, "summary": summary or "no supported logsource fields"}

    def _logsource_values_equal(self, key: str, expected: Any, actual: Any) -> bool:
        expected_text, actual_text = str(expected).lower(), str(actual).lower()
        if key != "category":
            return expected_text == actual_text
        aliases = {
            "process": "process_creation",
            "process_creation": "process_creation",
            "login": "authentication",
            "authentication": "authentication",
            "network": "network_connection",
            "network_connection": "network_connection",
        }
        return aliases.get(expected_text, expected_text) == aliases.get(actual_text, actual_text)

    def _resolve_logsource_value(self, key: str, event: dict[str, Any]) -> tuple[Any, str | None]:
        if key == "product":
            paths = ("product", "operating_system", "platform", "normalized_event.product",
                     "normalized_event.operating_system", "normalized_event.platform")
            value, path = self._first_path(event, paths)
            if value is None and str(event.get("source", "")).lower() == "windows-agent":
                return "windows", "source"
            return value, path
        if key == "service":
            paths = ("service", "channel", "log_name", "event_log", "winlog.channel",
                     "raw_data.Channel", "raw_data.channel", "normalized_event.channel",
                     "normalized_event.log_name")
            value, path = self._first_path(event, paths)
            if value is None:
                provider, provider_path = self._first_path(
                    event, ("ProviderName", "provider_name", "raw_data.ProviderName")
                )
                if str(provider).lower() == "microsoft-windows-security-auditing":
                    return "security", provider_path
            return value, path
        value, path = self._first_path(event, ("category", "normalized_event.category"))
        if value is not None:
            return value, path
        event_type, event_type_path = self._first_path(event, ("event_type",))
        category_aliases = {
            "process": "process_creation",
            "network": "network_connection",
            "login": "authentication",
        }
        return category_aliases.get(str(event_type).lower(), event_type), event_type_path

    def _match_search(self, search: Any, event: dict[str, Any]) -> tuple[bool, list[dict[str, Any]]]:
        if isinstance(search, list):
            alternatives = [self._match_search(item, event) for item in search]
            return any(item[0] for item in alternatives), [
                field for _, fields in alternatives for field in fields
            ]
        if not isinstance(search, dict):
            return False, [{"error": "search is not an object", "matched": False}]
        details = []
        matched = True
        for field_expr, expected in search.items():
            parts = str(field_expr).split("|")
            field, modifiers = parts[0], [part.lower() for part in parts[1:]]
            actual, resolved_from = self.resolve_field_with_source(event, field)
            values = expected if isinstance(expected, list) else [expected]
            if "all" in modifiers:
                field_matched = actual is not None and all(
                    self._compare(actual, value, modifiers) for value in values
                )
            else:
                field_matched = actual is not None and any(
                    self._compare(actual, value, modifiers) for value in values
                )
            details.append({
                "field": field,
                "expression": field_expr,
                "resolved_from": resolved_from,
                "actual": actual,
                "expected": expected,
                "matched": field_matched,
            })
            matched = matched and field_matched
        return matched, details

    def _compare(self, actual: Any, expected: Any, modifiers: list[str]) -> bool:
        comparison_modifiers = set(modifiers) - {"all"}
        for actual_value in self._scalar_values(actual):
            actual_text, expected_text = str(actual_value), str(expected)
            actual_cmp = actual_text if "case_sensitive" in comparison_modifiers else actual_text.lower()
            expected_cmp = expected_text if "case_sensitive" in comparison_modifiers else expected_text.lower()
            if "re" in comparison_modifiers:
                flags = 0 if "case_sensitive" in comparison_modifiers else re.IGNORECASE
                if re.search(expected_text, actual_text, flags=flags):
                    return True
            elif "contains" in comparison_modifiers and expected_cmp in actual_cmp:
                return True
            elif "startswith" in comparison_modifiers and actual_cmp.startswith(expected_cmp):
                return True
            elif "endswith" in comparison_modifiers and actual_cmp.endswith(expected_cmp):
                return True
            elif not comparison_modifiers and actual_cmp == expected_cmp:
                return True
        return False

    def _evaluate_condition(self, condition: str, selections: dict[str, bool]) -> tuple[bool, str]:
        normalized = " ".join(condition.strip().lower().split())
        if not normalized:
            raise ValueError("Sigma condition is empty")
        values = {key.lower(): value for key, value in selections.items()}
        counter = 0

        def replace_quantifier(match: re.Match[str]) -> str:
            nonlocal counter
            amount, pattern = match.group(1), match.group(2)
            if pattern == "them":
                selected = list(values.values())
            else:
                prefix = pattern.removesuffix("*")
                selected = [value for key, value in values.items() if key.startswith(prefix)]
            key = f"__quant{counter}"
            counter += 1
            values[key] = (bool(selected) and all(selected)) if amount == "all" else any(selected)
            return key

        normalized = re.sub(
            r"\b(1|all)\s+of\s+([a-z0-9_]+\*?|them)(?=\s|\)|$)",
            replace_quantifier,
            normalized,
        )
        tokens = re.findall(r"\(|\)|\b(?:and|or|not)\b|[a-z0-9_*]+", normalized)
        if "".join(tokens).replace("and", "").replace("or", "").replace("not", "") == "" or not tokens:
            raise ValueError(f"Unsupported Sigma condition: {condition}")
        position = 0

        def parse_or() -> bool:
            nonlocal position
            value = parse_and()
            while position < len(tokens) and tokens[position] == "or":
                position += 1
                rhs = parse_and()
                value = value or rhs
            return value

        def parse_and() -> bool:
            nonlocal position
            value = parse_not()
            while position < len(tokens) and tokens[position] == "and":
                position += 1
                rhs = parse_not()
                value = value and rhs
            return value

        def parse_not() -> bool:
            nonlocal position
            if position < len(tokens) and tokens[position] == "not":
                position += 1
                return not parse_not()
            return parse_atom()

        def parse_atom() -> bool:
            nonlocal position
            if position >= len(tokens):
                raise ValueError(f"Incomplete Sigma condition: {condition}")
            token = tokens[position]
            position += 1
            if token == "(":
                value = parse_or()
                if position >= len(tokens) or tokens[position] != ")":
                    raise ValueError(f"Unbalanced Sigma condition parentheses: {condition}")
                position += 1
                return value
            if token in {")", "and", "or"}:
                raise ValueError(f"Invalid Sigma condition token '{token}'")
            if token not in values:
                raise ValueError(f"Sigma condition references unknown selection '{token}'")
            return bool(values[token])

        result = parse_or()
        if position != len(tokens):
            raise ValueError(f"Unsupported Sigma condition: {condition}")
        return result, f"{condition}: {result}"

    def resolve_field(self, event: dict[str, Any], field: str) -> Any:
        return self.resolve_field_with_source(event, field)[0]

    def resolve_field_with_source(self, event: dict[str, Any], field: str) -> tuple[Any, str | None]:
        canonical = self._canonical_field(field)
        candidates = [canonical, canonical.lower(), self._snake_case(canonical)]
        candidates.extend(FIELD_ALIASES.get(canonical, []))
        container_paths = ("raw_data", "normalized_event", "event_data", "raw_data.EventData",
                           "raw_data.event_data", "normalized_event.event_data")
        candidates.extend(f"{container}.{canonical}" for container in container_paths)
        candidates.extend(f"{container}.{self._snake_case(canonical)}" for container in container_paths)
        return self._first_path(event, tuple(dict.fromkeys(candidates)))

    def _first_path(self, event: dict[str, Any], paths: tuple[str, ...]) -> tuple[Any, str | None]:
        for path in paths:
            value = self._get_path(event, path)
            if value is not None:
                return value, path
        return None, None

    def _get_path(self, event: dict[str, Any], path: str) -> Any:
        current: Any = event
        for part in path.split("."):
            if not isinstance(current, dict):
                return None
            key = next((key for key in current if key.lower() == part.lower()), None)
            if key is None:
                return None
            current = current[key]
        return current

    def _scalar_values(self, value: Any) -> list[Any]:
        if isinstance(value, list):
            return [nested for item in value for nested in self._scalar_values(item)]
        return [value]

    def _canonical_field(self, field: str) -> str:
        return field.split("|", 1)[0]

    def _snake_case(self, value: str) -> str:
        value = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", value)
        return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value).lower()


sigma_rule_service = SigmaRuleService()
