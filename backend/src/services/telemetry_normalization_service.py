from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from src.models.sqlalchemy import EventType, Severity
from src.utils.datetime_utils import ensure_utc, get_utc_now


@dataclass(frozen=True)
class NormalizationResult:
    normalized: dict[str, Any]
    event_type: EventType
    severity: Severity
    timestamp: datetime
    original_offset: str | None
    parser_name: str
    parser_version: str
    quality_score: int
    quality_reasons: list[str]
    warnings: list[str]


class TelemetryNormalizationService:
    """Versioned, bounded normalizer with an OCSF-oriented common envelope.

    This is an internal mapping contract, not a claim of full OCSF conformance.
    """

    VERSION = "1.0.0"
    MAX_EXTENSION_FIELDS = 100
    MAX_STRING_LENGTH = 8192

    def __init__(self) -> None:
        self._parsers: dict[str, Callable[[str | None, dict[str, Any]], dict[str, Any]]] = {
            "json": self._json,
            "syslog": self._syslog,
            "cef": self._cef,
            "leef": self._leef,
            "windows": self._json,
            "linux": self._json,
        }

    def normalize(
        self,
        *,
        format_name: str,
        raw_message: str | None,
        raw_event: dict[str, Any],
        supplied_normalized: dict[str, Any] | None,
        supplied_type: EventType,
        supplied_severity: Severity,
        supplied_timestamp: datetime | None,
        source: str,
    ) -> NormalizationResult:
        parser = self._parsers.get(format_name.lower())
        if parser is None:
            raise ValueError("UNSUPPORTED_FORMAT")
        parsed = parser(raw_message, raw_event)
        merged = {**parsed, **(supplied_normalized or {})}
        event_type = self._event_type(merged.get("event_type"), supplied_type)
        severity = self._severity(merged.get("severity"), supplied_severity)
        timestamp_value = merged.get("timestamp") or supplied_timestamp
        timestamp, offset, timestamp_warning = self._timestamp(timestamp_value)
        warnings = [timestamp_warning] if timestamp_warning else []
        reasons: list[str] = []
        score = 100
        if not merged.get("host") and not merged.get("hostname"):
            score -= 10
            reasons.append("missing_host")
        if not merged.get("message") and not raw_message:
            score -= 10
            reasons.append("missing_message")
        if timestamp_warning:
            score -= 15
            reasons.append("invalid_or_missing_timestamp")
        extensions = self._bounded_extensions(raw_event)
        normalized = {
            "metadata": {"version": "1.0", "product": {"name": "VigilantAI"}, "source": source},
            "time": timestamp.isoformat().replace("+00:00", "Z"),
            "class_name": merged.get("class_name") or event_type.value,
            "category_name": merged.get("category_name") or self._category(event_type),
            "severity": severity.value,
            "message": str(merged.get("message") or raw_message or "")[: self.MAX_STRING_LENGTH],
            "actor": merged.get("actor") or {"user": merged.get("user")},
            "device": merged.get("device") or {"hostname": merged.get("hostname") or merged.get("host")},
            "network": merged.get("network") or {
                "src_ip": merged.get("source_ip") or merged.get("src"),
                "dst_ip": merged.get("destination_ip") or merged.get("dst"),
            },
            "extensions": extensions,
        }
        return NormalizationResult(
            normalized=normalized,
            event_type=event_type,
            severity=severity,
            timestamp=timestamp,
            original_offset=offset,
            parser_name=format_name.lower(),
            parser_version=self.VERSION,
            quality_score=max(0, score),
            quality_reasons=reasons,
            warnings=warnings,
        )

    def _json(self, raw_message: str | None, raw_event: dict[str, Any]) -> dict[str, Any]:
        if raw_message:
            try:
                value = json.loads(raw_message)
            except json.JSONDecodeError as exc:
                raise ValueError("INVALID_JSON") from exc
            if not isinstance(value, dict):
                raise ValueError("JSON_OBJECT_REQUIRED")
            return value
        return dict(raw_event)

    def _syslog(self, raw_message: str | None, raw_event: dict[str, Any]) -> dict[str, Any]:
        message = raw_message or str(raw_event.get("message") or "")
        match = re.match(r"^(?:<(?P<pri>\d{1,3})>)?(?P<body>.*)$", message)
        if not match:
            raise ValueError("INVALID_SYSLOG")
        priority = int(match.group("pri") or 13)
        return {"message": match.group("body"), "severity": self._syslog_severity(priority % 8)}

    def _cef(self, raw_message: str | None, raw_event: dict[str, Any]) -> dict[str, Any]:
        parts = (raw_message or "").split("|", 7)
        if len(parts) < 7 or not parts[0].startswith("CEF:"):
            raise ValueError("INVALID_CEF")
        return {
            "vendor": parts[1], "product": parts[2], "event_id": parts[4],
            "message": parts[5], "severity": parts[6], "extensions": parts[7] if len(parts) > 7 else "",
        }

    def _leef(self, raw_message: str | None, raw_event: dict[str, Any]) -> dict[str, Any]:
        parts = (raw_message or "").split("|", 5)
        if len(parts) < 5 or not parts[0].startswith("LEEF:"):
            raise ValueError("INVALID_LEEF")
        return {"vendor": parts[1], "product": parts[2], "event_id": parts[4], "message": parts[5] if len(parts) > 5 else ""}

    def _bounded_extensions(self, raw: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in list(raw.items())[: self.MAX_EXTENSION_FIELDS]:
            if isinstance(value, str):
                value = value[: self.MAX_STRING_LENGTH]
            elif not isinstance(value, (str, int, float, bool, list, dict, type(None))):
                value = str(value)[: self.MAX_STRING_LENGTH]
            result[str(key)[:128]] = value
        return result

    @staticmethod
    def _event_type(value: Any, fallback: EventType) -> EventType:
        try:
            return EventType(str(value).lower()) if value else fallback
        except ValueError:
            return fallback

    @staticmethod
    def _severity(value: Any, fallback: Severity) -> Severity:
        if value is None:
            return fallback
        aliases = {"0": "low", "1": "low", "2": "low", "3": "medium", "4": "medium", "5": "high", "6": "high", "7": "critical", "8": "critical", "9": "critical", "10": "critical"}
        normalized = aliases.get(str(value).lower(), str(value).lower())
        try:
            return Severity(normalized)
        except ValueError:
            return fallback

    @staticmethod
    def _timestamp(value: Any) -> tuple[datetime, str | None, str | None]:
        if isinstance(value, datetime):
            offset = value.strftime("%z") or None
            return ensure_utc(value), offset, None
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return ensure_utc(parsed), parsed.strftime("%z") or None, None
            except ValueError:
                pass
        return get_utc_now(), None, "timestamp_defaulted_to_receive_time"

    @staticmethod
    def _category(event_type: EventType) -> str:
        return {"login": "identity_activity", "logout": "identity_activity", "network": "network_activity",
                "process": "system_activity", "file": "file_activity", "alert": "findings",
                "user_creation": "identity_activity"}.get(event_type.value, "other")

    @staticmethod
    def _syslog_severity(value: int) -> str:
        return "critical" if value <= 2 else "high" if value == 3 else "medium" if value <= 5 else "low"


telemetry_normalization_service = TelemetryNormalizationService()
