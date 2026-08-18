from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import String, and_, case, cast, func, not_, or_
from sqlalchemy.orm import Session

from src.core.config import get_settings
from src.models.sqlalchemy import Alert, Incident, SearchEntity, SearchHistory, SecurityEvent
from src.services.search_query_service import SEARCH_FIELDS, SearchQueryError, normalize_time_value, search_query_parser
from src.utils.datetime_utils import ensure_utc, get_utc_now


RESOURCE_MODELS = {"events": SecurityEvent, "alerts": Alert, "incidents": Incident, "entities": SearchEntity}
RESOURCE_PERMISSION = {
    "events": "search.events", "alerts": "search.alerts",
    "incidents": "search.incidents", "entities": "search.entities",
}


class SearchService:
    def execute(
        self,
        db: Session,
        *,
        tenant_id: str,
        user_id: str,
        permission_values: set[str],
        query_text: str,
        resource_scope: str,
        start: datetime | None,
        end: datetime | None,
        page: int,
        page_size: int,
        sort_field: str,
        sort_direction: str,
        record_history: bool = True,
    ) -> dict[str, Any]:
        started = time.perf_counter()
        query_id = str(uuid.uuid4())
        if resource_scope not in RESOURCE_MODELS:
            raise SearchQueryError("SEARCH_RESOURCE_UNSUPPORTED", "Unsupported search resource")
        if RESOURCE_PERMISSION[resource_scope] not in permission_values:
            raise PermissionError("SEARCH_PERMISSION_DENIED")
        settings = get_settings()
        if page_size > settings.SEARCH_MAX_PAGE_SIZE:
            raise SearchQueryError("SEARCH_RESULT_LIMIT_EXCEEDED", "Page size exceeds configured maximum")
        ast = search_query_parser.parse(query_text)
        start, end = self._time_range(start, end, permission_values)
        model = RESOURCE_MODELS[resource_scope]
        query = db.query(model).filter(model.tenant_id == tenant_id)
        time_column = self._time_column(model)
        if time_column is not None:
            query = query.filter(time_column >= start, time_column <= end)
        if ast:
            query = query.filter(self._compile(ast, model, resource_scope))
        sort_column = self._sort_column(model, resource_scope, sort_field)
        if sort_column is None:
            raise SearchQueryError("SEARCH_SORT_INVALID", "Sort field is unavailable for this resource")
        direction = sort_column.desc() if sort_direction == "desc" else sort_column.asc()
        id_direction = model.id.desc() if sort_direction == "desc" else model.id.asc()
        total = query.with_entities(func.count(model.id)).scalar() or 0
        rows = query.order_by(direction, id_direction).offset((page - 1) * page_size).limit(page_size + 1).all()
        has_next = len(rows) > page_size
        rows = rows[:page_size]
        execution_ms = round((time.perf_counter() - started) * 1000, 2)
        result = {
            "query_id": query_id, "resource_scope": resource_scope,
            "normalized_query": ast, "time_range": {"start": start, "end": end},
            "items": [self._project(resource_scope, row) for row in rows],
            "page": page, "page_size": page_size, "result_count": len(rows),
            "total_count": total, "total_count_estimated": False, "has_next": has_next,
            "sort_field": sort_field, "sort_direction": sort_direction,
            "execution_time_ms": execution_ms,
        }
        if record_history:
            db.add(SearchHistory(
                tenant_id=tenant_id, user_id=user_id,
                display_query=self._sanitize_query(query_text), normalized_query=ast,
                resource_scope=resource_scope, time_range={"start": start.isoformat(), "end": end.isoformat()},
                sort={"field": sort_field, "direction": sort_direction},
                result_count=len(rows), execution_time_ms=execution_ms, success=True,
            ))
            db.commit()
        return result

    def _compile(self, node: dict[str, Any], model, resource: str):
        if node["type"] == "boolean":
            expressions = [self._compile(child, model, resource) for child in node["children"]]
            return and_(*expressions) if node["operator"] == "AND" else or_(*expressions)
        if node["type"] == "not":
            return not_(self._compile(node["child"], model, resource))
        field = SEARCH_FIELDS[node["field"]]
        if field.resource not in {resource, "*"}:
            raise SearchQueryError("SEARCH_FIELD_UNKNOWN", f"Field '{field.name}' is not available for {resource}")
        column = self._time_column(model) if field.name == "timestamp" else self._column(model, field.path)
        if column is None:
            raise SearchQueryError("SEARCH_FIELD_UNKNOWN", f"Field '{field.name}' is unavailable")
        operator, value = node["operator"], node["value"]
        if field.data_type == "severity":
            column = case(
                (cast(column, String).in_(["critical", "Severity.CRITICAL"]), 4),
                (cast(column, String).in_(["high", "Severity.HIGH"]), 3),
                (cast(column, String).in_(["medium", "Severity.MEDIUM"]), 2),
                else_=1,
            )
        if field.data_type == "datetime" and value is not None:
            value = normalize_time_value(value)
        if operator == "EXISTS":
            return column.is_not(None)
        if operator == "NOT EXISTS":
            return column.is_(None)
        if operator == "IN":
            return column.in_(value)
        if operator == "!=":
            return column != value
        if operator in {":", "="}:
            if isinstance(value, str) and "*" in value:
                return cast(column, String).ilike(value.replace("*", "%"))
            if operator == ":" and isinstance(value, str) and field.data_type in {"text", "domain", "url"}:
                return cast(column, String).ilike(f"%{self._escape_like(value)}%", escape="\\")
            if field.data_type == "ip" and isinstance(value, str) and "/" in value:
                network, prefix = value.split("/")
                if prefix in {"8", "16", "24"}:
                    parts = network.split(".")[: int(prefix) // 8]
                    return cast(column, String).like(".".join(parts) + ".%")
                raise SearchQueryError("SEARCH_VALUE_INVALID", "Portable CIDR search supports /8, /16, and /24")
            return column == value
        return {">": column > value, ">=": column >= value, "<": column < value, "<=": column <= value}[operator]

    @staticmethod
    def _column(model, path: str):
        parts = path.split(".")
        column = getattr(model, parts[0], None)
        if column is None:
            return None
        for part in parts[1:]:
            column = column[part]
        return column.as_string() if len(parts) > 1 else column

    @staticmethod
    def _time_column(model):
        for name in ("timestamp", "created_at", "last_seen_at"):
            column = getattr(model, name, None)
            if column is not None:
                return column
        return None

    def _sort_column(self, model, resource: str, field_name: str):
        # "timestamp" is the stable cross-resource UI concept even when the
        # underlying record calls it created_at or last_seen_at.
        if field_name == "timestamp":
            return self._time_column(model)
        if field_name == "id":
            return model.id
        field = SEARCH_FIELDS.get(field_name)
        if not field or not field.sortable or field.resource not in {resource, "*"}:
            return None
        return self._column(model, field.path)

    @staticmethod
    def _project(resource: str, row) -> dict[str, Any]:
        if resource == "events":
            normalized = row.normalized_event or {}
            return {
                "id": row.id, "type": "event", "timestamp": row.timestamp, "severity": row.severity,
                "title": normalized.get("message") or f"{row.event_type.value} event",
                "source": row.source, "event_category": row.event_category, "event_class": row.event_class,
                "collector_id": row.collector_id, "data_source_id": row.data_source_id,
                "quality_score": row.data_quality_score, "path": f"/events/{row.id}",
            }
        if resource == "alerts":
            return {"id": row.id, "type": "alert", "timestamp": row.created_at, "severity": row.severity,
                    "title": row.title, "status": row.status, "path": f"/alerts/{row.id}"}
        if resource == "incidents":
            return {"id": row.id, "type": "incident", "timestamp": row.created_at, "severity": row.severity,
                    "title": row.title, "status": row.status, "risk_score": row.risk_score, "path": f"/incidents/{row.id}"}
        return {"id": row.id, "type": "entity", "entity_type": row.entity_type, "title": row.display_value,
                "first_seen_at": row.first_seen_at, "last_seen_at": row.last_seen_at,
                "sighting_count": row.sighting_count, "path": f"/entities/{row.id}"}

    @staticmethod
    def _time_range(start, end, permissions):
        settings = get_settings()
        now = get_utc_now()
        end = ensure_utc(end) if end else now
        start = ensure_utc(start) if start else end - timedelta(hours=settings.SEARCH_DEFAULT_RANGE_HOURS)
        if start >= end:
            raise SearchQueryError("SEARCH_VALUE_INVALID", "Search start must be before end")
        if end > now + timedelta(minutes=5):
            raise SearchQueryError("SEARCH_VALUE_INVALID", "Search end is too far in the future")
        max_days = settings.SEARCH_MAX_BACKGROUND_DAYS if "search.extended_range" in permissions else settings.SEARCH_MAX_INTERACTIVE_DAYS
        if end - start > timedelta(days=max_days):
            raise SearchQueryError("SEARCH_TIME_RANGE_TOO_LARGE", "Search range exceeds the interactive limit")
        return start, end

    @staticmethod
    def _sanitize_query(value: str) -> str:
        return re.sub(r"(?i)(password|token|secret|api[_-]?key)\s*[:=]\s*(\"[^\"]*\"|\S+)", r"\1:[REDACTED]", value)[:4000]

    @staticmethod
    def _escape_like(value: str) -> str:
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


search_service = SearchService()
