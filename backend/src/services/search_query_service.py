from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from src.core.config import get_settings
from src.core.permissions import Permission


@dataclass(frozen=True)
class SearchField:
    name: str
    resource: str
    path: str
    data_type: str
    operators: frozenset[str]
    sortable: bool = False
    facetable: bool = False
    case_sensitive: bool = False
    masked: bool = False
    permission: str = Permission.SEARCH_EVENTS.value
    description: str = ""
    example: str = ""
    indexed: bool = False


TEXT_OPS = frozenset({"=", "!=", ":", "IN", "EXISTS", "NOT EXISTS"})
ORDER_OPS = frozenset({"=", "!=", ":", ">", ">=", "<", "<=", "IN", "EXISTS", "NOT EXISTS"})
IP_OPS = frozenset({"=", "!=", ":", "IN", "EXISTS", "NOT EXISTS"})

SEARCH_FIELDS: dict[str, SearchField] = {
    "timestamp": SearchField("timestamp", "*", "timestamp", "datetime", ORDER_OPS, True, False, indexed=True),
    "received_at": SearchField("received_at", "events", "received_at", "datetime", ORDER_OPS, True, indexed=True),
    "processed_at": SearchField("processed_at", "events", "processed_at", "datetime", ORDER_OPS, True),
    "severity": SearchField("severity", "*", "severity", "severity", ORDER_OPS, True, True, indexed=True),
    "status": SearchField("status", "*", "status", "text", TEXT_OPS, True, True),
    "event.category": SearchField("event.category", "events", "event_category", "text", TEXT_OPS, True, True, indexed=True),
    "event.class": SearchField("event.class", "events", "event_class", "text", TEXT_OPS, True, True),
    "event.action": SearchField("event.action", "events", "normalized_event.event.action", "text", TEXT_OPS),
    "event.outcome": SearchField("event.outcome", "events", "normalized_event.event.outcome", "text", TEXT_OPS, facetable=True),
    "result": SearchField("result", "events", "normalized_event.event.outcome", "text", TEXT_OPS, facetable=True),
    "source.ip": SearchField("source.ip", "events", "normalized_event.network.src_ip", "ip", IP_OPS),
    "destination.ip": SearchField("destination.ip", "events", "normalized_event.network.dst_ip", "ip", IP_OPS),
    "source.port": SearchField("source.port", "events", "normalized_event.network.src_port", "integer", ORDER_OPS),
    "destination.port": SearchField("destination.port", "events", "normalized_event.network.dst_port", "integer", ORDER_OPS),
    "user.name": SearchField("user.name", "events", "normalized_event.actor.user", "text", TEXT_OPS),
    "user.id": SearchField("user.id", "events", "normalized_event.actor.user_id", "text", TEXT_OPS),
    "host.name": SearchField("host.name", "events", "normalized_event.device.hostname", "text", TEXT_OPS),
    "host.id": SearchField("host.id", "events", "normalized_event.device.uid", "text", TEXT_OPS),
    "process.name": SearchField("process.name", "events", "normalized_event.process.name", "text", TEXT_OPS),
    "process.pid": SearchField("process.pid", "events", "normalized_event.process.pid", "integer", ORDER_OPS),
    "process.command_line": SearchField("process.command_line", "events", "normalized_event.process.command_line", "text", TEXT_OPS, masked=True),
    "file.name": SearchField("file.name", "events", "normalized_event.file.name", "text", TEXT_OPS),
    "file.path": SearchField("file.path", "events", "normalized_event.file.path", "text", TEXT_OPS, masked=True),
    "file.hash.md5": SearchField("file.hash.md5", "events", "normalized_event.file.hash.md5", "hash", TEXT_OPS),
    "file.hash.sha1": SearchField("file.hash.sha1", "events", "normalized_event.file.hash.sha1", "hash", TEXT_OPS),
    "file.hash.sha256": SearchField("file.hash.sha256", "events", "normalized_event.file.hash.sha256", "hash", TEXT_OPS),
    "domain": SearchField("domain", "events", "normalized_event.domain", "domain", TEXT_OPS),
    "url": SearchField("url", "events", "normalized_event.url", "url", TEXT_OPS, masked=True),
    "collector.id": SearchField("collector.id", "events", "collector_id", "uuid", TEXT_OPS, True, indexed=True),
    "data_source.id": SearchField("data_source.id", "events", "data_source_id", "uuid", TEXT_OPS, True, indexed=True),
    "detection.rule_id": SearchField("detection.rule_id", "alerts", "rule_id", "uuid", TEXT_OPS, permission=Permission.SEARCH_ALERTS.value),
    "alert.id": SearchField("alert.id", "alerts", "id", "uuid", TEXT_OPS, permission=Permission.SEARCH_ALERTS.value, indexed=True),
    "incident.id": SearchField("incident.id", "incidents", "id", "uuid", TEXT_OPS, permission=Permission.SEARCH_INCIDENTS.value, indexed=True),
    "mitre.technique_id": SearchField("mitre.technique_id", "*", "mitre_techniques", "text", TEXT_OPS),
    "message": SearchField("message", "events", "normalized_event.message", "text", TEXT_OPS),
    "title": SearchField("title", "*", "title", "text", TEXT_OPS),
    "confidence": SearchField("confidence", "*", "confidence", "number", ORDER_OPS, True),
    "risk_score": SearchField("risk_score", "incidents", "risk_score", "number", ORDER_OPS, True, permission=Permission.SEARCH_INCIDENTS.value),
    "entity.type": SearchField("entity.type", "entities", "entity_type", "text", TEXT_OPS, True, True, permission=Permission.SEARCH_ENTITIES.value),
    "entity.value": SearchField("entity.value", "entities", "normalized_value", "text", TEXT_OPS, permission=Permission.SEARCH_ENTITIES.value),
    "entity.last_seen": SearchField("entity.last_seen", "entities", "last_seen_at", "datetime", ORDER_OPS, True, permission=Permission.SEARCH_ENTITIES.value),
    "entity.sightings": SearchField("entity.sightings", "entities", "sighting_count", "integer", ORDER_OPS, True, permission=Permission.SEARCH_ENTITIES.value),
}

ALIASES = {"src.ip": "source.ip", "dst.ip": "destination.ip", "hostname": "host.name", "username": "user.name"}


class SearchQueryError(ValueError):
    def __init__(self, code: str, message: str, position: int = 0):
        super().__init__(message)
        self.code, self.message, self.position = code, message, position


TOKEN = re.compile(
    r'\s*(?:(?P<quoted>"(?:\\.|[^"\\])*")|(?P<op>>=|<=|!=|=|>|<|:)|'
    r'(?P<lparen>\()|(?P<rparen>\))|(?P<comma>,)|(?P<word>[A-Za-z0-9_.@/+\-*]+))'
)


class SearchQueryParser:
    def parse(self, query: str) -> dict[str, Any] | None:
        settings = get_settings()
        if len(query) > settings.SEARCH_MAX_QUERY_LENGTH:
            raise SearchQueryError("SEARCH_TOO_COMPLEX", "Query exceeds maximum length", settings.SEARCH_MAX_QUERY_LENGTH)
        self.query = query
        self.tokens = self._tokenize(query)
        self.index = 0
        self.clauses = 0
        self.wildcards = 0
        if not self.tokens:
            return None
        node = self._or(0)
        if self.index != len(self.tokens):
            token = self.tokens[self.index]
            raise SearchQueryError("SEARCH_QUERY_INVALID", "Unexpected token", token[2])
        return node

    def _tokenize(self, query: str) -> list[tuple[str, str, int]]:
        result, position = [], 0
        while position < len(query):
            match = TOKEN.match(query, position)
            if not match:
                raise SearchQueryError("SEARCH_QUERY_INVALID", "Invalid token", position)
            kind = next(key for key, value in match.groupdict().items() if value is not None)
            result.append((kind, match.group(kind), match.start(kind)))
            position = match.end()
        return result

    def _or(self, depth: int):
        node = self._and(depth)
        while self._word("OR"):
            node = {"type": "boolean", "operator": "OR", "children": [node, self._and(depth)]}
        return node

    def _and(self, depth: int):
        node = self._not(depth)
        while self._word("AND"):
            node = {"type": "boolean", "operator": "AND", "children": [node, self._not(depth)]}
        return node

    def _not(self, depth: int):
        if self._word("NOT"):
            return {"type": "not", "child": self._not(depth)}
        return self._primary(depth)

    def _primary(self, depth: int):
        settings = get_settings()
        if depth > settings.SEARCH_MAX_NESTING_DEPTH:
            raise SearchQueryError("SEARCH_TOO_COMPLEX", "Query nesting is too deep", self._position())
        if self._accept("lparen"):
            node = self._or(depth + 1)
            self._expect("rparen", "Missing closing parenthesis")
            return node
        return self._clause()

    def _clause(self):
        settings = get_settings()
        field_token = self._expect("word", "Expected searchable field")
        public_name = ALIASES.get(field_token[1].lower(), field_token[1].lower())
        field = SEARCH_FIELDS.get(public_name)
        if not field:
            raise SearchQueryError("SEARCH_FIELD_UNKNOWN", f"Unknown search field '{field_token[1]}'", field_token[2])
        if self._word("NOT"):
            self._expect_word("EXISTS")
            operator = "NOT EXISTS"
            value = None
        elif self._word("EXISTS"):
            operator, value = "EXISTS", None
        elif self._word("IN"):
            operator, value = "IN", self._list()
        else:
            operator_token = self._expect("op", "Expected search operator")
            operator = operator_token[1]
            value = self._value()
        if operator not in field.operators:
            raise SearchQueryError("SEARCH_OPERATOR_INVALID", f"Operator '{operator}' is not valid for {public_name}", self._position())
        self.clauses += 1
        if self.clauses > settings.SEARCH_MAX_CLAUSES:
            raise SearchQueryError("SEARCH_TOO_COMPLEX", "Query has too many clauses", field_token[2])
        normalized = self._validate(field, value, field_token[2])
        return {"type": "clause", "field": public_name, "operator": operator, "value": normalized}

    def _list(self):
        settings = get_settings()
        self._expect("lparen", "Expected '(' after IN")
        values = [self._value()]
        while self._accept("comma"):
            values.append(self._value())
            if len(values) > settings.SEARCH_MAX_LIST_SIZE:
                raise SearchQueryError("SEARCH_TOO_COMPLEX", "IN list is too large", self._position())
        self._expect("rparen", "Expected ')' after IN list")
        return values

    def _value(self):
        if self.index >= len(self.tokens) or self.tokens[self.index][0] not in {"word", "quoted"}:
            raise SearchQueryError("SEARCH_VALUE_INVALID", "Expected a value", self._position())
        kind, value, _ = self.tokens[self.index]
        self.index += 1
        if kind == "quoted":
            return value[1:-1].replace(r"\"", '"').replace(r"\\", "\\")
        return value

    def _validate(self, field: SearchField, value: Any, position: int):
        if value is None:
            return None
        if isinstance(value, list):
            return [self._validate(field, item, position) for item in value]
        text = str(value)
        if text.startswith("*"):
            raise SearchQueryError("SEARCH_VALUE_INVALID", "Leading wildcards are not allowed", position)
        count = text.count("*")
        self.wildcards += count
        if self.wildcards > get_settings().SEARCH_MAX_WILDCARDS:
            raise SearchQueryError("SEARCH_TOO_COMPLEX", "Too many wildcards", position)
        try:
            if field.data_type == "integer":
                return int(text)
            if field.data_type == "number":
                return float(text)
            if field.data_type == "datetime":
                return normalize_time_value(text).isoformat()
            if field.data_type == "uuid" and not re.fullmatch(r"[0-9a-fA-F-]{36}", text):
                raise ValueError
            if field.data_type == "ip":
                return str(ipaddress.ip_network(text, strict=False)) if "/" in text else str(ipaddress.ip_address(text))
            if field.data_type == "hash" and not re.fullmatch(r"[0-9a-fA-F]{32,128}", text):
                raise ValueError
            if field.data_type == "severity":
                mapping = {"low": 1, "medium": 2, "high": 3, "critical": 4}
                if text.lower() in mapping:
                    return mapping[text.lower()]
                if text.isdigit() and 1 <= int(text) <= 4:
                    return int(text)
                raise ValueError
        except (ValueError, TypeError):
            raise SearchQueryError("SEARCH_VALUE_INVALID", f"Invalid {field.data_type} value", position)
        return text[:2048]

    def _accept(self, kind: str):
        if self.index < len(self.tokens) and self.tokens[self.index][0] == kind:
            token = self.tokens[self.index]
            self.index += 1
            return token
        return None

    def _word(self, value: str):
        if self.index < len(self.tokens) and self.tokens[self.index][0] == "word" and self.tokens[self.index][1].upper() == value:
            self.index += 1
            return True
        return False

    def _expect_word(self, value: str):
        if not self._word(value):
            raise SearchQueryError("SEARCH_QUERY_INVALID", f"Expected {value}", self._position())

    def _expect(self, kind: str, message: str):
        token = self._accept(kind)
        if not token:
            raise SearchQueryError("SEARCH_QUERY_INVALID", message, self._position())
        return token

    def _position(self):
        return self.tokens[self.index][2] if self.index < len(self.tokens) else len(self.query)

def normalize_time_value(value: str, now: datetime | None = None) -> datetime:
    current = now or datetime.now(timezone.utc)
    match = re.fullmatch(r"now-(\d+)(m|h|d)", value.lower())
    if match:
        amount, unit = int(match.group(1)), match.group(2)
        return current - {"m": timedelta(minutes=amount), "h": timedelta(hours=amount), "d": timedelta(days=amount)}[unit]
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def field_catalog(permission_values: set[str]) -> list[dict[str, Any]]:
    return [
        {
            "name": field.name, "type": field.data_type, "operators": sorted(field.operators),
            "sortable": field.sortable, "facetable": field.facetable, "masked": field.masked,
            "description": field.description, "example": field.example, "indexed": field.indexed,
        }
        for field in SEARCH_FIELDS.values()
        if field.permission in permission_values
    ]


search_query_parser = SearchQueryParser()
