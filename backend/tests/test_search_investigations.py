from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.core.database import Base
from src.models.sqlalchemy import (
    EntityRelationship, EventEntity, EventType, SearchEntity, SearchHistory,
    SecurityEvent, Severity, Tenant,
)
from src.services.entity_investigation_service import entity_investigation_service
from src.services.search_query_service import SearchQueryError, field_catalog, search_query_parser
from src.services.search_service import search_service


@pytest.mark.parametrize(
    "query",
    [
        "severity:high",
        "severity>=medium AND source.ip:10.0.0.5",
        "user.name EXISTS",
        "user.name NOT EXISTS",
        "destination.port IN (80,443)",
        'message:"failed login"',
        "NOT (severity:low OR severity:medium)",
        "timestamp>=now-24h",
    ],
)
def test_supported_query_syntax(query):
    assert search_query_parser.parse(query)


@pytest.mark.parametrize(
    "query,code",
    [
        ("unknown:value", "SEARCH_FIELD_UNKNOWN"),
        ("source.ip:999.1.1.1", "SEARCH_VALUE_INVALID"),
        ("destination.port:abc", "SEARCH_VALUE_INVALID"),
        ("message:*danger", "SEARCH_VALUE_INVALID"),
        ("severity:impossible", "SEARCH_VALUE_INVALID"),
        ("severity:high AND", "SEARCH_QUERY_INVALID"),
    ],
)
def test_invalid_queries_have_stable_error_codes(query, code):
    with pytest.raises(SearchQueryError) as raised:
        search_query_parser.parse(query)
    assert raised.value.code == code


def test_empty_query_is_valid_match_all():
    assert search_query_parser.parse("") is None


def test_field_catalog_does_not_expose_database_expressions():
    fields = field_catalog({"search.events", "search.alerts", "search.incidents", "search.entities"})
    assert any(field["name"] == "source.ip" for field in fields)
    assert all("path" not in field for field in fields)


@pytest.fixture()
def search_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    tenant_a = Tenant(name="Alpha", slug="alpha-search")
    tenant_b = Tenant(name="Beta", slug="beta-search")
    db.add_all([tenant_a, tenant_b])
    db.flush()
    now = datetime.now(timezone.utc)
    first = SecurityEvent(
        tenant_id=tenant_a.id, source="edge", event_type=EventType.NETWORK,
        severity=Severity.HIGH, timestamp=now,
        raw_event={"src_ip": "10.0.0.5"},
        normalized_event={
            "message": "Blocked admin login",
            "actor": {"user": "Alice"},
            "device": {"hostname": "WS-01"},
            "network": {"src_ip": "10.0.0.5", "dst_ip": "192.0.2.8", "dst_port": 443},
            "process": {"name": "powershell.exe"},
        },
    )
    second = SecurityEvent(
        tenant_id=tenant_b.id, source="edge", event_type=EventType.NETWORK,
        severity=Severity.CRITICAL, timestamp=now,
        raw_event={"src_ip": "203.0.113.9"},
        normalized_event={"message": "Other tenant secret", "network": {"src_ip": "203.0.113.9"}},
    )
    db.add_all([first, second])
    db.commit()
    yield db, tenant_a, tenant_b, first
    db.close()
    engine.dispose()


def _execute(db, tenant_id, query="", permissions=None):
    return search_service.execute(
        db, tenant_id=tenant_id, user_id="test-user",
        permission_values=permissions or {"search.events"},
        query_text=query, resource_scope="events", start=None, end=None,
        page=1, page_size=25, sort_field="timestamp", sort_direction="desc",
    )


def test_search_is_tenant_scoped_before_filters(search_db):
    db, tenant_a, _tenant_b, _event = search_db
    result = _execute(db, tenant_a.id)
    assert result["total_count"] == 1
    assert result["items"][0]["title"] == "Blocked admin login"


def test_structured_json_field_search(search_db):
    db, tenant_a, _tenant_b, _event = search_db
    assert _execute(db, tenant_a.id, "source.ip:10.0.0.5")["total_count"] == 1
    assert _execute(db, tenant_a.id, "source.ip:203.0.113.9")["total_count"] == 0


def test_search_requires_resource_permission(search_db):
    db, tenant_a, _tenant_b, _event = search_db
    with pytest.raises(PermissionError, match="SEARCH_PERMISSION_DENIED"):
        _execute(db, tenant_a.id, permissions={"search.incidents"})


def test_interactive_time_range_is_bounded(search_db):
    db, tenant_a, _tenant_b, _event = search_db
    with pytest.raises(SearchQueryError) as raised:
        search_service.execute(
            db, tenant_id=tenant_a.id, user_id="test-user",
            permission_values={"search.events"}, query_text="", resource_scope="events",
            start=datetime.now(timezone.utc) - timedelta(days=31),
            end=datetime.now(timezone.utc), page=1, page_size=25,
            sort_field="timestamp", sort_direction="desc",
        )
    assert raised.value.code == "SEARCH_TIME_RANGE_TOO_LARGE"


def test_search_history_is_sanitized(search_db):
    db, tenant_a, _tenant_b, _event = search_db
    _execute(db, tenant_a.id, 'message:"token=supersecret"')
    history = db.query(SearchHistory).one()
    assert "supersecret" not in history.display_query


def test_entity_extraction_is_idempotent_and_creates_observed_relationships(search_db):
    db, tenant_a, _tenant_b, event = search_db
    entity_investigation_service.extract_event(db, event)
    db.commit()
    count = db.query(SearchEntity).filter(SearchEntity.tenant_id == tenant_a.id).count()
    links = db.query(EventEntity).filter(EventEntity.tenant_id == tenant_a.id).count()
    entity_investigation_service.extract_event(db, event)
    db.commit()
    assert db.query(SearchEntity).filter(SearchEntity.tenant_id == tenant_a.id).count() == count
    assert db.query(EventEntity).filter(EventEntity.tenant_id == tenant_a.id).count() == links
    assert db.query(EntityRelationship).filter(EntityRelationship.tenant_id == tenant_a.id).count() >= 2


def test_entity_graph_never_crosses_tenants(search_db):
    db, tenant_a, tenant_b, event = search_db
    entities = entity_investigation_service.extract_event(db, event)
    other = SearchEntity(
        tenant_id=tenant_b.id, entity_type="host", normalized_value="hidden",
        display_value="hidden", first_seen_at=event.timestamp, last_seen_at=event.timestamp,
    )
    db.add(other)
    db.commit()
    graph = entity_investigation_service.graph(db, tenant_a.id, entities[0].id, 3, 100, 100)
    assert other.id not in {node["id"] for node in graph["nodes"]}
