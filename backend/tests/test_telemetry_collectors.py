from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.core.database import Base
from src.models.pydantic import IngestionBatchRequest, SecurityEventCreate
from src.models.sqlalchemy import DataSource, EventType, SecurityEvent, Severity, Tenant
from src.services.telemetry_ingestion_service import telemetry_ingestion_service
from src.services.telemetry_normalization_service import telemetry_normalization_service


@pytest.fixture()
def telemetry_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    tenant = Tenant(name="Telemetry", slug="telemetry")
    session.add(tenant)
    session.flush()
    source = DataSource(
        tenant_id=tenant.id, source_key="edge-fw", name="Edge firewall",
        source_type="firewall", vendor="Example", product="NGFW", parser_name="cef",
    )
    session.add(source)
    session.commit()
    yield session, tenant, source
    session.close()
    engine.dispose()


def _event(source_id: str, event_id: str = "vendor-42") -> SecurityEventCreate:
    return SecurityEventCreate(
        source="edge-fw", data_source_id=source_id, source_event_id=event_id,
        event_type=EventType.NETWORK, severity=Severity.HIGH,
        format="cef", raw_message="CEF:0|Example|NGFW|1|100|Blocked connection|7|src=10.0.0.1",
        raw_event={"message": "Blocked connection"},
    )


def test_batch_receipt_dedup_and_replay_are_deterministic(telemetry_db):
    db, tenant, source = telemetry_db
    request = IngestionBatchRequest(batch_id="batch-1", events=[_event(source.id)])
    batch, items = telemetry_ingestion_service.ingest_batch(
        db, tenant_id=tenant.id, actor_key="collector:test", request=request, dispatch=False,
    )
    assert batch.accepted_count == 1
    assert items[0]["status"] == "accepted"
    assert db.query(SecurityEvent).count() == 1

    replay, replay_items = telemetry_ingestion_service.ingest_batch(
        db, tenant_id=tenant.id, actor_key="collector:test", request=request, dispatch=False,
    )
    assert replay.id == batch.id
    assert replay._replayed is True
    assert replay_items[0]["event_id"] == items[0]["event_id"]
    assert db.query(SecurityEvent).count() == 1

    second, second_items = telemetry_ingestion_service.ingest_batch(
        db, tenant_id=tenant.id, actor_key="collector:test",
        request=IngestionBatchRequest(batch_id="batch-2", events=[_event(source.id)]),
        dispatch=False,
    )
    assert second.duplicate_count == 1
    assert second_items[0]["duplicate_of"] == items[0]["event_id"]


def test_batch_id_conflict_and_partial_acceptance(telemetry_db):
    db, tenant, source = telemetry_db
    telemetry_ingestion_service.ingest_batch(
        db, tenant_id=tenant.id, actor_key="user:test",
        request=IngestionBatchRequest(batch_id="fixed", events=[_event(source.id)]),
        dispatch=False,
    )
    with pytest.raises(ValueError, match="BATCH_ID_CONFLICT"):
        telemetry_ingestion_service.ingest_batch(
            db, tenant_id=tenant.id, actor_key="user:test",
            request=IngestionBatchRequest(batch_id="fixed", events=[_event(source.id, "changed")]),
            dispatch=False,
        )

    _batch, items = telemetry_ingestion_service.ingest_batch(
        db, tenant_id=tenant.id, actor_key="user:test",
        request=IngestionBatchRequest(batch_id="partial", events=[
            _event(source.id, "good"),
            SecurityEventCreate(source="bad", event_type=EventType.ALERT, format="cef", raw_message="invalid", raw_event={}),
        ]), dispatch=False,
    )
    assert [item["status"] for item in items] == ["accepted", "rejected"]


@pytest.mark.parametrize("format_name,message", [
    ("syslog", "<34>Oct 11 22:14:15 host sshd: login failed"),
    ("cef", "CEF:0|Vendor|Product|1|42|Threat|8|src=192.0.2.1"),
    ("leef", "LEEF:2.0|Vendor|Product|1|42|src=192.0.2.1"),
])
def test_supported_text_formats_produce_stable_envelope(format_name, message):
    result = telemetry_normalization_service.normalize(
        format_name=format_name, raw_message=message, raw_event={},
        supplied_normalized=None, supplied_type=EventType.ALERT,
        supplied_severity=Severity.MEDIUM, supplied_timestamp=None, source="test",
    )
    assert result.parser_version == "1.0.0"
    assert result.normalized["metadata"]["version"] == "1.0"
    assert 0 <= result.quality_score <= 100
