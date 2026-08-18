from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.core.config import get_settings
from src.models.pydantic import IngestionBatchRequest, SecurityEventCreate
from src.models.sqlalchemy import (
    Collector,
    DataSource,
    IngestionBatch,
    SecurityEvent,
    TelemetryFailure,
)
from src.services.telemetry_normalization_service import telemetry_normalization_service
from src.utils.datetime_utils import ensure_utc, get_utc_now
from src.core.observability import (
    INGESTION_BATCHES, INGESTION_BATCH_SIZE, INGESTION_DEAD_LETTER,
    INGESTION_EVENT_OUTCOMES, INGESTION_LAG, INGESTION_QUALITY,
)


class TelemetryIngestionService:
    def ingest_batch(
        self,
        db: Session,
        *,
        tenant_id: str,
        actor_key: str,
        request: IngestionBatchRequest,
        collector: Collector | None = None,
        dispatch: bool = True,
    ) -> tuple[IngestionBatch, list[dict[str, Any]]]:
        settings = get_settings()
        if len(request.events) > settings.INGESTION_MAX_BATCH_EVENTS:
            raise ValueError("BATCH_LIMIT_EXCEEDED")
        canonical = json.dumps(request.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        if len(canonical.encode()) > settings.INGESTION_MAX_REQUEST_BYTES:
            raise ValueError("REQUEST_TOO_LARGE")
        fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
        existing = db.query(IngestionBatch).filter(
            IngestionBatch.tenant_id == tenant_id,
            IngestionBatch.actor_key == actor_key,
            IngestionBatch.batch_key == request.batch_id,
        ).first()
        if existing:
            if existing.request_fingerprint != fingerprint:
                raise ValueError("BATCH_ID_CONFLICT")
            receipt = dict(existing.receipt or {})
            receipt["replayed"] = True
            existing._replayed = True
            return existing, receipt.get("items", [])

        now = get_utc_now()
        batch = IngestionBatch(
            tenant_id=tenant_id,
            collector_id=collector.id if collector else None,
            actor_key=actor_key,
            batch_key=request.batch_id,
            request_fingerprint=fingerprint,
            submitted_count=len(request.events),
            state="processing",
        )
        db.add(batch)
        db.flush()
        INGESTION_BATCH_SIZE.observe(len(request.events))
        items: list[dict[str, Any]] = []
        accepted_ids: list[str] = []
        for index, event_data in enumerate(request.events):
            item = self._ingest_item(db, tenant_id, batch, index, event_data, collector)
            items.append(item)
            if item["status"] == "accepted":
                accepted_ids.append(item["event_id"])
        batch.accepted_count = sum(item["status"] == "accepted" for item in items)
        batch.duplicate_count = sum(item["status"] == "duplicate" for item in items)
        batch.rejected_count = sum(item["status"] == "rejected" for item in items)
        batch.state = "completed" if not batch.rejected_count else "partial"
        batch.completed_at = now
        batch.receipt = {"items": items, "replayed": False}
        if collector:
            collector.last_ingestion_at = now
            collector.events_submitted += len(request.events)
            collector.events_accepted += batch.accepted_count
            collector.events_rejected += batch.rejected_count
        db.commit()  # Events are durable before downstream detection is scheduled.
        INGESTION_BATCHES.labels(batch.state).inc()
        for item in items:
            INGESTION_EVENT_OUTCOMES.labels(item["status"]).inc()
        if dispatch:
            self._dispatch(accepted_ids)
        db.refresh(batch)
        batch._replayed = False
        return batch, items

    def _ingest_item(
        self,
        db: Session,
        tenant_id: str,
        batch: IngestionBatch,
        index: int,
        event_data: SecurityEventCreate,
        collector: Collector | None,
    ) -> dict[str, Any]:
        settings = get_settings()
        encoded = json.dumps(event_data.model_dump(mode="json"), sort_keys=True, default=str).encode()
        if len(encoded) > settings.INGESTION_MAX_EVENT_BYTES:
            return {"index": index, "status": "rejected", "error_code": "EVENT_TOO_LARGE", "message": "Event exceeds configured size"}
        source_model = None
        if event_data.data_source_id:
            source_model = db.query(DataSource).filter(
                DataSource.id == event_data.data_source_id,
                DataSource.tenant_id == tenant_id,
            ).first()
            if not source_model or not source_model.enabled:
                return {"index": index, "status": "rejected", "error_code": "SOURCE_UNAVAILABLE", "message": "Data source is missing or disabled"}
            if collector and source_model.collector_id and source_model.collector_id != collector.id:
                return {"index": index, "status": "rejected", "error_code": "SOURCE_NOT_ASSIGNED", "message": "Data source is assigned to another collector"}
        try:
            result = telemetry_normalization_service.normalize(
                format_name=event_data.format,
                raw_message=event_data.raw_message,
                raw_event=event_data.raw_event,
                supplied_normalized=event_data.normalized_event,
                supplied_type=event_data.event_type,
                supplied_severity=event_data.severity,
                supplied_timestamp=event_data.timestamp,
                source=event_data.source,
            )
        except ValueError as exc:
            self._dead_letter(db, tenant_id, batch, collector, source_model, event_data, str(exc))
            return {"index": index, "status": "rejected", "error_code": str(exc), "message": "Normalization failed"}
        if source_model and result.quality_score < source_model.minimum_quality_score:
            self._dead_letter(db, tenant_id, batch, collector, source_model, event_data, "QUALITY_THRESHOLD")
            return {"index": index, "status": "rejected", "error_code": "QUALITY_THRESHOLD", "message": "Event quality is below source policy"}
        content_fingerprint = self._fingerprint(event_data, result.timestamp)
        duplicate = db.query(SecurityEvent).filter(
            SecurityEvent.tenant_id == tenant_id,
            SecurityEvent.data_source_id == event_data.data_source_id,
            (
                (SecurityEvent.source_event_id == event_data.source_event_id)
                if event_data.source_event_id
                else (SecurityEvent.idempotency_key == event_data.idempotency_key)
                if event_data.idempotency_key
                else (SecurityEvent.content_fingerprint == content_fingerprint)
            ),
        ).first()
        if duplicate:
            if source_model:
                source_model.duplicate_count += 1
            return {"index": index, "status": "duplicate", "duplicate_of": duplicate.id}
        event = SecurityEvent(
            tenant_id=tenant_id,
            collector_id=collector.id if collector else None,
            data_source_id=event_data.data_source_id,
            batch_id=batch.id,
            source_event_id=event_data.source_event_id,
            idempotency_key=event_data.idempotency_key,
            content_fingerprint=content_fingerprint,
            source=event_data.source,
            source_type=source_model.source_type if source_model else event_data.format,
            vendor=source_model.vendor if source_model else None,
            product=source_model.product if source_model else None,
            parser_name=result.parser_name,
            parser_version=result.parser_version,
            event_category=result.normalized["category_name"],
            event_class=result.normalized["class_name"],
            event_type=result.event_type,
            raw_event=event_data.raw_event,
            normalized_event=result.normalized,
            severity=result.severity,
            timestamp=result.timestamp,
            original_offset=result.original_offset,
            processing_status="accepted",
            data_quality_score=result.quality_score,
            data_quality_reasons=result.quality_reasons,
            normalization_warnings=result.warnings,
        )
        try:
            with db.begin_nested():
                db.add(event)
                db.flush()
        except IntegrityError:
            duplicate = db.query(SecurityEvent).filter(
                SecurityEvent.tenant_id == tenant_id,
                SecurityEvent.content_fingerprint == content_fingerprint,
            ).first()
            return {"index": index, "status": "duplicate", "duplicate_of": duplicate.id if duplicate else None}
        if source_model:
            now = get_utc_now()
            source_model.accepted_count += 1
            source_model.quality_score_total += result.quality_score
            source_model.last_event_at = result.timestamp
            source_model.last_received_at = now
            source_model.last_successful_parse_at = now
            source_model.ingestion_lag_seconds = max(0, (now - ensure_utc(result.timestamp)).total_seconds())
            INGESTION_LAG.observe(source_model.ingestion_lag_seconds)
            source_model.health_status = "healthy"
        INGESTION_QUALITY.observe(result.quality_score)
        return {"index": index, "status": "accepted", "event_id": event.id}

    @staticmethod
    def _fingerprint(event: SecurityEventCreate, timestamp: Any) -> str:
        raw = event.raw_event or {}
        vendor_record = raw.get("record_number") or raw.get("RecordNumber")
        vendor_event = raw.get("event_id") or raw.get("EventID")
        image = raw.get("Image") or raw.get("process")
        command = raw.get("CommandLine") or raw.get("command_line") or raw.get("command")
        # The legacy route historically identified Windows records from these
        # stable vendor fields. Preserve that exact identity without fuzzy or
        # time-window similarity matching.
        source_identity = (
            {"record_number": str(vendor_record)}
            if vendor_record is not None
            else {"event_id": vendor_event, "image": image, "command": command}
            if vendor_event is not None and (image is not None or command is not None)
            else {"raw": raw, "raw_message": event.raw_message}
        )
        identity = {
            "source": event.source, "event_type": event.event_type.value,
            "source_event_id": event.source_event_id, "idempotency_key": event.idempotency_key,
            "timestamp": ensure_utc(timestamp).isoformat(), "identity": source_identity,
        }
        return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

    @staticmethod
    def _dead_letter(db, tenant_id, batch, collector, source_model, event_data, code) -> None:
        db.add(TelemetryFailure(
            tenant_id=tenant_id,
            collector_id=collector.id if collector else None,
            data_source_id=source_model.id if source_model else event_data.data_source_id,
            batch_id=batch.id,
            stage="normalization",
            error_code=code[:80],
            safe_error="Telemetry event could not be normalized",
            payload={"source": event_data.source, "format": event_data.format},
            state="dead_letter",
        ))
        INGESTION_DEAD_LETTER.labels("normalization", code[:80]).inc()
        if source_model:
            source_model.rejected_count += 1
            source_model.last_failure_at = get_utc_now()
            source_model.health_status = "degraded"

    @staticmethod
    def _dispatch(event_ids: list[str]) -> None:
        from src.workers.tasks import process_ingested_event
        for event_id in event_ids:
            process_ingested_event.delay(event_id)


telemetry_ingestion_service = TelemetryIngestionService()
