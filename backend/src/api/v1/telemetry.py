from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import timedelta

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from src.api.deps import get_db
from src.core.config import get_settings
from src.core.permissions import Permission, require_permission
from src.models.pydantic import (
    DataSourceCreate, DataSourceResponse, DeadLetterResponse,
    IngestionBatchRequest, SecurityEventCreate,
)
from src.models.sqlalchemy import (
    CollectorGroup, CollectorPolicy, CollectorPolicyVersion, DataSource, EventType,
    SecurityEvent, TelemetryFailure, TelemetryImportJob, User,
)
from src.services.audit_service import audit_service
from src.services.telemetry_ingestion_service import telemetry_ingestion_service
from src.utils.datetime_utils import get_utc_now

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


@router.get("/sources", response_model=list[DataSourceResponse])
def list_sources(db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.DATA_SOURCES_VIEW))):
    return db.query(DataSource).filter(DataSource.tenant_id == user.tenant_id).order_by(DataSource.created_at.desc()).all()


@router.post("/sources", response_model=DataSourceResponse, status_code=status.HTTP_201_CREATED)
def create_source(payload: DataSourceCreate, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.DATA_SOURCES_MANAGE))):
    source = DataSource(tenant_id=user.tenant_id, **payload.model_dump())
    db.add(source)
    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail={"error_code": "SOURCE_KEY_EXISTS", "message": "Source key already exists"}) from exc
    db.refresh(source)
    audit_service.record(db, action="data_source_created", user=user, resource_type="data_source", resource_id=source.id, details={"source_key": source.source_key, "parser": source.parser_name})
    return source


@router.patch("/sources/{source_id}/enabled", response_model=DataSourceResponse)
def set_source_enabled(source_id: str, enabled: bool, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.DATA_SOURCES_MANAGE))):
    source = db.query(DataSource).filter(DataSource.id == source_id, DataSource.tenant_id == user.tenant_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")
    source.enabled = enabled
    source.health_status = "disabled" if not enabled else "unknown"
    db.commit()
    audit_service.record(db, action="data_source_enabled_changed", user=user, resource_type="data_source", resource_id=source.id, details={"enabled": enabled})
    db.refresh(source)
    return source


@router.get("/metrics")
def ingestion_metrics(db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.INGESTION_METRICS_VIEW))):
    rows = db.query(
        func.count(SecurityEvent.id),
        func.avg(SecurityEvent.data_quality_score),
        func.max(SecurityEvent.received_at),
    ).filter(SecurityEvent.tenant_id == user.tenant_id).one()
    states = dict(db.query(TelemetryFailure.state, func.count(TelemetryFailure.id)).filter(
        TelemetryFailure.tenant_id == user.tenant_id,
    ).group_by(TelemetryFailure.state).all())
    return {"events": rows[0], "average_quality": float(rows[1] or 0), "last_received_at": rows[2], "failures": states}


@router.get("/dead-letter", response_model=list[DeadLetterResponse])
def list_dead_letter(db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.DEAD_LETTER_VIEW))):
    return db.query(TelemetryFailure).filter(
        TelemetryFailure.tenant_id == user.tenant_id,
        TelemetryFailure.state == "dead_letter",
    ).order_by(TelemetryFailure.created_at.desc()).limit(500).all()


@router.post("/dead-letter/{failure_id}/replay")
def replay_dead_letter(failure_id: str, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.TELEMETRY_REPLAY))):
    failure = db.query(TelemetryFailure).filter(TelemetryFailure.id == failure_id, TelemetryFailure.tenant_id == user.tenant_id).first()
    if not failure:
        raise HTTPException(status_code=404, detail="Dead-letter item not found")
    if not failure.event_id:
        raise HTTPException(status_code=409, detail={"error_code": "PAYLOAD_REQUIRES_CORRECTION", "message": "Normalization failures must be corrected and re-imported"})
    from src.workers.tasks import process_ingested_event
    failure.state = "replay_queued"
    failure.attempts += 1
    db.commit()
    process_ingested_event.delay(failure.event_id)
    audit_service.record(db, action="telemetry_dead_letter_replayed", user=user, resource_type="telemetry_failure", resource_id=failure.id, details={"event_id": failure.event_id})
    return {"status": "queued", "failure_id": failure.id}


@router.post("/imports", status_code=status.HTTP_202_ACCEPTED)
async def import_events(
    file: UploadFile = File(...),
    format_name: str = Form(..., pattern="^(json|jsonl|csv)$"),
    source: str = Form("file-import"),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.TELEMETRY_IMPORT)),
):
    data = await file.read(get_settings().TELEMETRY_IMPORT_MAX_BYTES + 1)
    if len(data) > get_settings().TELEMETRY_IMPORT_MAX_BYTES:
        raise HTTPException(status_code=413, detail={"error_code": "IMPORT_TOO_LARGE", "message": "Import file exceeds configured limit"})
    try:
        text = data.decode("utf-8-sig")
        if format_name == "json":
            parsed = json.loads(text)
            rows = parsed if isinstance(parsed, list) else [parsed]
        elif format_name == "jsonl":
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        else:
            rows = list(csv.DictReader(io.StringIO(text)))
        if not all(isinstance(row, dict) for row in rows):
            raise ValueError
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, csv.Error) as exc:
        raise HTTPException(status_code=422, detail={"error_code": "INVALID_IMPORT", "message": "Import file could not be parsed"}) from exc
    job = TelemetryImportJob(
        tenant_id=user.tenant_id, created_by_id=user.id, filename=(file.filename or "upload")[:255],
        format=format_name, expires_at=get_utc_now() + timedelta(hours=get_settings().TELEMETRY_IMPORT_EXPIRE_HOURS),
    )
    db.add(job)
    db.flush()
    events = [
        SecurityEventCreate(
            source=source, event_type=EventType.ALERT, raw_event=row,
            source_event_id=str(row.get("event_id")) if row.get("event_id") is not None else None,
        ) for row in rows
    ]
    batch_size = get_settings().INGESTION_MAX_BATCH_EVENTS
    states = []
    for index in range(0, len(events), batch_size):
        batch_request = IngestionBatchRequest(
            batch_id=f"import-{job.id}-{index // batch_size}", events=events[index:index + batch_size],
        )
        batch, _ = telemetry_ingestion_service.ingest_batch(
            db, tenant_id=user.tenant_id, actor_key=f"user:{user.id}", request=batch_request,
        )
        states.append(batch.state)
        job.submitted_count += batch.submitted_count
        job.accepted_count += batch.accepted_count
        job.duplicate_count += batch.duplicate_count
        job.rejected_count += batch.rejected_count
    job.state = "completed" if all(value == "completed" for value in states) else "partial"
    job.completed_at = get_utc_now()
    db.commit()
    audit_service.record(db, action="telemetry_file_imported", user=user, resource_type="telemetry_import", resource_id=job.id, details={"format": format_name, "submitted": job.submitted_count})
    return {"job_id": job.id, "state": job.state, "accepted": job.accepted_count, "duplicates": job.duplicate_count, "rejected": job.rejected_count}


@router.get("/collector-groups")
def list_groups(db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.COLLECTORS_VIEW))):
    return db.query(CollectorGroup).filter(CollectorGroup.tenant_id == user.tenant_id).all()


@router.post("/collector-groups", status_code=201)
def create_group(payload: dict, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.COLLECTOR_GROUPS_MANAGE))):
    name = str(payload.get("name", "")).strip()
    if not name:
        raise HTTPException(status_code=422, detail="Group name is required")
    group = CollectorGroup(tenant_id=user.tenant_id, name=name, normalized_name=name.casefold(), description=payload.get("description"), tags=payload.get("tags", []))
    db.add(group)
    db.commit()
    db.refresh(group)
    return {"id": group.id, "name": group.name, "description": group.description, "tags": group.tags}


@router.get("/collector-policies")
def list_policies(db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.COLLECTOR_POLICIES_VIEW))):
    policies = db.query(CollectorPolicy).filter(CollectorPolicy.tenant_id == user.tenant_id).all()
    return [{"id": p.id, "name": p.name, "description": p.description, "active_version": p.active_version} for p in policies]


@router.post("/collector-policies", status_code=201)
def create_policy(payload: dict, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.COLLECTOR_POLICIES_MANAGE))):
    name = str(payload.get("name", "")).strip()
    configuration = payload.get("configuration") or {}
    if not name or not isinstance(configuration, dict):
        raise HTTPException(status_code=422, detail="Policy name and configuration are required")
    policy = CollectorPolicy(tenant_id=user.tenant_id, name=name, description=payload.get("description"), active_version=1, created_by_id=user.id)
    db.add(policy)
    db.flush()
    canonical = json.dumps(configuration, sort_keys=True, separators=(",", ":"))
    version = CollectorPolicyVersion(
        tenant_id=user.tenant_id, policy_id=policy.id, version=1, status="active",
        configuration=configuration, checksum=hashlib.sha256(canonical.encode()).hexdigest(), created_by_id=user.id,
    )
    db.add(version)
    db.commit()
    return {"id": policy.id, "name": policy.name, "active_version": 1, "checksum": version.checksum}
