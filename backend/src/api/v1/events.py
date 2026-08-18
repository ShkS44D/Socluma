from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status, Body, Request
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any
from datetime import timedelta
from copy import deepcopy
import uuid
import hashlib
import hmac
import json
from datetime import datetime, timezone

from src.api.deps import get_db, get_current_auth_context, AuthContext
from src.core.permissions import Permission, membership_permissions, require_all_permissions, require_permission
from src.api.openapi_examples import EVENT_INGEST_EXAMPLES, SOC_SIMULATION_SCENARIOS
from src.models.pydantic import (
    SecurityEvent, SecurityEventCreate,
    EventAnalysisResponse, IngestionResponse, EventsTodayStats,
    IngestionBatchRequest, IngestionBatchReceipt,
)
from src.models.sqlalchemy import EventType, Severity, User, IngestionReplayNonce, SecurityEvent as SecurityEventModel
from src.core.config import get_settings
from src.services.security_event_service import security_event_service
from src.services.detection_engine import detection_engine
from src.services.log_parser_service import log_parser_service
from src.services.audit_service import audit_service
from src.utils.datetime_utils import ensure_utc, get_utc_now
from src.core.observability import COLLECTOR_EVENTS
from src.core.validation import validate_uuid
from src.services.telemetry_ingestion_service import telemetry_ingestion_service
from src.services.entity_investigation_service import entity_investigation_service
from src.services.websocket_service import NotificationType, broadcast_notification

router = APIRouter(prefix="/events", tags=["Security Events"])


@router.post(
    "/ingest",
    response_model=IngestionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a security event",
    description=(
        "Ingest a security event from a collector or analyst. "
        "Runs detection rules automatically and creates alerts/incidents when matched."
    ),
)
def ingest_event(
    background_tasks: BackgroundTasks,
    event_data: SecurityEventCreate = Body(openapi_examples=EVENT_INGEST_EXAMPLES),
    db: Session = Depends(get_db),
    auth_context: AuthContext = Depends(get_current_auth_context),
):
    tenant_id = auth_context.tenant_id
    ingestion_source = "collector" if auth_context.collector else "user"
    if auth_context.user and Permission.ALERTS_CREATE.value not in membership_permissions(db, auth_context.user):
        raise HTTPException(
            status_code=403,
            detail={"error_code": "PERMISSION_DENIED", "message": "Event ingestion permission is required"},
        )
    
    # Update collector info if authenticated as collector
    if auth_context.collector:
        auth_context.collector.last_seen = get_utc_now()
        auth_context.collector.status = "online"
        
        if auth_context.collector.log_source_id:
            from src.models.sqlalchemy import LogSource
            log_source = db.query(LogSource).filter(
                LogSource.id == auth_context.collector.log_source_id
            ).first()
            if log_source:
                log_source.last_seen = get_utc_now()
                log_source.status = "active"
        normalized = dict(event_data.normalized_event or {})
        normalized.setdefault("collector_id", auth_context.collector.id)
        normalized.setdefault("agent_id", auth_context.collector.id)
        event_data.normalized_event = normalized
    
    legacy_timestamp = ensure_utc(event_data.timestamp) if event_data.timestamp else get_utc_now()
    legacy_fingerprint = telemetry_ingestion_service._fingerprint(event_data, legacy_timestamp)
    event = db.query(SecurityEventModel).filter(
        SecurityEventModel.tenant_id == tenant_id,
        SecurityEventModel.content_fingerprint == legacy_fingerprint,
    ).first()
    event = event or security_event_service._find_existing_event(
        db, tenant_id, event_data.source, event_data.event_type, legacy_timestamp, event_data.raw_event,
    )
    created_new_event = event is None
    if event is None:
        batch_request = IngestionBatchRequest(batch_id=f"legacy-{uuid.uuid4()}", events=[event_data])
        _batch, receipt_items = telemetry_ingestion_service.ingest_batch(
            db, tenant_id=tenant_id,
            actor_key=f"collector:{auth_context.collector.id}" if auth_context.collector else f"user:{auth_context.user.id}",
            request=batch_request, collector=auth_context.collector, dispatch=False,
        )
        item = receipt_items[0]
        if item["status"] == "rejected":
            raise HTTPException(status_code=422, detail={"error_code": item["error_code"], "message": item["message"]})
        event_id = item.get("event_id") or item.get("duplicate_of")
        event = security_event_service.get_event_by_id(db, tenant_id, event_id)
    
    entity_investigation_service.extract_event(db, event)
    analysis_result = detection_engine.analyze_and_process_event(db, tenant_id, event)
    db.refresh(event, attribute_names=["detection_matches"])
    COLLECTOR_EVENTS.labels(ingestion_source).inc()
    
    # Record audit log
    audit_details = {"source": event_data.source, "event_type": event_data.event_type}
    if auth_context.user:
        audit_service.record(
            db,
            action="event_ingested",
            user=auth_context.user,
            tenant_id=tenant_id,
            resource_type="security_event",
            resource_id=event.id,
            details=audit_details
        )
    elif auth_context.collector:
        audit_service.record(
            db,
            action="event_ingested",
            tenant_id=tenant_id,
            resource_type="security_event",
            resource_id=event.id,
            details={**audit_details, "collector_id": auth_context.collector.id}
        )

    if created_new_event:
        background_tasks.add_task(
            broadcast_notification,
            tenant_id,
            NotificationType.NEW_EVENT,
            {"id": event.id, "accepted": 1, "source": ingestion_source},
        )
    
    return IngestionResponse(
        id=event.id,
        tenant_id=event.tenant_id,
        source=event.source,
        event_type=event.event_type,
        raw_event=event.raw_event,
        normalized_event=event.normalized_event,
        severity=event.severity,
        timestamp=event.timestamp,
        processed=analysis_result.processed,
        detection_count=event.detection_count,
        detection_status=event.detection_status,
        detections=analysis_result.matched_rules,
        incident_created=analysis_result.incident_created,
        incident_id=analysis_result.incident_id,
        created_at=event.created_at
    )


@router.post("/ingest/batch", response_model=IngestionBatchReceipt, status_code=status.HTTP_202_ACCEPTED)
def ingest_event_batch(
    payload: IngestionBatchRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    auth_context: AuthContext = Depends(get_current_auth_context),
):
    if auth_context.user and Permission.TELEMETRY_INGEST.value not in membership_permissions(db, auth_context.user):
        raise HTTPException(status_code=403, detail={"error_code": "PERMISSION_DENIED", "message": "Telemetry ingestion permission is required"})
    actor_key = f"collector:{auth_context.collector.id}" if auth_context.collector else f"user:{auth_context.user.id}"
    if auth_context.collector:
        timestamp_header = request.headers.get("x-ingestion-timestamp")
        nonce = request.headers.get("x-ingestion-nonce")
        signature = request.headers.get("x-ingestion-signature")
        if any((timestamp_header, nonce, signature)):
            if not all((timestamp_header, nonce, signature)):
                raise HTTPException(status_code=401, detail={"error_code": "INCOMPLETE_SIGNATURE", "message": "All ingestion signature headers are required"})
            try:
                submitted_at = datetime.fromtimestamp(int(timestamp_header), tz=timezone.utc)
            except (TypeError, ValueError, OSError) as exc:
                raise HTTPException(status_code=401, detail={"error_code": "INVALID_SIGNATURE_TIME", "message": "Signature timestamp is invalid"}) from exc
            if abs((get_utc_now() - submitted_at).total_seconds()) > get_settings().INGESTION_REPLAY_WINDOW_SECONDS:
                raise HTTPException(status_code=401, detail={"error_code": "SIGNATURE_EXPIRED", "message": "Signed request is outside the replay window"})
            if len(nonce) > 100:
                raise HTTPException(status_code=401, detail={"error_code": "INVALID_NONCE", "message": "Nonce is invalid"})
            if db.query(IngestionReplayNonce).filter(
                IngestionReplayNonce.collector_id == auth_context.collector.id,
                IngestionReplayNonce.nonce == nonce,
            ).first():
                raise HTTPException(status_code=409, detail={"error_code": "REPLAY_DETECTED", "message": "Signed request nonce has already been used"})
            token = request.headers.get("authorization", "").split(" ", 1)[-1]
            # Exclude defaults the client did not send, then use Pydantic's
            # normalized JSON representation as the signing contract.
            canonical_body = json.dumps(
                payload.model_dump(mode="json", exclude_unset=True),
                sort_keys=True,
                separators=(",", ":"),
            )
            body_hash = hashlib.sha256(canonical_body.encode()).hexdigest()
            material = f"{timestamp_header}.{nonce}.{payload.batch_id}.{body_hash}".encode()
            expected = hmac.new(token.encode(), material, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                raise HTTPException(status_code=401, detail={"error_code": "INVALID_SIGNATURE", "message": "Signed request verification failed"})
            db.add(IngestionReplayNonce(
                tenant_id=auth_context.tenant_id, collector_id=auth_context.collector.id,
                nonce=nonce, request_fingerprint=body_hash,
                expires_at=get_utc_now() + timedelta(seconds=get_settings().INGESTION_REPLAY_WINDOW_SECONDS),
            ))
            db.flush()
    try:
        batch, items = telemetry_ingestion_service.ingest_batch(
            db,
            tenant_id=auth_context.tenant_id,
            actor_key=actor_key,
            request=payload,
            collector=auth_context.collector,
        )
    except ValueError as exc:
        code = str(exc)
        status_code = 409 if code == "BATCH_ID_CONFLICT" else 413 if "LARGE" in code or "LIMIT" in code else 422
        raise HTTPException(status_code=status_code, detail={"error_code": code, "message": "Batch was not accepted"}) from exc
    replayed = bool(getattr(batch, "_replayed", False))
    if auth_context.user:
        audit_service.record(
            db, action="telemetry_batch_ingested", user=auth_context.user,
            tenant_id=auth_context.tenant_id, resource_type="ingestion_batch", resource_id=batch.id,
            details={"batch_id": payload.batch_id, "submitted": batch.submitted_count, "accepted": batch.accepted_count,
                     "duplicates": batch.duplicate_count, "rejected": batch.rejected_count},
        )
    if not replayed and batch.accepted_count > 0:
        accepted_event_ids = [
            item.get("event_id")
            for item in items
            if item.get("status") == "accepted" and item.get("event_id")
        ]
        background_tasks.add_task(
            broadcast_notification,
            auth_context.tenant_id,
            NotificationType.NEW_EVENT,
            {
                "id": accepted_event_ids[-1] if accepted_event_ids else batch.id,
                "batch_id": batch.batch_key,
                "accepted": batch.accepted_count,
                "submitted": batch.submitted_count,
                "duplicates": batch.duplicate_count,
                "collector_id": auth_context.collector.id if auth_context.collector else None,
            },
        )
    return IngestionBatchReceipt(
        receipt_id=batch.id, batch_id=batch.batch_key, replayed=replayed,
        submitted=batch.submitted_count, accepted=batch.accepted_count,
        duplicates=batch.duplicate_count, rejected=batch.rejected_count,
        items=items, received_at=batch.received_at,
    )


@router.get("/simulate/scenarios", response_model=Dict[str, Any])
def list_simulation_scenarios(
    current_user: User = Depends(require_permission(Permission.DETECTIONS_VIEW)),
):
    """List available SOC attack simulation scenarios for demo."""
    return {
        scenario_id: {
            "name": scenario["name"],
            "description": scenario["description"],
            "event_count": len(scenario["events"]),
        }
        for scenario_id, scenario in SOC_SIMULATION_SCENARIOS.items()
    }


@router.post(
    "/simulate/{scenario_id}",
    response_model=List[IngestionResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Run SOC attack simulation",
    description=(
        "Ingest pre-built attack scenario events through the full pipeline: "
        "Event → Detection → Alert → Incident → IOC → AI Analysis."
    ),
)
def simulate_attack(
    scenario_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ALERTS_CREATE)),
):
    """Run a pre-built SOC attack simulation scenario."""
    scenario = SOC_SIMULATION_SCENARIOS.get(scenario_id)
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown scenario '{scenario_id}'. Available: {list(SOC_SIMULATION_SCENARIOS.keys())}",
        )

    results: List[IngestionResponse] = []
    run_id = str(uuid.uuid4())
    observed_at = get_utc_now()
    run_octets = (int(run_id[0:2], 16), int(run_id[2:4], 16), int(run_id[4:6], 16))
    for index, template in enumerate(scenario["events"]):
        event_payload = deepcopy(template)
        event_payload["timestamp"] = observed_at + timedelta(seconds=index * 30)
        for section in ("raw_event", "normalized_event"):
            event_payload.setdefault(section, {})
            event_payload[section].update({
                "synthetic": True,
                "simulation_run_id": run_id,
                "hostname": f"triageops-sim-{run_id[:8]}",
                "agent_id": f"sim-agent-{run_id[:8]}",
                "source_ip": f"10.{run_octets[0]}.{run_octets[1]}.{max(1, run_octets[2])}",
                "source_host": f"triageops-sim-source-{run_id[:8]}",
                "user": f"synthetic-user-{run_id[:8]}",
            })
        event_data = SecurityEventCreate(**event_payload)
        event = security_event_service.create_event(db, current_user.tenant_id, event_data)
        
        analysis_result = detection_engine.analyze_and_process_event(
            db, current_user.tenant_id, event, allow_external_enrichment=False,
        )
        db.refresh(event, attribute_names=["detection_matches"])
        audit_service.record(
            db,
            action="simulation_event_ingested",
            user=current_user,
            tenant_id=current_user.tenant_id,
            resource_type="security_event",
            resource_id=event.id,
            details={"scenario": scenario_id, "scenario_name": scenario["name"], "simulation_run_id": run_id},
        )
        results.append(IngestionResponse(
            id=event.id,
            tenant_id=event.tenant_id,
            source=event.source,
            event_type=event.event_type,
            raw_event=event.raw_event,
            normalized_event=event.normalized_event,
            severity=event.severity,
            timestamp=event.timestamp,
            processed=analysis_result.processed,
            detection_count=event.detection_count,
            detection_status=event.detection_status,
            detections=analysis_result.matched_rules,
            incident_created=analysis_result.incident_created,
            incident_id=analysis_result.incident_id,
            created_at=event.created_at,
        ))

    return results


@router.get("", response_model=list[SecurityEvent])
def list_events(
    event_type: Optional[EventType] = Query(None),
    severity: Optional[Severity] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    sort_by: str = Query("timestamp", pattern="^(timestamp|created_at|severity|event_type)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ALERTS_VIEW)),
):
    events = security_event_service.list_events(
        db,
        current_user.tenant_id,
        event_type=event_type,
        severity=severity,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    return [SecurityEvent.model_validate(event) for event in events]


@router.get("/stats/today", response_model=EventsTodayStats)
def get_events_today_stats(
    timezone_offset_minutes: int = Query(
        0,
        ge=-840,
        le=840,
        description="Browser timezone offset in minutes, matching JavaScript Date.getTimezoneOffset().",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ALERTS_VIEW)),
):
    now = get_utc_now()
    local_now = now - timedelta(minutes=timezone_offset_minutes)
    local_start_of_day = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    start_of_day = local_start_of_day + timedelta(minutes=timezone_offset_minutes)
    return {
        "count": security_event_service.count_events_since(
            db,
            current_user.tenant_id,
            start_of_day,
        )
    }


@router.get("/{event_id}", response_model=SecurityEvent)
def get_event(
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ALERTS_VIEW)),
):
    validate_uuid(event_id, "event_id")
    try:
        event = security_event_service.get_event_by_id(db, current_user.tenant_id, event_id)
        return SecurityEvent.model_validate(event)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e


@router.post("/{event_id}/analyze", response_model=EventAnalysisResponse, status_code=status.HTTP_200_OK)
def analyze_event(
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_all_permissions(Permission.ALERTS_UPDATE, Permission.TRIAGE_AI_USE)),
):
    validate_uuid(event_id, "event_id")
    try:
        event = security_event_service.get_event_by_id(db, current_user.tenant_id, event_id)
        analysis_result = detection_engine.analyze_and_process_event(db, current_user.tenant_id, event)
        return EventAnalysisResponse(
            event_id=analysis_result.event_id,
            processed=analysis_result.processed,
            matched_rules=analysis_result.matched_rules,
            incident_created=analysis_result.incident_created,
            incident_id=analysis_result.incident_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
