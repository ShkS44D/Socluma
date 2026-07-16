from fastapi import APIRouter, Depends, HTTPException, Query, status, Body
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any
from datetime import timedelta

from src.api.deps import get_db, get_current_user, get_current_auth_context, AuthContext, require_roles
from src.api.openapi_examples import EVENT_INGEST_EXAMPLES, SOC_SIMULATION_SCENARIOS
from src.models.pydantic import (
    SecurityEvent, SecurityEventCreate,
    EventAnalysisResponse, IngestionResponse, EventsTodayStats
)
from src.models.sqlalchemy import EventType, Severity, User, UserRole
from src.services.security_event_service import security_event_service
from src.services.detection_engine import detection_engine
from src.services.log_parser_service import log_parser_service
from src.services.audit_service import audit_service
from src.utils.datetime_utils import get_utc_now
from src.core.observability import COLLECTOR_EVENTS
from src.core.validation import validate_uuid

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
    event_data: SecurityEventCreate = Body(openapi_examples=EVENT_INGEST_EXAMPLES),
    db: Session = Depends(get_db),
    auth_context: AuthContext = Depends(get_current_auth_context),
):
    tenant_id = auth_context.tenant_id
    ingestion_source = "collector" if auth_context.collector else "user"
    
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
    
    # If normalized event not provided, try to parse raw log
    if not event_data.normalized_event:
        source_type = event_data.source
        parsed = log_parser_service.parse_log(source_type, event_data.raw_event)
        if parsed:
            event_data.normalized_event = parsed
            if "severity" in parsed:
                event_data.severity = parsed["severity"]
            if "event_type" in parsed:
                event_data.event_type = parsed["event_type"]
    
    event = security_event_service.create_event(db, tenant_id, event_data)
    
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


@router.get("/simulate/scenarios", response_model=Dict[str, Any])
def list_simulation_scenarios(
    current_user: User = Depends(get_current_user),
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
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Run a pre-built SOC attack simulation scenario."""
    scenario = SOC_SIMULATION_SCENARIOS.get(scenario_id)
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown scenario '{scenario_id}'. Available: {list(SOC_SIMULATION_SCENARIOS.keys())}",
        )

    results: List[IngestionResponse] = []
    for event_payload in scenario["events"]:
        event_data = SecurityEventCreate(**event_payload)
        event = security_event_service.create_event(db, current_user.tenant_id, event_data)
        
        analysis_result = detection_engine.analyze_and_process_event(db, current_user.tenant_id, event)
        db.refresh(event, attribute_names=["detection_matches"])
        audit_service.record(
            db,
            action="simulation_event_ingested",
            user=current_user,
            tenant_id=current_user.tenant_id,
            resource_type="security_event",
            resource_id=event.id,
            details={"scenario": scenario_id, "scenario_name": scenario["name"]},
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
    current_user: User = Depends(get_current_user),
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
    current_user: User = Depends(get_current_user),
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
    current_user: User = Depends(get_current_user),
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
    current_user: User = Depends(get_current_user),
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
