from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status, Query, Header, Body
from sqlalchemy import asc, desc
from sqlalchemy.orm import Session, joinedload
from typing import Optional
from pydantic import BaseModel
from src.api.deps import get_db, get_current_user, require_roles
from src.models.sqlalchemy import (
    User, 
    AlertSource, 
    Alert, 
    Severity, 
    AlertStatus, 
    AlertSourceType,
    UserRole,
    Incident,
    IOC
)
from src.models.pydantic import (
    AlertCreate, 
    Alert as AlertResponse, 
    AlertListResponse,
    Incident as IncidentResponse,
    IOC as IOCResponse,
    AlertWithRule
)
from src.utils.ocsf_normalizer import normalize_alert
from src.utils.datetime_utils import get_utc_now
from src.core.logging import logger
from src.workers.tasks import process_alert_for_incident
from src.core.config import get_settings
from src.services.incident_service import incident_service
from src.services.audit_service import audit_service
from src.core.security import verify_api_key
from src.services.source_service import source_service
from src.services.ioc_service import ioc_service
from src.api.openapi_examples import ALERT_CREATE_EXAMPLES
from src.core.observability import ALERTS_CREATED
from src.core.validation import validate_uuid


router = APIRouter(prefix="/alerts", tags=["Alerts"])
settings = get_settings()


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


def _client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


@router.post("/external", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
def create_alert_external(
    request: Request,
    alert_in: AlertCreate = Body(openapi_examples=ALERT_CREATE_EXAMPLES),
    x_source_name: str = Header(..., alias="X-Source-Name"),
    x_api_key: str = Header(..., alias="X-Api-Key"),
    db: Session = Depends(get_db),
):
    """Create a new alert using external API key authentication"""
    logger.info(f"Creating external alert from source: {x_source_name}")
    
    try:
        source = source_service.authenticate_source(db, x_source_name, x_api_key)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    
    # Normalize raw data
    ocsf_data = normalize_alert(alert_in.raw_data)
    severity = ocsf_data.get("severity", Severity.MEDIUM)
    
    # Create alert
    alert = Alert(
        tenant_id=source.tenant_id,
        source_id=source.id,
        raw_data=alert_in.raw_data,
        ocsf_data=ocsf_data,
        severity=severity,
        status=AlertStatus.OPEN,
        processed_at=get_utc_now()
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    ALERTS_CREATED.labels("external_api").inc()

    if settings.USE_REDIS_MOCK:
        incident = incident_service.process_alert(db, alert)
        logger.info(f"Alert {alert.id} processed synchronously into incident {incident.id}")
    else:
        try:
            process_alert_for_incident.delay(alert.id)
            logger.info(f"Queued background incident processing for alert {alert.id}")
        except Exception:
            logger.exception("Failed to enqueue alert incident processing; processing synchronously", extra={"alert_id": alert.id})
            incident = incident_service.process_alert(db, alert)
            logger.info(f"Alert {alert.id} processed synchronously into incident {incident.id}")

    db.refresh(alert)
    audit_service.record(
        db,
        action="external_alert_created",
        resource_type="alert",
        resource_id=alert.id,
        tenant_id=source.tenant_id,
        ip_address=_client_ip(request),
        details={"source": source.name, "severity": str(alert.severity.value if hasattr(alert.severity, "value") else alert.severity)},
    )
    logger.info(f"External alert created: {alert.id}")
    return alert


@router.post("", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
def create_alert(
    request: Request,
    alert_in: AlertCreate = Body(openapi_examples=ALERT_CREATE_EXAMPLES),
    db: Session = Depends(get_db), 
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))
):
    """Create a new alert"""
    logger.info(f"Creating alert from source: {alert_in.source}")
    
    # Get or create alert source
    source = db.query(AlertSource).filter(
        AlertSource.tenant_id == current_user.tenant_id,
        AlertSource.name == alert_in.source
    ).first()
    
    if not source:
        logger.info(f"Creating new alert source: {alert_in.source}")
        source = AlertSource(
            tenant_id=current_user.tenant_id,
            name=alert_in.source,
            type=AlertSourceType.API,
            is_active=True
        )
        db.add(source)
        db.commit()
        db.refresh(source)
    
    # Normalize raw data
    ocsf_data = normalize_alert(alert_in.raw_data)
    severity = ocsf_data.get("severity", Severity.MEDIUM)
    
    # Create alert
    alert = Alert(
        tenant_id=current_user.tenant_id,
        source_id=source.id,
        raw_data=alert_in.raw_data,
        ocsf_data=ocsf_data,
        severity=severity,
        status=AlertStatus.OPEN,
        processed_at=get_utc_now()
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    ALERTS_CREATED.labels("api").inc()

    if settings.USE_REDIS_MOCK:
        incident = incident_service.process_alert(db, alert)
        logger.info(f"Alert {alert.id} processed synchronously into incident {incident.id}")
    else:
        try:
            process_alert_for_incident.delay(alert.id)
            logger.info(f"Queued background incident processing for alert {alert.id}")
        except Exception:
            logger.exception("Failed to enqueue alert incident processing; processing synchronously", extra={"alert_id": alert.id})
            incident = incident_service.process_alert(db, alert)
            logger.info(f"Alert {alert.id} processed synchronously into incident {incident.id}")

    db.refresh(alert)
    audit_service.record(
        db,
        action="alert_created",
        user=current_user,
        resource_type="alert",
        resource_id=alert.id,
        ip_address=_client_ip(request),
        details={"source": alert_in.source, "severity": str(alert.severity.value if hasattr(alert.severity, "value") else alert.severity)},
    )
    logger.info(f"Alert created: {alert.id}")
    return alert


@router.get("", response_model=AlertListResponse)
def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[Severity] = None,
    status: Optional[AlertStatus] = None,
    sort_by: str = Query("created_at", pattern="^(created_at|severity|status|processed_at)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get list of alerts with pagination and filtering"""
    query = db.query(Alert).filter(Alert.tenant_id == current_user.tenant_id)
    
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    
    # Count total
    total = query.count()
    
    # Pagination with joinedload for detection rule
    skip = (page - 1) * page_size
    sort_map = {
        "created_at": Alert.created_at,
        "severity": Alert.severity,
        "status": Alert.status,
        "processed_at": Alert.processed_at,
    }
    sort_column = sort_map.get(sort_by, Alert.created_at)
    order_clause = asc(sort_column) if sort_order == "asc" else desc(sort_column)
    alerts = query.options(
        joinedload(Alert.detection_rule),
        joinedload(Alert.source),
        joinedload(Alert.event)
    ).order_by(order_clause, Alert.created_at.desc()).offset(skip).limit(page_size).all()
    
    # Convert to AlertWithRule
    from src.models.pydantic import AlertWithRule
    items = [
        AlertWithRule(
            id=alert.id,
            tenant_id=alert.tenant_id,
            source_id=alert.source_id,
            detection_rule_id=alert.detection_rule_id,
            incident_id=alert.incident_id,
            event_id=alert.event_id,
            raw_data=alert.raw_data,
            ocsf_data=alert.ocsf_data,
            risk_score=alert.risk_score,
            severity=alert.severity,
            status=alert.status,
            matched_condition=alert.matched_condition,
            why_matched=alert.why_matched,
            created_at=alert.created_at,
            processed_at=alert.processed_at,
            detection_rule=alert.detection_rule
        )
        for alert in alerts
    ]
    
    return AlertListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/{alert_id}", response_model=AlertWithRule)
def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a single alert by ID"""
    validate_uuid(alert_id, "alert_id")
    alert = db.query(Alert).options(
        joinedload(Alert.detection_rule),
        joinedload(Alert.source),
        joinedload(Alert.event)
    ).filter(
        Alert.id == alert_id,
        Alert.tenant_id == current_user.tenant_id
    ).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    return AlertWithRule(
        id=alert.id,
        tenant_id=alert.tenant_id,
        source_id=alert.source_id,
        detection_rule_id=alert.detection_rule_id,
        incident_id=alert.incident_id,
        event_id=alert.event_id,
        raw_data=alert.raw_data,
        ocsf_data=alert.ocsf_data,
        risk_score=alert.risk_score,
        severity=alert.severity,
        status=alert.status,
        matched_condition=alert.matched_condition,
        why_matched=alert.why_matched,
        created_at=alert.created_at,
        processed_at=alert.processed_at,
        detection_rule=alert.detection_rule
    )


@router.post("/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(
    alert_id: str,
    status_update: AlertStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.RESPONDER))
):
    """Update alert status"""
    validate_uuid(alert_id, "alert_id")
    alert = db.query(Alert).filter(
        Alert.id == alert_id,
        Alert.tenant_id == current_user.tenant_id
    ).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    previous_status = alert.status.value if hasattr(alert.status, "value") else str(alert.status)
    alert.status = status_update.status
    db.commit()
    db.refresh(alert)
    
    audit_service.record(
        db,
        action="alert_status_changed",
        user=current_user,
        resource_type="alert",
        resource_id=alert.id,
        ip_address=_client_ip(request),
        details={
            "previous_status": previous_status,
            "new_status": alert.status.value if hasattr(alert.status, "value") else str(alert.status)
        }
    )
    
    return alert


@router.post("/{alert_id}/create-incident", response_model=IncidentResponse)
def create_incident_from_alert(
    alert_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))
):
    """Create an incident from an alert"""
    validate_uuid(alert_id, "alert_id")
    alert = db.query(Alert).filter(
        Alert.id == alert_id,
        Alert.tenant_id == current_user.tenant_id
    ).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    if alert.incident_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Alert already has an incident"
        )
    
    incident = incident_service.process_alert(db, alert)
    
    audit_service.record(
        db,
        action="incident_created_from_alert",
        user=current_user,
        resource_type="incident",
        resource_id=incident.id,
        ip_address=_client_ip(request),
        details={"alert_id": alert.id}
    )
    
    return incident_service.serialize_incident(incident)


@router.get("/{alert_id}/incident", response_model=Optional[IncidentResponse])
def get_alert_incident(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get incident associated with alert"""
    validate_uuid(alert_id, "alert_id")
    alert = db.query(Alert).filter(
        Alert.id == alert_id,
        Alert.tenant_id == current_user.tenant_id
    ).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    if not alert.incident_id:
        return None
    
    incident = db.query(Incident).filter(
        Incident.id == alert.incident_id,
        Incident.tenant_id == current_user.tenant_id
    ).first()
    
    return incident_service.serialize_incident(incident) if incident else None


@router.get("/{alert_id}/iocs", response_model=list[IOCResponse])
def get_alert_iocs(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get IOCs associated with alert"""
    validate_uuid(alert_id, "alert_id")
    alert = db.query(Alert).filter(
        Alert.id == alert_id,
        Alert.tenant_id == current_user.tenant_id
    ).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    if not alert.incident_id:
        return []
    
    iocs = ioc_service.get_iocs_for_incident(db, current_user.tenant_id, alert.incident_id)
    return [IOCResponse.model_validate(ioc) for ioc in iocs]
