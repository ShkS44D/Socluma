from fastapi import APIRouter, Depends, HTTPException, Request, status, Query
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import Optional

from src.api.deps import get_db
from src.core.permissions import Permission, membership_permissions, require_permission
from src.models.pydantic import IOC, IOCCreate, IOCUpdate, IOCListResponse
from src.models.sqlalchemy import (
    IndicatorType, User, IOC as IOCModel, IOCSighting, IOCWatchlist,
    IOCWatchlistMember, IOCListEntry, IOCHuntJob,
    ThreatIntelligenceRelationship,
)
from src.services.ioc_service import ioc_service
from src.services.ioc_intelligence_service import IOCDuplicateError, IOCValidationError, ioc_intelligence_service
from src.services.ioc_exchange_service import export_stix_bundle, parse_stix_bundle, validate_sync_url
from src.core.config import get_settings
from src.services.threat_intel_service import threat_intel_service
from src.services.audit_service import audit_service


router = APIRouter(prefix="/iocs", tags=["IOCs"])


def _client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


@router.post("", response_model=IOC, status_code=status.HTTP_201_CREATED)
def create_ioc(
    ioc_data: IOCCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_CREATE)),
):
    try:
        ioc = ioc_service.create_ioc(
            db, current_user.tenant_id, current_user.id, ioc_data
        )
        audit_service.record(
            db,
            action="ioc_created",
            user=current_user,
            resource_type="ioc",
            resource_id=ioc.id,
            ip_address=_client_ip(request),
            details={"value": ioc.value, "type": ioc.type.value},
        )
        return IOC.model_validate(ioc)
    except IOCDuplicateError as e:
        raise HTTPException(status_code=409, detail={"error_code": "IOC_DUPLICATE", "message": str(e)}) from e
    except IOCValidationError as e:
        raise HTTPException(status_code=422, detail={"error_code": "IOC_VALUE_INVALID", "message": str(e)}) from e


@router.get("", response_model=IOCListResponse)
def list_iocs(
    ioc_type: Optional[IndicatorType] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_VIEW)),
):
    items, total = ioc_service.list_iocs(
        db, current_user.tenant_id, ioc_type=ioc_type, search=search, page=page, page_size=page_size
    )
    return IOCListResponse(
        items=[IOC.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/stats", response_model=dict)
def get_ioc_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_VIEW)),
):
    return ioc_service.get_ioc_stats(db, current_user.tenant_id)


@router.post("/stix/import", response_model=dict)
def import_stix(
    payload: dict,
    request: Request,
    dry_run: bool = Query(True),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.STIX_IMPORT)),
):
    try:
        result = parse_stix_bundle(payload)
    except IOCValidationError as exc:
        raise HTTPException(status_code=422, detail={"error_code": "STIX_INVALID", "message": str(exc)}) from exc
    if dry_run:
        return {**result, "created": 0, "duplicates": 0, "dry_run": True}
    created, duplicates = 0, 0
    for item in result["indicators"]:
        try:
            references = [
                str(ref.get("url") or ref.get("source_name") or "")
                for ref in item.pop("source_references", [])
                if isinstance(ref, dict)
            ]
            ioc_service.create_ioc(
                db, current_user.tenant_id, current_user.id,
                IOCCreate(**item, source="stix", source_references=[ref for ref in references if ref]),
            )
            created += 1
        except IOCDuplicateError:
            duplicates += 1
    audit_service.record(
        db, action="stix_imported", user=current_user, resource_type="stix_bundle",
        resource_id=result["bundle_id"], ip_address=_client_ip(request),
        details={"objects": result["object_count"], "created": created, "duplicates": duplicates, "unsupported": len(result["unsupported"])},
    )
    return {**result, "created": created, "duplicates": duplicates, "dry_run": False}


@router.get("/stix/export", response_model=dict)
def export_stix(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.STIX_EXPORT)),
):
    rows = db.query(IOCModel).filter(IOCModel.tenant_id == current_user.tenant_id).all()
    allow_red = Permission.TLP_OVERRIDE.value in membership_permissions(db, current_user)
    try:
        bundle = export_stix_bundle(rows, allow_tlp_red=allow_red)
    except IOCValidationError as exc:
        raise HTTPException(status_code=403, detail={"error_code": "TLP_RESTRICTION_VIOLATION", "message": str(exc)}) from exc
    audit_service.record(
        db, action="stix_exported", user=current_user, resource_type="stix_bundle",
        resource_id=bundle["id"], ip_address=_client_ip(request),
        details={"objects": len(bundle["objects"]), "manifest": bundle["x_triageops_manifest_sha256"]},
    )
    return bundle


@router.post("/sources/validate-url", response_model=dict)
def validate_source_url(
    payload: dict,
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_SOURCES_MANAGE)),
):
    try:
        return {"url": validate_sync_url(str(payload.get("url") or "")), "valid": True}
    except IOCValidationError as exc:
        raise HTTPException(status_code=422, detail={"error_code": "THREAT_SOURCE_CREDENTIAL_INVALID", "message": str(exc)}) from exc


@router.post("/{ioc_id}/hunt", response_model=dict, status_code=202)
def start_historical_hunt(
    ioc_id: str,
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_HUNT)),
):
    ioc = db.query(IOCModel).filter(IOCModel.id == ioc_id, IOCModel.tenant_id == current_user.tenant_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail={"error_code": "IOC_NOT_FOUND", "message": "IOC not found"})
    settings = get_settings()
    days = min(max(int(payload.get("days") or 30), 1), settings.IOC_HUNT_MAX_DAYS)
    event_limit = min(max(int(payload.get("event_limit") or 10_000), 1), settings.IOC_HUNT_MAX_EVENTS)
    job = IOCHuntJob(
        tenant_id=current_user.tenant_id, ioc_id=ioc.id, requested_by=current_user.id,
        query={"days": days, "event_limit": event_limit, "normalized_value": ioc.normalized_value},
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    from src.workers.tasks import run_ioc_hunt
    run_ioc_hunt.delay(job.id, current_user.tenant_id)
    audit_service.record(
        db, action="ioc_hunt_requested", user=current_user, resource_type="ioc_hunt",
        resource_id=job.id, ip_address=_client_ip(request),
        details={"ioc_id": ioc.id, "days": days, "event_limit": event_limit},
    )
    return {"id": job.id, "status": job.status, "query": job.query}


@router.get("/hunts/{job_id}", response_model=dict)
def get_hunt(
    job_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_HUNT)),
):
    job = db.query(IOCHuntJob).filter(IOCHuntJob.id == job_id, IOCHuntJob.tenant_id == current_user.tenant_id).first()
    if not job:
        raise HTTPException(status_code=404, detail={"error_code": "IOC_HUNT_NOT_READY", "message": "IOC hunt not found"})
    return {
        "id": job.id, "ioc_id": job.ioc_id, "status": job.status, "progress": job.progress,
        "events_scanned": job.events_scanned, "matches_found": job.matches_found,
        "truncated": job.truncated, "error_code": job.error_code,
        "created_at": job.created_at, "completed_at": job.completed_at,
    }


@router.post("/hunts/{job_id}/cancel", response_model=dict)
def cancel_hunt(
    job_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_HUNT)),
):
    job = db.query(IOCHuntJob).filter(IOCHuntJob.id == job_id, IOCHuntJob.tenant_id == current_user.tenant_id).first()
    if not job:
        raise HTTPException(status_code=404, detail={"error_code": "IOC_HUNT_NOT_READY", "message": "IOC hunt not found"})
    job.cancellation_requested = True
    db.commit()
    return {"id": job.id, "status": "cancellation_requested"}


@router.get("/review/queue", response_model=dict)
def review_queue(
    queue: str = Query("new"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_REVIEW)),
):
    query = db.query(IOCModel).filter(IOCModel.tenant_id == current_user.tenant_id)
    filters = {
        "new": IOCModel.lifecycle_status == "new",
        "under_review": IOCModel.lifecycle_status == "under_review",
        "high_risk": IOCModel.risk_score >= 70,
        "sighted": IOCModel.internal_sighting_count > 0,
        "failed_enrichment": IOCModel.enrichment_status == "failed",
        "expiring": IOCModel.valid_until.isnot(None),
    }
    if queue in filters:
        query = query.filter(filters[queue])
    total = query.count()
    items = query.order_by(IOCModel.risk_score.desc(), IOCModel.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [IOC.model_validate(item).model_dump(mode="json") for item in items], "total": total, "page": page, "page_size": page_size}


@router.get("/sightings", response_model=dict)
def list_sightings(
    ioc_id: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_SIGHTINGS_VIEW)),
):
    query = db.query(IOCSighting).filter(IOCSighting.tenant_id == current_user.tenant_id)
    if ioc_id:
        query = query.filter(IOCSighting.ioc_id == ioc_id)
    total = query.count()
    rows = query.order_by(IOCSighting.last_observed.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [{
        "id": row.id, "ioc_id": row.ioc_id, "event_id": row.event_id,
        "alert_id": row.alert_id, "incident_id": row.incident_id,
        "matched_field": row.matched_field, "matched_value": row.matched_value,
        "first_observed": row.first_observed, "last_observed": row.last_observed,
        "observation_count": row.observation_count, "false_positive": row.false_positive,
    } for row in rows], "total": total, "page": page, "page_size": page_size}


@router.get("/watchlists", response_model=list[dict])
def list_watchlists(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_WATCHLISTS_VIEW)),
):
    rows = db.query(IOCWatchlist).filter(IOCWatchlist.tenant_id == current_user.tenant_id).order_by(IOCWatchlist.name).all()
    return [{"id": row.id, "name": row.name, "description": row.description, "status": row.status, "tlp": row.tlp, "policies": row.policies, "tags": row.tags} for row in rows]


@router.post("/watchlists", response_model=dict, status_code=201)
def create_watchlist(
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_WATCHLISTS_MANAGE)),
):
    name = str(payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=422, detail={"error_code": "IOC_WATCHLIST_INVALID", "message": "Watchlist name is required"})
    row = IOCWatchlist(
        tenant_id=current_user.tenant_id, name=name, description=payload.get("description"),
        owner_id=current_user.id, tags=payload.get("tags") or [], policies=payload.get("policies") or {},
        tlp=payload.get("tlp") or "TLP:AMBER",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    audit_service.record(db, action="ioc_watchlist_created", user=current_user, resource_type="ioc_watchlist", resource_id=row.id, ip_address=_client_ip(request), details={"name": name})
    return {"id": row.id, "name": row.name, "status": row.status}


@router.post("/watchlists/{watchlist_id}/members/{ioc_id}", response_model=dict, status_code=201)
def add_watchlist_member(
    watchlist_id: str,
    ioc_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_WATCHLISTS_MANAGE)),
):
    watchlist = db.query(IOCWatchlist).filter(
        IOCWatchlist.id == watchlist_id, IOCWatchlist.tenant_id == current_user.tenant_id
    ).first()
    ioc = db.query(IOCModel).filter(
        IOCModel.id == ioc_id, IOCModel.tenant_id == current_user.tenant_id
    ).first()
    if not watchlist or not ioc:
        raise HTTPException(status_code=404, detail={"error_code": "IOC_NOT_FOUND", "message": "Watchlist or IOC not found"})
    existing = db.query(IOCWatchlistMember).filter_by(
        tenant_id=current_user.tenant_id, watchlist_id=watchlist_id, ioc_id=ioc_id
    ).first()
    if existing:
        return {"id": existing.id, "watchlist_id": watchlist_id, "ioc_id": ioc_id}
    member = IOCWatchlistMember(
        tenant_id=current_user.tenant_id, watchlist_id=watchlist_id, ioc_id=ioc_id
    )
    db.add(member)
    db.commit()
    db.refresh(member)
    audit_service.record(
        db, action="ioc_watchlist_member_added", user=current_user,
        resource_type="ioc_watchlist", resource_id=watchlist_id,
        ip_address=_client_ip(request), details={"ioc_id": ioc_id},
    )
    return {"id": member.id, "watchlist_id": watchlist_id, "ioc_id": ioc_id}


@router.delete("/watchlists/{watchlist_id}/members/{ioc_id}", status_code=204)
def remove_watchlist_member(
    watchlist_id: str,
    ioc_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_WATCHLISTS_MANAGE)),
):
    member = db.query(IOCWatchlistMember).filter_by(
        tenant_id=current_user.tenant_id, watchlist_id=watchlist_id, ioc_id=ioc_id
    ).first()
    if not member:
        raise HTTPException(status_code=404, detail={"error_code": "IOC_NOT_FOUND", "message": "Watchlist member not found"})
    db.delete(member)
    db.commit()
    audit_service.record(
        db, action="ioc_watchlist_member_removed", user=current_user,
        resource_type="ioc_watchlist", resource_id=watchlist_id,
        ip_address=_client_ip(request), details={"ioc_id": ioc_id},
    )
    return None


@router.post("/lists", response_model=dict, status_code=201)
def create_list_entry(
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_ALLOWLISTS_MANAGE)),
):
    kind = str(payload.get("list_kind") or "allowlist")
    if kind not in {"allowlist", "warning"}:
        raise HTTPException(status_code=422, detail={"error_code": "IOC_ALLOWLIST_CONFLICT", "message": "List kind must be allowlist or warning"})
    normalized = ioc_intelligence_service.apply_normalization
    scratch = IOCModel(tenant_id=current_user.tenant_id)
    normalized(scratch, payload.get("ioc_type"), payload.get("value"))
    row = IOCListEntry(
        tenant_id=current_user.tenant_id, list_kind=kind, name=str(payload.get("name") or scratch.display_value),
        description=payload.get("description"), ioc_type=scratch.type.value,
        normalized_value=scratch.normalized_value, reason=str(payload.get("reason") or "Analyst decision"),
        source=payload.get("source"), expires_at=payload.get("expires_at"), created_by=current_user.id,
        status="active", scope=payload.get("scope") or "organization", tags=payload.get("tags") or [],
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    audit_service.record(db, action=f"ioc_{kind}_created", user=current_user, resource_type="ioc_list_entry", resource_id=row.id, ip_address=_client_ip(request), details={"ioc_type": row.ioc_type, "scope": row.scope})
    return {"id": row.id, "list_kind": row.list_kind, "normalized_value": row.normalized_value}


@router.get("/lists", response_model=dict)
def list_entries(
    list_kind: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_ALLOWLISTS_VIEW)),
):
    query = db.query(IOCListEntry).filter(IOCListEntry.tenant_id == current_user.tenant_id)
    if list_kind:
        query = query.filter(IOCListEntry.list_kind == list_kind)
    rows = query.order_by(IOCListEntry.created_at.desc()).all()
    return {"items": [{
        "id": row.id, "list_kind": row.list_kind, "name": row.name,
        "ioc_type": row.ioc_type, "normalized_value": row.normalized_value,
        "reason": row.reason, "status": row.status, "scope": row.scope,
        "starts_at": row.starts_at, "expires_at": row.expires_at,
    } for row in rows], "total": len(rows)}


@router.get("/relationships", response_model=dict)
def list_relationships(
    ioc_id: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_RELATIONSHIPS_VIEW)),
):
    query = db.query(ThreatIntelligenceRelationship).filter(
        ThreatIntelligenceRelationship.tenant_id == current_user.tenant_id
    )
    if ioc_id:
        query = query.filter(
            (ThreatIntelligenceRelationship.source_id == ioc_id)
            | (ThreatIntelligenceRelationship.target_id == ioc_id)
        )
    rows = query.order_by(ThreatIntelligenceRelationship.created_at.desc()).limit(1000).all()
    return {"items": [{
        "id": row.id, "relationship_type": row.relationship_type,
        "source_type": row.source_type, "source_id": row.source_id,
        "target_type": row.target_type, "target_id": row.target_id,
        "confidence": row.confidence, "source": row.source,
        "evidence_references": row.evidence_references, "status": row.status,
        "origin": row.origin,
    } for row in rows], "total": len(rows)}


@router.post("/relationships", response_model=dict, status_code=201)
def create_relationship(
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_RELATIONSHIPS_MANAGE)),
):
    relationship_type = str(payload.get("relationship_type") or "").strip().lower()
    source_type = str(payload.get("source_type") or "ioc").strip().lower()
    target_type = str(payload.get("target_type") or "ioc").strip().lower()
    source_id = str(payload.get("source_id") or "").strip()
    target_id = str(payload.get("target_id") or "").strip()
    if not relationship_type or not source_id or not target_id or source_id == target_id:
        raise HTTPException(status_code=422, detail={"error_code": "IOC_RELATIONSHIP_INVALID", "message": "A valid relationship and distinct endpoints are required"})
    for object_type, object_id in ((source_type, source_id), (target_type, target_id)):
        if object_type == "ioc" and not db.query(IOCModel.id).filter(
            IOCModel.id == object_id, IOCModel.tenant_id == current_user.tenant_id
        ).first():
            raise HTTPException(status_code=404, detail={"error_code": "IOC_NOT_FOUND", "message": "Related IOC not found"})
    row = ThreatIntelligenceRelationship(
        tenant_id=current_user.tenant_id, relationship_type=relationship_type,
        source_type=source_type, source_id=source_id, target_type=target_type,
        target_id=target_id, confidence=min(max(int(payload.get("confidence") or 50), 0), 100),
        first_seen=payload.get("first_seen"), last_seen=payload.get("last_seen"),
        created_by=current_user.id, source=payload.get("source"),
        evidence_references=payload.get("evidence_references") or [],
        origin=payload.get("origin") or "analyst_created",
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail={"error_code": "IOC_RELATIONSHIP_CONFLICT", "message": "Relationship already exists"}) from exc
    db.refresh(row)
    audit_service.record(
        db, action="ioc_relationship_created", user=current_user,
        resource_type="threat_intelligence_relationship", resource_id=row.id,
        ip_address=_client_ip(request),
        details={"relationship_type": relationship_type, "source_type": source_type, "target_type": target_type},
    )
    return {"id": row.id, "relationship_type": row.relationship_type}


@router.post("/{ioc_id}/merge", response_model=IOC)
def merge_ioc(
    ioc_id: str,
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_MERGE)),
):
    source_id = str(payload.get("source_ioc_id") or "").strip()
    reason = str(payload.get("reason") or "").strip()
    try:
        merged = ioc_service.merge_iocs(
            db, current_user.tenant_id, ioc_id, source_id, reason
        )
    except IOCValidationError as exc:
        raise HTTPException(status_code=422, detail={"error_code": "IOC_MERGE_CONFLICT", "message": str(exc)}) from exc
    except ValueError as exc:
        raise HTTPException(status_code=404, detail={"error_code": "IOC_NOT_FOUND", "message": str(exc)}) from exc
    audit_service.record(
        db, action="ioc_merged", user=current_user, resource_type="ioc",
        resource_id=ioc_id, ip_address=_client_ip(request),
        details={"source_ioc_id": source_id, "reason": reason},
    )
    return IOC.model_validate(merged)


@router.get("/{ioc_id}", response_model=IOC)
def get_ioc(
    ioc_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_VIEW)),
):
    try:
        ioc = ioc_service.get_ioc_by_id(db, current_user.tenant_id, ioc_id)
        return IOC.model_validate(ioc)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e


@router.post("/{ioc_id}/enrich", response_model=list[dict])
def enrich_ioc(
    ioc_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_ENRICH)),
):
    try:
        ioc = ioc_service.get_ioc_by_id(db, current_user.tenant_id, ioc_id)
        results = threat_intel_service.enrich_ioc(db, ioc)
        audit_service.record(
            db,
            action="ioc_enriched",
            user=current_user,
            resource_type="ioc",
            resource_id=ioc.id,
            ip_address=_client_ip(request),
        )
        return results
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e


@router.patch("/{ioc_id}", response_model=IOC)
def update_ioc(
    ioc_id: str,
    update_data: IOCUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_UPDATE)),
):
    try:
        ioc = ioc_service.update_ioc(
            db, current_user.tenant_id, ioc_id, update_data
        )
        audit_service.record(
            db,
            action="ioc_updated",
            user=current_user,
            resource_type="ioc",
            resource_id=ioc.id,
            ip_address=_client_ip(request),
        )
        return IOC.model_validate(ioc)
    except IOCValidationError as e:
        raise HTTPException(status_code=409, detail={"error_code": "IOC_STATE_INVALID", "message": str(e)}) from e
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e


@router.delete("/{ioc_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_ioc(
    ioc_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.IOC_DELETE)),
):
    try:
        ioc_service.delete_ioc(db, current_user.tenant_id, ioc_id)
        audit_service.record(
            db,
            action="ioc_deleted",
            user=current_user,
            resource_type="ioc",
            resource_id=ioc_id,
            ip_address=_client_ip(request),
        )
        return None
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
