from __future__ import annotations

import json

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from sqlalchemy.orm import Session

from src.api.deps import get_db
from src.core.config import get_settings
from src.core.crypto import decrypt_bytes
from src.core.permissions import Permission, membership_permissions, require_permission
from src.models.sqlalchemy import (
    IOC,
    IOCBulkActionJob,
    IOCHuntJob,
    IOCImportJob,
    IOCImportRowResult,
    IOCReportJob,
    IOCResponseRecommendation,
    IOCReviewAssignment,
    IOCReviewHistory,
    IOCSighting,
    IOCWatchlist,
    IOCWatchlistMember,
    SensitiveActionApproval,
    ThreatSourceCredential,
    ThreatSyncConfiguration,
    ThreatSyncJob,
    User,
)
from src.services.audit_management_service import LocalAuditArtifactStorage
from src.services.audit_service import audit_service
from src.services.ioc_commercial_service import IOCCommercialError, ioc_commercial_service


router = APIRouter(prefix="/ioc-commercial", tags=["IOC Commercial"])


def _ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    return forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else None)


def _raise(exc: IOCCommercialError, status_code: int = 422):
    raise HTTPException(status_code=status_code, detail={"error_code": exc.code, "message": exc.message}) from exc


@router.get("/sources")
def list_sources(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_SOURCES_VIEW)),
):
    rows = db.query(ThreatSourceCredential).filter_by(tenant_id=user.tenant_id).order_by(ThreatSourceCredential.provider, ThreatSourceCredential.name).all()
    return {"items": [ioc_commercial_service.credential_public(row) for row in rows], "total": len(rows)}


@router.post("/sources", status_code=201)
def create_source(
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_SOURCES_MANAGE)),
):
    try:
        row = ioc_commercial_service.create_credential(db, user, payload)
    except IOCCommercialError as exc:
        _raise(exc)
    audit_service.record(
        db, action="threat_source_created", user=user, resource_type="threat_source",
        resource_id=row.id, ip_address=_ip(request),
        details={"provider": row.provider, "fingerprint": row.credential_fingerprint[:16]},
    )
    return ioc_commercial_service.credential_public(row)


@router.post("/sources/{source_id}/rotate")
def rotate_source(
    source_id: str,
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_SOURCES_MANAGE)),
):
    try:
        row = ioc_commercial_service.rotate_credential(db, user.tenant_id, source_id, user.id, payload.get("credentials") or {})
    except IOCCommercialError as exc:
        _raise(exc)
    audit_service.record(
        db, action="threat_source_credential_rotated", user=user, resource_type="threat_source",
        resource_id=row.id, ip_address=_ip(request),
        details={"provider": row.provider, "fingerprint": row.credential_fingerprint[:16], "key_version": row.encryption_key_version},
    )
    return ioc_commercial_service.credential_public(row)


@router.post("/sources/{source_id}/test")
def test_source(
    source_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_SOURCES_TEST)),
):
    try:
        result = ioc_commercial_service.test_credential(db, user.tenant_id, source_id)
    except IOCCommercialError as exc:
        audit_service.record(
            db, action="threat_source_connection_tested", user=user, resource_type="threat_source",
            resource_id=source_id, status="failure", failure_reason=exc.code,
            ip_address=_ip(request), details={"connected": False},
        )
        _raise(exc, 502)
    audit_service.record(
        db, action="threat_source_connection_tested", user=user, resource_type="threat_source",
        resource_id=source_id, ip_address=_ip(request), details={"connected": True},
    )
    return result


@router.patch("/sources/{source_id}")
def update_source(
    source_id: str,
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_SOURCES_MANAGE)),
):
    try:
        row = ioc_commercial_service.require_credential(db, user.tenant_id, source_id)
        if "base_url" in payload:
            row.base_url = ioc_commercial_service.validate_external_url(str(payload["base_url"]))
        if "status" in payload and payload["status"] in {"active", "disabled"}:
            row.status = payload["status"]
        if "name" in payload:
            row.name = str(payload["name"]).strip()[:150]
        row.updated_by = user.id
        db.commit()
        db.refresh(row)
    except IOCCommercialError as exc:
        _raise(exc)
    audit_service.record(
        db, action="threat_source_updated", user=user, resource_type="threat_source",
        resource_id=row.id, ip_address=_ip(request), details={"status": row.status},
    )
    return ioc_commercial_service.credential_public(row)


@router.delete("/sources/{source_id}", status_code=204)
def delete_source(
    source_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_SOURCES_MANAGE)),
):
    try:
        row = ioc_commercial_service.require_credential(db, user.tenant_id, source_id)
    except IOCCommercialError as exc:
        _raise(exc, 404)
    provider = row.provider
    db.delete(row)
    db.commit()
    audit_service.record(
        db, action="threat_source_deleted", user=user, resource_type="threat_source",
        resource_id=source_id, ip_address=_ip(request), details={"provider": provider},
    )
    return None


@router.get("/sync/configurations")
def list_sync_configurations(
    provider: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_SOURCES_VIEW)),
):
    query = db.query(ThreatSyncConfiguration).filter_by(tenant_id=user.tenant_id)
    if provider:
        query = query.filter(ThreatSyncConfiguration.provider == provider)
    rows = query.order_by(ThreatSyncConfiguration.created_at.desc()).all()
    return {"items": [{
        "id": row.id, "provider": row.provider, "name": row.name,
        "credential_id": row.credential_id, "api_root": row.api_root,
        "collection_id": row.collection_id, "settings": row.settings,
        "safe_cursor": row.safe_cursor, "schedule_seconds": row.schedule_seconds,
        "enabled": row.enabled, "next_run_at": row.next_run_at,
    } for row in rows], "total": len(rows)}


@router.post("/sync/configurations", status_code=201)
def create_sync_configuration(
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_SOURCES_MANAGE)),
):
    provider = str(payload.get("provider") or "").lower()
    required = Permission.TAXII_MANAGE.value if provider == "taxii" else Permission.MISP_MANAGE.value
    if required not in membership_permissions(db, user):
        raise HTTPException(403, detail={"error_code": "PERMISSION_DENIED", "message": "Provider configuration permission is required"})
    try:
        row = ioc_commercial_service.create_sync_configuration(db, user, payload)
    except IOCCommercialError as exc:
        _raise(exc)
    audit_service.record(
        db, action=f"{row.provider}_configuration_created", user=user,
        resource_type="threat_sync_configuration", resource_id=row.id,
        ip_address=_ip(request), details={"provider": row.provider, "enabled": row.enabled},
    )
    return {"id": row.id, "provider": row.provider, "name": row.name, "enabled": row.enabled}


@router.post("/sync/configurations/{configuration_id}/run", status_code=202)
def start_sync(
    configuration_id: str,
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_SYNC)),
):
    config = db.query(ThreatSyncConfiguration).filter_by(id=configuration_id, tenant_id=user.tenant_id).first()
    specific = Permission.TAXII_SYNC.value if config and config.provider == "taxii" else Permission.MISP_SYNC.value
    if specific not in membership_permissions(db, user):
        raise HTTPException(403, detail={"error_code": "PERMISSION_DENIED", "message": "Provider synchronization permission is required"})
    try:
        row = ioc_commercial_service.start_sync(db, user, configuration_id, str(payload.get("direction") or "pull"))
    except IOCCommercialError as exc:
        _raise(exc, 409)
    from src.workers.tasks import process_threat_sync
    process_threat_sync.delay(row.id, user.tenant_id)
    audit_service.record(
        db, action=f"{row.provider}_sync_requested", user=user, resource_type="threat_sync_job",
        resource_id=row.id, ip_address=_ip(request), details={"direction": row.direction},
    )
    return {"id": row.id, "status": row.status, "provider": row.provider}


@router.get("/sync/jobs")
def list_sync_jobs(
    provider: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_SYNC)),
):
    query = db.query(ThreatSyncJob).filter_by(tenant_id=user.tenant_id)
    if provider:
        query = query.filter(ThreatSyncJob.provider == provider)
    rows = query.order_by(ThreatSyncJob.created_at.desc()).limit(200).all()
    return {"items": [{
        "id": row.id, "configuration_id": row.configuration_id,
        "provider": row.provider, "direction": row.direction, "status": row.status,
        "progress": row.progress, "counts": row.counts, "failure_code": row.failure_code,
        "failure_details": row.failure_details, "created_at": row.created_at,
        "started_at": row.started_at, "completed_at": row.completed_at,
    } for row in rows], "total": len(rows)}


@router.post("/sync/jobs/{job_id}/cancel")
def cancel_sync(
    job_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_SYNC)),
):
    row = db.query(ThreatSyncJob).filter_by(id=job_id, tenant_id=user.tenant_id).first()
    if not row:
        raise HTTPException(404, detail={"error_code": "TAXII_SYNC_FAILED", "message": "Synchronization job not found"})
    row.cancellation_requested = True
    db.commit()
    audit_service.record(db, action=f"{row.provider}_sync_cancelled", user=user, resource_type="threat_sync_job", resource_id=row.id, ip_address=_ip(request))
    return {"id": row.id, "status": "cancellation_requested"}


@router.post("/imports", status_code=201)
async def upload_import(
    file: UploadFile = File(...),
    format_name: str = Form(...),
    options_json: str = Form("{}"),
    request: Request = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_IMPORT)),
):
    settings = get_settings()
    payload = bytearray()
    while chunk := await file.read(1024 * 1024):
        payload.extend(chunk)
        if len(payload) > settings.IOC_BULK_IMPORT_MAX_BYTES:
            raise HTTPException(413, detail={"error_code": "IOC_IMPORT_INVALID", "message": "Import exceeds configured size limit"})
    try:
        options = json.loads(options_json)
        row = ioc_commercial_service.create_import_job(db, user, file.filename or "import", format_name, bytes(payload), options)
    except (ValueError, IOCCommercialError) as exc:
        if isinstance(exc, IOCCommercialError):
            _raise(exc)
        raise HTTPException(422, detail={"error_code": "IOC_IMPORT_INVALID", "message": "Import options are invalid"}) from exc
    from src.workers.tasks import process_ioc_import
    process_ioc_import.delay(row.id, user.tenant_id)
    audit_service.record(
        db, action="ioc_import_uploaded", user=user, resource_type="ioc_import_job",
        resource_id=row.id, ip_address=_ip(request), details={"format": row.format, "checksum": row.artifact_checksum, "size": len(payload)},
    )
    return {"id": row.id, "status": row.status, "format": row.format, "expires_at": row.expires_at}


@router.get("/imports")
def list_imports(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_IMPORT)),
):
    rows = db.query(IOCImportJob).filter_by(tenant_id=user.tenant_id).order_by(IOCImportJob.created_at.desc()).limit(200).all()
    return {"items": [{
        "id": row.id, "format": row.format, "original_filename": row.original_filename,
        "status": row.status, "dry_run": row.dry_run, "counts": row.counts,
        "progress": row.progress, "error_code": row.error_code,
        "expires_at": row.expires_at, "created_at": row.created_at,
    } for row in rows], "total": len(rows)}


@router.get("/imports/{job_id}/rows")
def import_rows(
    job_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_IMPORT)),
):
    if not db.query(IOCImportJob.id).filter_by(id=job_id, tenant_id=user.tenant_id).first():
        raise HTTPException(404, detail={"error_code": "IOC_IMPORT_NOT_READY", "message": "Import job not found"})
    query = db.query(IOCImportRowResult).filter_by(tenant_id=user.tenant_id, job_id=job_id)
    total = query.count()
    rows = query.order_by(IOCImportRowResult.row_number).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [{
        "row_number": row.row_number, "status": row.status, "ioc_id": row.ioc_id,
        "error_code": row.error_code, "safe_details": row.safe_details,
    } for row in rows], "total": total, "page": page, "page_size": page_size}


@router.post("/imports/{job_id}/confirm", status_code=202)
def confirm_import(
    job_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_IMPORT)),
):
    original = db.query(IOCImportJob).filter_by(id=job_id, tenant_id=user.tenant_id).first()
    if not original or original.status != "validated" or not original.dry_run:
        raise HTTPException(409, detail={"error_code": "IOC_IMPORT_NOT_READY", "message": "Dry-run validation must complete before confirmation"})
    row = IOCImportJob(
        tenant_id=user.tenant_id, format=original.format,
        original_filename=original.original_filename, artifact_key=original.artifact_key,
        artifact_checksum=original.artifact_checksum, encrypted_artifact=True,
        status="uploaded", dry_run=False, options=original.options,
        counts={"valid": 0, "invalid": 0, "duplicates": 0, "created": 0},
        requested_by=user.id, expires_at=original.expires_at,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    from src.workers.tasks import process_ioc_import
    process_ioc_import.delay(row.id, user.tenant_id)
    audit_service.record(db, action="ioc_import_confirmed", user=user, resource_type="ioc_import_job", resource_id=row.id, ip_address=_ip(request), details={"dry_run_job_id": original.id, "checksum": row.artifact_checksum})
    return {"id": row.id, "status": row.status}


@router.post("/imports/{job_id}/cancel")
def cancel_import(
    job_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_IMPORT)),
):
    row = db.query(IOCImportJob).filter_by(id=job_id, tenant_id=user.tenant_id).first()
    if not row:
        raise HTTPException(404, detail={"error_code": "IOC_IMPORT_NOT_READY", "message": "Import job not found"})
    row.cancellation_requested = True
    db.commit()
    audit_service.record(db, action="ioc_import_cancelled", user=user, resource_type="ioc_import_job", resource_id=row.id, ip_address=_ip(request))
    return {"id": row.id, "status": "cancellation_requested"}


@router.post("/bulk-actions", status_code=202)
def create_bulk_action(
    payload: dict,
    request: Request,
    confirmed: bool = Query(False),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_BULK_MANAGE)),
):
    try:
        row = ioc_commercial_service.create_bulk_job(db, user, payload, confirmed)
    except IOCCommercialError as exc:
        _raise(exc, 413)
    if row.status == "pending":
        from src.workers.tasks import process_ioc_bulk_action
        process_ioc_bulk_action.delay(row.id, user.tenant_id)
    audit_service.record(
        db, action="ioc_bulk_action_requested", user=user, resource_type="ioc_bulk_action_job",
        resource_id=row.id, ip_address=_ip(request),
        details={"action": row.action, "count": row.preview.get("requested"), "confirmed": confirmed},
    )
    return {"id": row.id, "status": row.status, "preview": row.preview}


@router.get("/bulk-actions")
def list_bulk_actions(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_BULK_MANAGE)),
):
    rows = db.query(IOCBulkActionJob).filter_by(tenant_id=user.tenant_id).order_by(IOCBulkActionJob.created_at.desc()).limit(200).all()
    return {"items": [{"id": row.id, "action": row.action, "status": row.status, "preview": row.preview, "results": row.results, "progress": row.progress, "created_at": row.created_at} for row in rows], "total": len(rows)}


@router.post("/bulk-actions/{job_id}/confirm", status_code=202)
def confirm_bulk_action(
    job_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_BULK_MANAGE)),
):
    row = db.query(IOCBulkActionJob).filter_by(id=job_id, tenant_id=user.tenant_id).first()
    if not row or row.status != "preview":
        raise HTTPException(409, detail={"error_code": "IOC_IMPORT_NOT_READY", "message": "Bulk preview is not ready for confirmation"})
    row.status = "pending"
    db.commit()
    from src.workers.tasks import process_ioc_bulk_action
    process_ioc_bulk_action.delay(row.id, user.tenant_id)
    audit_service.record(db, action="ioc_bulk_action_confirmed", user=user, resource_type="ioc_bulk_action_job", resource_id=row.id, ip_address=_ip(request), details={"action": row.action, "count": row.preview.get("requested")})
    return {"id": row.id, "status": row.status}


@router.post("/bulk-actions/{job_id}/cancel")
def cancel_bulk_action(
    job_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_BULK_MANAGE)),
):
    row = db.query(IOCBulkActionJob).filter_by(id=job_id, tenant_id=user.tenant_id).first()
    if not row:
        raise HTTPException(404, detail={"error_code": "IOC_IMPORT_NOT_READY", "message": "Bulk action not found"})
    row.cancellation_requested = True
    db.commit()
    audit_service.record(db, action="ioc_bulk_action_cancelled", user=user, resource_type="ioc_bulk_action_job", resource_id=row.id, ip_address=_ip(request))
    return {"id": row.id, "status": "cancellation_requested"}


@router.post("/review/{ioc_id}/assign", status_code=201)
def assign_review(
    ioc_id: str,
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_REVIEW_ASSIGN)),
):
    try:
        row = ioc_commercial_service.assign_reviewer(db, user.tenant_id, ioc_id, str(payload.get("reviewer_id") or ""), user.id, payload.get("due_at"))
    except IOCCommercialError as exc:
        _raise(exc)
    audit_service.record(db, action="ioc_review_assigned", user=user, resource_type="ioc", resource_id=ioc_id, ip_address=_ip(request), details={"reviewer_id": row.reviewer_id, "due_at": str(row.due_at) if row.due_at else None})
    return {"id": row.id, "ioc_id": row.ioc_id, "reviewer_id": row.reviewer_id, "status": row.status, "due_at": row.due_at}


@router.post("/review/{ioc_id}/decision")
def decide_review(
    ioc_id: str,
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_REVIEW)),
):
    try:
        row = ioc_commercial_service.review_decision(db, user, ioc_id, payload)
    except IOCCommercialError as exc:
        _raise(exc, 409)
    audit_service.record(db, action="ioc_review_decided", user=user, resource_type="ioc", resource_id=ioc_id, ip_address=_ip(request), details={"decision": payload.get("action")})
    return {"id": row.id, "review_status": row.review_status, "lifecycle_status": row.lifecycle_status, "risk_score": row.risk_score}


@router.get("/review/{ioc_id}/history")
def review_history(
    ioc_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_REVIEW)),
):
    rows = db.query(IOCReviewHistory).filter_by(tenant_id=user.tenant_id, ioc_id=ioc_id).order_by(IOCReviewHistory.created_at.desc()).all()
    return {"items": [{"id": row.id, "action": row.action, "actor_id": row.actor_id, "comment": row.comment, "revision": row.revision, "before_values": row.before_values, "after_values": row.after_values, "created_at": row.created_at} for row in rows], "total": len(rows)}


@router.get("/watchlists/{watchlist_id}")
def watchlist_detail(
    watchlist_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_WATCHLISTS_VIEW)),
):
    row = db.query(IOCWatchlist).filter_by(id=watchlist_id, tenant_id=user.tenant_id).first()
    if not row:
        raise HTTPException(404, detail={"error_code": "IOC_NOT_FOUND", "message": "Watchlist not found"})
    query = db.query(IOCWatchlistMember, IOC).join(IOC, IOC.id == IOCWatchlistMember.ioc_id).filter(
        IOCWatchlistMember.tenant_id == user.tenant_id, IOCWatchlistMember.watchlist_id == watchlist_id, IOC.tenant_id == user.tenant_id
    )
    total = query.count()
    members = query.order_by(IOCWatchlistMember.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    sightings = db.query(IOCSighting).join(IOCWatchlistMember, IOCWatchlistMember.ioc_id == IOCSighting.ioc_id).filter(
        IOCSighting.tenant_id == user.tenant_id, IOCWatchlistMember.watchlist_id == watchlist_id
    ).count()
    return {"id": row.id, "name": row.name, "description": row.description, "owner_id": row.owner_id, "collaborators": row.collaborators, "tags": row.tags, "policies": row.policies, "tlp": row.tlp, "status": row.status, "match_statistics": {"members": total, "sightings": sightings}, "members": [{"ioc_id": ioc.id, "type": ioc.type.value, "value": ioc.display_value, "risk_score": ioc.risk_score, "lifecycle_status": ioc.lifecycle_status} for _, ioc in members], "page": page, "page_size": page_size, "total": total}


@router.patch("/watchlists/{watchlist_id}")
def update_watchlist(
    watchlist_id: str,
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_WATCHLIST_POLICIES_MANAGE)),
):
    row = db.query(IOCWatchlist).filter_by(id=watchlist_id, tenant_id=user.tenant_id).first()
    if not row:
        raise HTTPException(404, detail={"error_code": "IOC_NOT_FOUND", "message": "Watchlist not found"})
    if "name" in payload:
        row.name = str(payload["name"]).strip()[:255]
    if "description" in payload:
        row.description = str(payload["description"])[:5000]
    if "tags" in payload:
        row.tags = payload["tags"][:100]
    if "collaborators" in payload:
        row.collaborators = payload["collaborators"][:100]
    if "policies" in payload:
        policies = payload["policies"]
        if not isinstance(policies, dict) or len(json.dumps(policies)) > 10000:
            raise HTTPException(422, detail={"error_code": "IOC_WATCHLIST_POLICY_INVALID", "message": "Watchlist policy is invalid"})
        row.policies = policies
    if "status" in payload and payload["status"] in {"active", "paused", "archived"}:
        row.status = payload["status"]
    db.commit()
    audit_service.record(db, action="ioc_watchlist_policy_updated", user=user, resource_type="ioc_watchlist", resource_id=row.id, ip_address=_ip(request), details={"status": row.status})
    return {"id": row.id, "name": row.name, "policies": row.policies, "status": row.status}


@router.get("/hunts")
def list_hunts(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_HUNT)),
):
    rows = db.query(IOCHuntJob).filter_by(tenant_id=user.tenant_id).order_by(IOCHuntJob.created_at.desc()).limit(200).all()
    return {"items": [{"id": row.id, "ioc_id": row.ioc_id, "status": row.status, "query": row.query, "progress": row.progress, "events_scanned": row.events_scanned, "matches_found": row.matches_found, "truncated": row.truncated, "error_code": row.error_code, "created_at": row.created_at, "started_at": row.started_at, "completed_at": row.completed_at} for row in rows], "total": len(rows)}


@router.post("/watchlists/{watchlist_id}/hunt", status_code=202)
def hunt_watchlist(
    watchlist_id: str,
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_HUNTS_MANAGE)),
):
    watchlist = db.query(IOCWatchlist).filter_by(id=watchlist_id, tenant_id=user.tenant_id).first()
    if not watchlist:
        raise HTTPException(404, detail={"error_code": "IOC_NOT_FOUND", "message": "Watchlist not found"})
    hunt_limit = min(
        get_settings().IOC_MAX_WATCHLIST_SIZE,
        get_settings().IOC_BULK_ACTION_MAX_SIZE,
    )
    members = db.query(IOCWatchlistMember.ioc_id).filter_by(
        tenant_id=user.tenant_id, watchlist_id=watchlist_id
    ).limit(hunt_limit + 1).all()
    if len(members) > hunt_limit:
        raise HTTPException(413, detail={"error_code": "IOC_BULK_LIMIT_EXCEEDED", "message": "Watchlist exceeds hunt limit"})
    days = min(max(int(payload.get("days") or 30), 1), get_settings().IOC_HUNT_MAX_DAYS)
    event_limit = min(max(int(payload.get("event_limit") or 10000), 1), get_settings().IOC_HUNT_MAX_EVENTS)
    jobs = [
        IOCHuntJob(
            tenant_id=user.tenant_id, ioc_id=ioc_id, requested_by=user.id,
            query={"days": days, "event_limit": event_limit, "watchlist_id": watchlist_id},
        )
        for (ioc_id,) in members
    ]
    db.add_all(jobs)
    db.commit()
    from src.workers.tasks import run_ioc_hunt
    for row in jobs:
        run_ioc_hunt.delay(row.id, user.tenant_id)
    audit_service.record(db, action="ioc_watchlist_hunt_requested", user=user, resource_type="ioc_watchlist", resource_id=watchlist_id, ip_address=_ip(request), details={"job_count": len(jobs), "days": days, "event_limit": event_limit})
    return {"watchlist_id": watchlist_id, "job_ids": [row.id for row in jobs], "count": len(jobs)}


@router.post("/hunts/{job_id}/retry", status_code=202)
def retry_hunt(
    job_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_HUNTS_MANAGE)),
):
    old = db.query(IOCHuntJob).filter_by(id=job_id, tenant_id=user.tenant_id).first()
    if not old or old.status not in {"failed", "cancelled", "completed"}:
        raise HTTPException(409, detail={"error_code": "IOC_HUNT_NOT_READY", "message": "Hunt cannot be retried"})
    row = IOCHuntJob(tenant_id=user.tenant_id, ioc_id=old.ioc_id, requested_by=user.id, query=old.query)
    db.add(row)
    db.commit()
    db.refresh(row)
    from src.workers.tasks import run_ioc_hunt
    run_ioc_hunt.delay(row.id, user.tenant_id)
    audit_service.record(db, action="ioc_hunt_retried", user=user, resource_type="ioc_hunt", resource_id=row.id, ip_address=_ip(request), details={"original_job_id": old.id})
    return {"id": row.id, "status": row.status}


@router.get("/graph/{ioc_id}")
def relationship_graph(
    ioc_id: str,
    depth: int = Query(2, ge=1),
    min_confidence: int = Query(0, ge=0, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_GRAPH_VIEW)),
):
    try:
        return ioc_commercial_service.graph(db, user.tenant_id, ioc_id, depth, min_confidence)
    except IOCCommercialError as exc:
        _raise(exc, 413 if exc.code == "IOC_RELATIONSHIP_LIMIT_EXCEEDED" else 404)


@router.post("/detections/{ioc_id}", status_code=201)
def generate_detection(
    ioc_id: str,
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_DETECTION_GENERATE)),
):
    try:
        row = ioc_commercial_service.generate_detection(db, user, ioc_id, payload)
    except IOCCommercialError as exc:
        _raise(exc)
    audit_service.record(db, action="ioc_detection_draft_generated", user=user, resource_type="detection_rule", resource_id=row.id, ip_address=_ip(request), details={"ioc_id": ioc_id, "lifecycle_status": row.lifecycle_status})
    return {"id": row.id, "name": row.name, "lifecycle_status": row.lifecycle_status, "enabled": row.enabled}


@router.get("/recommendations")
def list_recommendations(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_RESPONSE_RECOMMEND)),
):
    rows = db.query(IOCResponseRecommendation).filter_by(tenant_id=user.tenant_id).order_by(IOCResponseRecommendation.created_at.desc()).limit(200).all()
    return {"items": [{
        "id": row.id, "ioc_id": row.ioc_id, "action": row.action,
        "target_connector_type": row.target_connector_type, "safe_context": row.safe_context,
        "status": row.status, "approval_id": row.approval_id,
        "expires_at": row.expires_at, "created_at": row.created_at,
    } for row in rows], "total": len(rows)}


@router.post("/recommendations/{ioc_id}", status_code=201)
def create_recommendation(
    ioc_id: str,
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_RESPONSE_RECOMMEND)),
):
    try:
        row = ioc_commercial_service.create_recommendation(db, user, ioc_id, payload)
    except IOCCommercialError as exc:
        _raise(exc)
    audit_service.record(db, action="ioc_response_recommendation_requested", user=user, resource_type="ioc_response_recommendation", resource_id=row.id, ip_address=_ip(request), details={"ioc_id": ioc_id, "action": row.action, "approval_id": row.approval_id})
    return {"id": row.id, "status": row.status, "approval_id": row.approval_id, "expires_at": row.expires_at}


@router.get("/reports")
def list_reports(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_REPORTS_VIEW)),
):
    rows = db.query(IOCReportJob).filter_by(tenant_id=user.tenant_id).order_by(IOCReportJob.created_at.desc()).limit(200).all()
    return {"items": [{"id": row.id, "report_type": row.report_type, "format": row.format, "status": row.status, "manifest": row.manifest, "checksum": row.checksum, "error_code": row.error_code, "expires_at": row.expires_at, "created_at": row.created_at} for row in rows], "total": len(rows)}


@router.post("/reports", status_code=202)
def create_report(
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_REPORTS_EXPORT)),
):
    try:
        row = ioc_commercial_service.create_report(db, user, str(payload.get("report_type") or "executive_summary"), str(payload.get("format") or "json"), payload.get("filters") or {})
    except IOCCommercialError as exc:
        _raise(exc)
    from src.workers.tasks import process_ioc_report
    process_ioc_report.delay(row.id, user.tenant_id)
    audit_service.record(db, action="ioc_report_requested", user=user, resource_type="ioc_report_job", resource_id=row.id, ip_address=_ip(request), details={"report_type": row.report_type, "format": row.format})
    return {"id": row.id, "status": row.status, "expires_at": row.expires_at}


@router.get("/reports/{job_id}/download")
def download_report(
    job_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.IOC_REPORTS_EXPORT)),
):
    row = db.query(IOCReportJob).filter_by(id=job_id, tenant_id=user.tenant_id).first()
    if not row:
        raise HTTPException(404, detail={"error_code": "IOC_REPORT_NOT_FOUND", "message": "Report was not found"})
    if row.status != "completed" or not row.artifact_key:
        raise HTTPException(409, detail={"error_code": "IOC_REPORT_NOT_READY", "message": "Report is not ready"})
    from src.utils.datetime_utils import ensure_utc, get_utc_now
    if ensure_utc(row.expires_at) <= get_utc_now():
        raise HTTPException(410, detail={"error_code": "IOC_REPORT_EXPIRED", "message": "Report has expired"})
    encrypted = LocalAuditArtifactStorage(get_settings().IOC_COMMERCIAL_ARTIFACT_DIRECTORY).read(row.artifact_key)
    payload = decrypt_bytes(encrypted)
    audit_service.record(db, action="ioc_report_downloaded", user=user, resource_type="ioc_report_job", resource_id=row.id, ip_address=_ip(request), details={"checksum": row.checksum})
    media = {"csv": "text/csv", "json": "application/json", "jsonl": "application/x-ndjson", "markdown": "text/markdown", "html": "text/html"}.get(row.format, "application/octet-stream")
    return Response(payload, media_type=media, headers={"Content-Disposition": f'attachment; filename="socluma-ioc-report-{row.id}.{row.format}"', "X-Content-SHA256": row.checksum or ""})
