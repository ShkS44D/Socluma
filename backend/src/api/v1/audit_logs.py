from __future__ import annotations

import hashlib
import csv
import io
import json
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from src.api.deps import get_db
from src.core.permissions import Permission, require_permission
from src.models.pydantic import AuditLog as AuditLogResponse
from src.models.sqlalchemy import AuditArchiveJob, AuditExportJob, AuditLegalHold, AuditLog, User
from src.services.audit_management_service import (
    JOB_STATES,
    LocalAuditArtifactStorage,
    audit_management_service,
)
from src.services.audit_service import audit_service
from src.core.config import get_settings
from src.utils.datetime_utils import ensure_utc, get_utc_now


router = APIRouter(prefix="/audit-logs", tags=["Audit logs"])
settings = get_settings()
SORT_FIELDS = {
    "created_at": AuditLog.created_at,
    "sequence_number": AuditLog.sequence_number,
    "action": AuditLog.action,
    "severity": AuditLog.severity,
    "status": AuditLog.status,
}


def _error(code: str, status_code: int) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": code.replace("_", " ").title()})


def build_filtered_query(
    db: Session,
    tenant_id: str,
    search: str | None = None,
    actor_id: str | None = None,
    actor_type: str | None = None,
    action: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    audit_status: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    ip_address: str | None = None,
    request_id: str | None = None,
    correlation_id: str | None = None,
    approval_id: str | None = None,
    retention_class: str | None = None,
    start: datetime | str | None = None,
    end: datetime | str | None = None,
    **_: Any,
):
    if isinstance(start, str):
        start = datetime.fromisoformat(start.replace("Z", "+00:00"))
    if isinstance(end, str):
        end = datetime.fromisoformat(end.replace("Z", "+00:00"))
    if start and end and (ensure_utc(start) > ensure_utc(end) or ensure_utc(end) - ensure_utc(start) > timedelta(days=3660)):
        raise ValueError("AUDIT_EVENT_INVALID")
    query = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id)
    if search:
        if len(search) > 200 or search.count("*") + search.count("%") + search.count("_") > 2:
            raise ValueError("AUDIT_EVENT_INVALID")
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("*", "%")
        term = f"%{escaped}%"
        query = query.filter(or_(
            AuditLog.action.ilike(term, escape="\\"),
            AuditLog.resource_type.ilike(term, escape="\\"),
            AuditLog.resource_id.ilike(term, escape="\\"),
        ))
    fields = (
        (AuditLog.user_id, actor_id), (AuditLog.actor_type, actor_type), (AuditLog.action, action),
        (AuditLog.category, category), (AuditLog.severity, severity), (AuditLog.status, audit_status),
        (AuditLog.resource_type, resource_type), (AuditLog.resource_id, resource_id),
        (AuditLog.ip_address, ip_address), (AuditLog.request_id, request_id),
        (AuditLog.correlation_id, correlation_id), (AuditLog.approval_request_id, approval_id),
        (AuditLog.retention_class, retention_class),
    )
    for field, value in fields:
        if value:
            query = query.filter(field == value)
    if start:
        query = query.filter(AuditLog.created_at >= start)
    if end:
        query = query.filter(AuditLog.created_at <= end)
    return query


def _filters(**values: Any) -> dict[str, Any]:
    return {key: value.isoformat() if isinstance(value, datetime) else value for key, value in values.items() if value is not None}


@router.get("")
def list_logs(
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
    search: str | None = None, actor_id: str | None = None, actor_type: str | None = None,
    action: str | None = None, category: str | None = None, severity: str | None = None,
    audit_status: str | None = Query(None, alias="status"), resource_type: str | None = None,
    resource_id: str | None = None, ip_address: str | None = None, request_id: str | None = None,
    correlation_id: str | None = None, approval_id: str | None = None,
    retention_class: str | None = None, start: datetime | None = None, end: datetime | None = None,
    sort_by: str = Query("created_at", pattern="^(created_at|sequence_number|action|severity|status)$"),
    sort: str = Query("desc", pattern="^(asc|desc)$"), db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_VIEW)),
):
    try:
        query = build_filtered_query(db, current_user.tenant_id, **_filters(
            search=search, actor_id=actor_id, actor_type=actor_type, action=action, category=category,
            severity=severity, audit_status=audit_status, resource_type=resource_type,
            resource_id=resource_id, ip_address=ip_address, request_id=request_id,
            correlation_id=correlation_id, approval_id=approval_id,
            retention_class=retention_class, start=start, end=end,
        ))
    except ValueError:
        raise _error("AUDIT_EVENT_INVALID", status.HTTP_422_UNPROCESSABLE_ENTITY)
    total = query.count()
    column = SORT_FIELDS[sort_by]
    order = column.asc() if sort == "asc" else column.desc()
    rows = query.order_by(order, AuditLog.id.asc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [AuditLogResponse.model_validate(row) for row in rows], "total": total,
        "page": page, "page_size": page_size, "has_more": page * page_size < total,
    }


@router.post("/integrity/verify")
def verify_integrity(
    request: Request, db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_INTEGRITY_VERIFY)),
):
    result = audit_service.verify(db, current_user.tenant_id)
    audit_service.record(
        db, action="audit.integrity.verified", user=current_user, resource_type="audit_chain",
        resource_id=current_user.tenant_id, status="success" if result["status"] == "verified" else "failure",
        severity="critical" if result["status"] == "failed" else "info",
        request_id=getattr(request.state, "request_id", None), details=result,
    )
    return result


@router.get("/retention")
def get_retention(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_VIEW)),
):
    policy = audit_management_service.retention_policy(db, current_user.tenant_id)
    db.commit()
    return audit_management_service.policy_dict(policy) | {
        "minimum_days": settings.AUDIT_RETENTION_MINIMUM_DAYS,
        "maximum_days": settings.AUDIT_RETENTION_MAXIMUM_DAYS,
    }


@router.put("/retention")
def update_retention(
    values: dict[str, Any], db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_RETENTION_MANAGE)),
):
    try:
        policy = audit_management_service.update_retention(db, current_user.tenant_id, current_user, values)
    except ValueError as exc:
        raise _error(str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY)
    return audit_management_service.policy_dict(policy)


@router.get("/legal-holds")
def list_legal_holds(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_LEGAL_HOLD_VIEW)),
):
    return db.query(AuditLegalHold).filter_by(tenant_id=current_user.tenant_id).order_by(
        AuditLegalHold.created_at.desc()
    ).all()


@router.post("/legal-holds", status_code=status.HTTP_201_CREATED)
def create_legal_hold(
    values: dict[str, Any], db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_LEGAL_HOLD_MANAGE)),
):
    try:
        return audit_management_service.create_hold(db, current_user.tenant_id, current_user, values)
    except (KeyError, ValueError):
        raise _error("LEGAL_HOLD_INVALID", status.HTTP_422_UNPROCESSABLE_ENTITY)


@router.post("/legal-holds/{hold_id}/release")
def release_legal_hold(
    hold_id: str, db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_LEGAL_HOLD_MANAGE)),
):
    try:
        return audit_management_service.release_hold(db, current_user.tenant_id, hold_id, current_user)
    except LookupError:
        raise _error("LEGAL_HOLD_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    except RuntimeError:
        raise _error("LEGAL_HOLD_ALREADY_RELEASED", status.HTTP_409_CONFLICT)


@router.post("/archive/run")
def run_archive(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_ARCHIVE_MANAGE)),
):
    try:
        return audit_management_service.run_retention(db, current_user.tenant_id, requested_by_id=current_user.id)
    except Exception:
        raise _error("ARCHIVE_JOB_FAILED", status.HTTP_409_CONFLICT)


@router.get("/archive/jobs")
def list_archive_jobs(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_ARCHIVE_MANAGE)),
):
    return db.query(AuditArchiveJob).filter_by(tenant_id=current_user.tenant_id).order_by(
        AuditArchiveJob.created_at.desc()
    ).limit(100).all()


@router.post("/exports", status_code=status.HTTP_202_ACCEPTED)
def create_export(
    values: dict[str, Any], db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_EXPORT)),
):
    try:
        job, token = audit_management_service.create_export(
            db, current_user.tenant_id, current_user,
            values.get("format", "csv"), values.get("filters") or {},
        )
    except ValueError:
        raise _error("AUDIT_EVENT_INVALID", status.HTTP_422_UNPROCESSABLE_ENTITY)
    count = build_filtered_query(db, current_user.tenant_id, **(job.filters or {})).count()
    if count <= 5000:
        audit_management_service.process_export(db, job.id)
    else:
        from src.workers.tasks import process_audit_export
        process_audit_export.delay(job.id)
    db.refresh(job)
    return {"job": job, "download_token": token}


@router.get("/export")
def legacy_stream_export(
    format: str = Query("csv", pattern="^(csv|json)$"), search: str | None = None,
    action: str | None = None, resource_type: str | None = None,
    audit_status: str | None = Query(None, alias="status"), start: datetime | None = None,
    end: datetime | None = None, db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_EXPORT)),
):
    """Compatibility stream for existing clients; new clients should use export jobs."""
    filters = _filters(search=search, action=action, resource_type=resource_type,
                       audit_status=audit_status, start=start, end=end)
    try:
        query = build_filtered_query(db, current_user.tenant_id, **filters).order_by(AuditLog.sequence_number.asc())
    except ValueError:
        raise _error("AUDIT_EVENT_INVALID", status.HTTP_422_UNPROCESSABLE_ENTITY)
    audit_service.record(
        db, action="export.audit.streamed", user=current_user, resource_type="audit_log",
        details={"format": format, "filters": filters},
    )
    fields = ["id", "created_at", "sequence_number", "actor_type", "user_id", "action",
              "category", "severity", "resource_type", "resource_id", "status", "ip_address",
              "request_id", "correlation_id", "failure_reason", "details"]

    def render_csv() -> str:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for row in query.yield_per(500):
            item = AuditLogResponse.model_validate(row).model_dump(mode="json")
            item["details"] = json.dumps(item.get("details") or {}, separators=(",", ":"))
            writer.writerow({field: item.get(field) for field in fields})
        return output.getvalue()

    def render_json() -> str:
        return json.dumps(
            [AuditLogResponse.model_validate(row).model_dump(mode="json") for row in query.yield_per(500)],
            separators=(",", ":"),
        )

    extension = "json" if format == "json" else "csv"
    return Response(
        render_json() if format == "json" else render_csv(),
        media_type="application/json" if format == "json" else "text/csv",
        headers={"Content-Disposition": f'attachment; filename="vigilantai-audit.{extension}"',
                 "X-Content-Type-Options": "nosniff"},
    )


@router.get("/exports")
def list_exports(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_EXPORT)),
):
    return db.query(AuditExportJob).filter_by(tenant_id=current_user.tenant_id).order_by(
        AuditExportJob.created_at.desc()
    ).limit(100).all()


@router.post("/exports/{job_id}/cancel")
def cancel_export(
    job_id: str, db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_EXPORT)),
):
    job = db.query(AuditExportJob).filter_by(id=job_id, tenant_id=current_user.tenant_id).first()
    if not job:
        raise _error("EXPORT_JOB_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    if job.status not in {"pending", "running"}:
        raise _error("EXPORT_NOT_READY", status.HTTP_409_CONFLICT)
    job.status = "cancelled"
    job.cancelled_at = get_utc_now()
    audit_service.record(db, action="export.audit.cancelled", user=current_user,
                         resource_type="audit_export_job", resource_id=job.id, commit=False)
    db.commit()
    return job


@router.get("/exports/{job_id}/download")
def download_export(
    job_id: str, token: str = Query(..., min_length=20, max_length=200), db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_EXPORT_DOWNLOAD)),
):
    job = db.query(AuditExportJob).filter_by(id=job_id, tenant_id=current_user.tenant_id).first()
    if not job:
        raise _error("EXPORT_JOB_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    if ensure_utc(job.expires_at) <= get_utc_now() or job.status == "expired":
        raise _error("EXPORT_EXPIRED", status.HTTP_410_GONE)
    if job.status != "completed" or not job.artifact_key:
        raise _error("EXPORT_NOT_READY", status.HTTP_409_CONFLICT)
    if not secrets_compare(job.download_token_hash, hashlib.sha256(token.encode()).hexdigest()):
        raise _error("EXPORT_DOWNLOAD_DENIED", status.HTTP_403_FORBIDDEN)
    payload = LocalAuditArtifactStorage(settings.AUDIT_EXPORT_DIRECTORY).read(job.artifact_key)
    content_types = {"csv": "text/csv", "jsonl": "application/x-ndjson", "evidence_zip": "application/zip"}
    extension = {"csv": "csv", "jsonl": "jsonl", "evidence_zip": "zip"}[job.format]
    audit_service.record(db, action="export.audit.downloaded", user=current_user,
                         resource_type="audit_export_job", resource_id=job.id,
                         details={"format": job.format})
    return Response(
        payload, media_type=content_types[job.format],
        headers={"Content-Disposition": f'attachment; filename="vigilantai-audit-{job.id}.{extension}"',
                 "X-Content-Type-Options": "nosniff"},
    )


@router.post("/encryption/rotate")
def rotate_encryption(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ENCRYPTION_ROTATION_EXECUTE)),
):
    try:
        return audit_management_service.rotate_encrypted_fields(db, current_user.tenant_id, current_user)
    except Exception:
        db.rollback()
        raise _error("DECRYPTION_FAILED", status.HTTP_409_CONFLICT)


def secrets_compare(left: str | None, right: str) -> bool:
    import hmac
    return bool(left) and hmac.compare_digest(left, right)
