from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from src.api.deps import get_db
from src.core.config import get_settings
from src.core.permissions import Permission, membership_permissions, require_permission
from src.models.sqlalchemy import (
    Alert, EvidenceBookmark, EvidenceSnapshot, EventEntity, Incident,
    InvestigationAttachment, InvestigationCollaborator, InvestigationNoteRevision, InvestigationResource,
    InvestigationWorkspace, InvestigationWorkspaceNote, OrganizationMembership,
    SavedSearch, SavedSearchRevision, ScheduledSearch, SearchEntity, SearchHistory,
    SearchExportJob, SearchTemplate, SecurityEvent, SharedSearchReference, User,
)
from src.services.audit_service import audit_service
from src.services.entity_investigation_service import entity_investigation_service
from src.services.search_query_service import SearchQueryError, field_catalog, search_query_parser
from src.services.search_service import search_service
from src.services.search_export_service import search_export_service
from src.utils.datetime_utils import get_utc_now

router = APIRouter(tags=["Search and Investigations"])


class SearchRequest(BaseModel):
    query: str = Field(default="", max_length=4000)
    resource_scope: str = Field(default="events", pattern="^(events|alerts|incidents|entities)$")
    start: datetime | None = None
    end: datetime | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1)
    sort_field: str = "timestamp"
    sort_direction: str = Field(default="desc", pattern="^(asc|desc)$")
    record_history: bool = True


class SavedSearchRequest(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    description: str | None = Field(default=None, max_length=2000)
    query: str = Field(min_length=1, max_length=4000)
    resource_scope: str = Field(pattern="^(events|alerts|incidents|entities)$")
    time_range: dict[str, Any] = Field(default_factory=lambda: {"mode": "relative", "value": "24h"})
    sort: dict[str, str] = Field(default_factory=lambda: {"field": "timestamp", "direction": "desc"})
    visibility: str = Field(default="private", pattern="^(private|team|organization)$")
    tags: list[str] = Field(default_factory=list, max_length=20)
    pinned: bool = False


class InvestigationCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=5000)
    linked_incident_id: str | None = None


class ResourceCreate(BaseModel):
    resource_type: str = Field(pattern="^(event|alert|incident|entity|saved_search)$")
    resource_id: str
    label: str | None = Field(default=None, max_length=255)


class BookmarkCreate(ResourceCreate):
    event_timestamp: datetime | None = None
    analyst_comment: str | None = Field(default=None, max_length=2000)
    relevance: str = Field(default="supporting", pattern="^(supporting|contradicting|context)$")
    display_order: int = Field(default=0, ge=0, le=10000)


class NoteCreate(BaseModel):
    content: str = Field(min_length=1, max_length=10000)
    tags: list[str] = Field(default_factory=list, max_length=20)
    pinned: bool = False


class SearchExportRequest(BaseModel):
    query: str = Field(default="", max_length=4000)
    resource_scope: str = Field(default="events", pattern="^(events|alerts|incidents|entities)$")
    start: datetime | None = None
    end: datetime | None = None
    sort_field: str = "timestamp"
    sort_direction: str = Field(default="desc", pattern="^(asc|desc)$")
    format: str = Field(default="csv", pattern="^(csv|jsonl|evidence_zip)$")


class AttachmentMetadataCreate(BaseModel):
    display_name: str = Field(min_length=1, max_length=255)
    content_type: str = Field(min_length=1, max_length=100)
    size_bytes: int = Field(ge=1)
    sha256: str = Field(pattern="^[0-9a-fA-F]{64}$")
    classification: str = Field(default="confidential", pattern="^(internal|confidential|restricted)$")


def _permissions(db: Session, user: User) -> set[str]:
    return membership_permissions(db, user)


def _query_error(exc: SearchQueryError):
    raise HTTPException(
        status_code=422,
        detail={"error_code": exc.code, "message": exc.message, "details": {"position": exc.position}},
    ) from exc


@router.get("/search/fields")
def search_fields(db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.SEARCH_EVENTS))):
    return {"fields": field_catalog(_permissions(db, user)), "syntax": ["field:value", "field>=value", "field IN (...)", "field EXISTS", "AND / OR / NOT", "parentheses"]}


@router.post("/search/validate")
def validate_search(payload: SearchRequest, user: User = Depends(require_permission(Permission.SEARCH_EVENTS))):
    try:
        return {"valid": True, "normalized_query": search_query_parser.parse(payload.query)}
    except SearchQueryError as exc:
        _query_error(exc)


@router.post("/search")
def execute_search(payload: SearchRequest, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.SEARCH_EVENTS))):
    try:
        return search_service.execute(
            db, tenant_id=user.tenant_id, user_id=user.id, permission_values=_permissions(db, user),
            query_text=payload.query, resource_scope=payload.resource_scope,
            start=payload.start, end=payload.end, page=payload.page, page_size=payload.page_size,
            sort_field=payload.sort_field, sort_direction=payload.sort_direction,
            record_history=payload.record_history,
        )
    except SearchQueryError as exc:
        _query_error(exc)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail={"error_code": "SEARCH_PERMISSION_DENIED", "message": "Search permission is required"}) from exc


@router.get("/search/history")
def history(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.SEARCH_HISTORY_VIEW))):
    return db.query(SearchHistory).filter(
        SearchHistory.tenant_id == user.tenant_id, SearchHistory.user_id == user.id,
    ).order_by(SearchHistory.created_at.desc()).limit(limit).all()


@router.delete("/search/history", status_code=204)
def clear_history(db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.SEARCH_HISTORY_MANAGE))):
    db.query(SearchHistory).filter(SearchHistory.tenant_id == user.tenant_id, SearchHistory.user_id == user.id).delete()
    db.commit()


@router.get("/search/saved")
def list_saved(db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.SEARCH_SAVED_VIEW))):
    return db.query(SavedSearch).filter(
        SavedSearch.tenant_id == user.tenant_id,
        or_(SavedSearch.owner_id == user.id, SavedSearch.visibility.in_(["team", "organization"])),
    ).order_by(SavedSearch.pinned.desc(), SavedSearch.updated_at.desc()).all()


@router.post("/search/saved", status_code=201)
def create_saved(payload: SavedSearchRequest, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.SEARCH_SAVED_MANAGE))):
    if payload.visibility != "private" and Permission.SEARCH_SAVED_SHARE.value not in _permissions(db, user):
        raise HTTPException(status_code=403, detail={"error_code": "SAVED_SEARCH_ACCESS_DENIED", "message": "Sharing permission is required"})
    try:
        ast = search_query_parser.parse(payload.query)
    except SearchQueryError as exc:
        _query_error(exc)
    record = SavedSearch(
        tenant_id=user.tenant_id, owner_id=user.id, name=payload.name.strip(),
        normalized_name=payload.name.strip().casefold(), description=payload.description,
        display_query=search_service._sanitize_query(payload.query), query_ast=ast,
        resource_scope=payload.resource_scope, time_range=payload.time_range,
        sort=payload.sort, visibility=payload.visibility, tags=payload.tags, pinned=payload.pinned,
    )
    db.add(record)
    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail={"error_code": "SAVED_SEARCH_CONFLICT", "message": "A saved search with this name already exists"}) from exc
    db.refresh(record)
    db.add(SavedSearchRevision(
        tenant_id=user.tenant_id, saved_search_id=record.id, version=1,
        definition=payload.model_dump(mode="json"), changed_by_id=user.id,
    ))
    db.commit()
    audit_service.record(db, action="saved_search_created", user=user, resource_type="saved_search", resource_id=record.id, details={"visibility": record.visibility})
    return record


@router.post("/search/saved/{saved_id}/clone", status_code=201)
def clone_saved(saved_id: str, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.SEARCH_SAVED_MANAGE))):
    source = db.query(SavedSearch).filter(
        SavedSearch.id == saved_id, SavedSearch.tenant_id == user.tenant_id,
        or_(SavedSearch.owner_id == user.id, SavedSearch.visibility != "private"),
    ).first()
    if not source:
        raise HTTPException(status_code=404, detail={"error_code": "SAVED_SEARCH_NOT_FOUND", "message": "Saved search not found"})
    clone = SavedSearch(
        tenant_id=user.tenant_id, owner_id=user.id, name=f"{source.name} copy",
        normalized_name=f"{source.normalized_name} copy {secrets.token_hex(2)}",
        description=source.description, display_query=source.display_query, query_ast=source.query_ast,
        resource_scope=source.resource_scope, time_range=source.time_range, sort=source.sort,
        visibility="private", tags=source.tags,
    )
    db.add(clone); db.commit(); db.refresh(clone)
    return clone


@router.post("/search/saved/{saved_id}/share")
def share_saved(saved_id: str, expires_minutes: int = Query(60, ge=5, le=10080), db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.SEARCH_SAVED_SHARE))):
    saved = db.query(SavedSearch).filter(SavedSearch.id == saved_id, SavedSearch.tenant_id == user.tenant_id, SavedSearch.owner_id == user.id).first()
    if not saved:
        raise HTTPException(status_code=404, detail={"error_code": "SAVED_SEARCH_NOT_FOUND", "message": "Saved search not found"})
    token = secrets.token_urlsafe(24)
    reference = SharedSearchReference(
        tenant_id=user.tenant_id, saved_search_id=saved.id,
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        expires_at=get_utc_now() + timedelta(minutes=expires_minutes), created_by_id=user.id,
    )
    db.add(reference); db.commit()
    audit_service.record(db, action="saved_search_shared", user=user, resource_type="saved_search", resource_id=saved.id, details={"expires_minutes": expires_minutes})
    return {"reference_id": reference.id, "token": token, "expires_at": reference.expires_at}


@router.get("/search/templates")
def templates(db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.SEARCH_SAVED_VIEW))):
    return db.query(SearchTemplate).filter(or_(SearchTemplate.tenant_id.is_(None), SearchTemplate.tenant_id == user.tenant_id)).all()


@router.post("/search/saved/{saved_id}/schedule", status_code=201)
def schedule_search(saved_id: str, cadence: str = Query(pattern="^(hourly|daily|weekly)$"), db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.SEARCH_SCHEDULE_MANAGE))):
    saved = db.query(SavedSearch).filter(SavedSearch.id == saved_id, SavedSearch.tenant_id == user.tenant_id, SavedSearch.owner_id == user.id).first()
    if not saved:
        raise HTTPException(status_code=404, detail={"error_code": "SAVED_SEARCH_NOT_FOUND", "message": "Saved search not found"})
    count = db.query(ScheduledSearch).filter(ScheduledSearch.tenant_id == user.tenant_id, ScheduledSearch.status == "active").count()
    if count >= get_settings().SEARCH_MAX_SCHEDULES_PER_TENANT:
        raise HTTPException(status_code=409, detail={"error_code": "SCHEDULED_SEARCH_INVALID", "message": "Schedule limit reached"})
    delta = {"hourly": timedelta(hours=1), "daily": timedelta(days=1), "weekly": timedelta(days=7)}[cadence]
    record = ScheduledSearch(tenant_id=user.tenant_id, saved_search_id=saved.id, owner_id=user.id, cadence=cadence, next_run_at=get_utc_now() + delta)
    db.add(record); db.commit(); db.refresh(record)
    audit_service.record(db, action="scheduled_search_created", user=user, resource_type="scheduled_search", resource_id=record.id, details={"cadence": cadence})
    return record


def _run_export(job_id: str):
    from src.core.database import SessionLocal
    session = SessionLocal()
    try:
        search_export_service.run(session, job_id)
    finally:
        session.close()


@router.post("/search/exports", status_code=202)
def create_search_export(payload: SearchExportRequest, tasks: BackgroundTasks, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.SEARCH_EXPORT))):
    try:
        search_query_parser.parse(payload.query)
    except SearchQueryError as exc:
        _query_error(exc)
    definition = payload.model_dump(mode="json", exclude={"format"})
    job = search_export_service.create_search_job(db, user, definition, payload.format)
    tasks.add_task(_run_export, job.id)
    audit_service.record(db, action="search_export_requested", user=user, resource_type="search_export", resource_id=job.id, details={"format": payload.format})
    return job


@router.post("/investigations/{investigation_id}/reports", status_code=202)
def create_investigation_report(investigation_id: str, tasks: BackgroundTasks, format: str = Query(default="markdown", pattern="^(jsonl|markdown)$"), db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.INVESTIGATIONS_EXPORT))):
    try:
        job = search_export_service.create_investigation_job(db, user, investigation_id, format)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail={"error_code": "INVESTIGATION_NOT_FOUND", "message": "Investigation not found"}) from exc
    tasks.add_task(_run_export, job.id)
    audit_service.record(db, action="investigation_report_requested", user=user, resource_type="investigation_report", resource_id=job.id, parent_resource_type="investigation", parent_resource_id=investigation_id, details={"format": format})
    return job


@router.get("/search/exports/{job_id}")
def export_status(job_id: str, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.SEARCH_EXPORT))):
    job = db.query(SearchExportJob).filter(SearchExportJob.id == job_id, SearchExportJob.tenant_id == user.tenant_id).first()
    if not job:
        raise HTTPException(status_code=404, detail={"error_code": "EVIDENCE_NOT_FOUND", "message": "Export not found"})
    return job


@router.get("/search/exports/{job_id}/download")
def download_export(job_id: str, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.SEARCH_EXPORT))):
    job = db.query(SearchExportJob).filter(SearchExportJob.id == job_id, SearchExportJob.tenant_id == user.tenant_id).first()
    if not job:
        raise HTTPException(status_code=404, detail={"error_code": "EVIDENCE_NOT_FOUND", "message": "Export not found"})
    try:
        payload = search_export_service.read(job)
    except RuntimeError as exc:
        code = str(exc)
        raise HTTPException(status_code=410 if code == "EXPORT_EXPIRED" else 409, detail={"error_code": code, "message": code.replace("_", " ").title()}) from exc
    audit_service.record(db, action="search_export_downloaded", user=user, resource_type="search_export", resource_id=job.id, details={"checksum": job.checksum})
    media = {"csv": "text/csv", "jsonl": "application/x-ndjson", "markdown": "text/markdown", "evidence_zip": "application/zip"}[job.format]
    return Response(payload, media_type=media, headers={"Content-Disposition": f'attachment; filename="vigilantai-{job.id}.{job.format}"'})


@router.get("/entities/{entity_id}")
def entity_detail(entity_id: str, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.ENTITIES_VIEW))):
    entity = db.query(SearchEntity).filter(SearchEntity.id == entity_id, SearchEntity.tenant_id == user.tenant_id).first()
    if not entity:
        raise HTTPException(status_code=404, detail={"error_code": "ENTITY_NOT_FOUND", "message": "Entity not found"})
    return entity


@router.get("/entities/{entity_id}/timeline")
def entity_timeline(entity_id: str, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.ENTITIES_VIEW))):
    entity = db.query(SearchEntity).filter(SearchEntity.id == entity_id, SearchEntity.tenant_id == user.tenant_id).first()
    if not entity:
        raise HTTPException(status_code=404, detail={"error_code": "ENTITY_NOT_FOUND", "message": "Entity not found"})
    query = db.query(SecurityEvent, EventEntity).join(EventEntity, EventEntity.event_id == SecurityEvent.id).filter(
        SecurityEvent.tenant_id == user.tenant_id, EventEntity.entity_id == entity.id,
    )
    total = query.count()
    rows = query.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [{"id": event.id, "event_id": event.id, "type": "event", "timestamp": event.timestamp,
                       "title": (event.normalized_event or {}).get("message") or f"{event.event_type.value} event",
                       "category": event.event_category,
                       "severity": event.severity, "source": event.source, "role": link.role,
                       "path": f"/events/{event.id}"} for event, link in rows],
            "page": page, "page_size": page_size, "total_count": total, "has_next": page * page_size < total}


@router.get("/entities/{entity_id}/graph")
def entity_graph(entity_id: str, depth: int = Query(1, ge=1), db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.ENTITIES_GRAPH_VIEW))):
    settings = get_settings()
    try:
        return entity_investigation_service.graph(
            db, user.tenant_id, entity_id, min(depth, settings.ENTITY_GRAPH_MAX_DEPTH),
            settings.ENTITY_GRAPH_MAX_NODES, settings.ENTITY_GRAPH_MAX_EDGES,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail={"error_code": "ENTITY_NOT_FOUND", "message": "Entity not found"}) from exc


def _investigation(db: Session, tenant_id: str, investigation_id: str):
    record = db.query(InvestigationWorkspace).filter(
        InvestigationWorkspace.id == investigation_id, InvestigationWorkspace.tenant_id == tenant_id,
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail={"error_code": "INVESTIGATION_NOT_FOUND", "message": "Investigation not found"})
    return record


@router.get("/investigations")
def list_investigations(db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.INVESTIGATIONS_VIEW))):
    return db.query(InvestigationWorkspace).filter(InvestigationWorkspace.tenant_id == user.tenant_id).order_by(InvestigationWorkspace.updated_at.desc()).limit(200).all()


@router.post("/investigations", status_code=201)
def create_investigation(payload: InvestigationCreate, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.INVESTIGATIONS_CREATE))):
    if payload.linked_incident_id and not db.query(Incident.id).filter(Incident.id == payload.linked_incident_id, Incident.tenant_id == user.tenant_id).first():
        raise HTTPException(status_code=404, detail={"error_code": "INVESTIGATION_NOT_FOUND", "message": "Linked incident not found"})
    record = InvestigationWorkspace(
        tenant_id=user.tenant_id, title=payload.title, description=payload.description,
        owner_id=user.id, created_by_id=user.id, linked_incident_id=payload.linked_incident_id,
    )
    db.add(record); db.commit(); db.refresh(record)
    audit_service.record(db, action="investigation_created", user=user, resource_type="investigation", resource_id=record.id, details={"linked_incident_id": record.linked_incident_id})
    return record


@router.get("/investigations/{investigation_id}")
def investigation_detail(investigation_id: str, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.INVESTIGATIONS_VIEW))):
    record = _investigation(db, user.tenant_id, investigation_id)
    return {
        "id": record.id, "title": record.title, "description": record.description,
        "status": record.status,
        "created_at": record.created_at, "updated_at": record.updated_at,
        "resources": db.query(InvestigationResource).filter(InvestigationResource.investigation_id == record.id, InvestigationResource.tenant_id == user.tenant_id).all(),
        "bookmarks": db.query(EvidenceBookmark).filter(EvidenceBookmark.investigation_id == record.id, EvidenceBookmark.tenant_id == user.tenant_id, EvidenceBookmark.removed_at.is_(None)).order_by(EvidenceBookmark.display_order).all(),
        "snapshots": db.query(EvidenceSnapshot).filter(EvidenceSnapshot.investigation_id == record.id, EvidenceSnapshot.tenant_id == user.tenant_id).order_by(EvidenceSnapshot.created_at.desc()).all(),
        "notes": db.query(InvestigationWorkspaceNote).filter(InvestigationWorkspaceNote.investigation_id == record.id, InvestigationWorkspaceNote.tenant_id == user.tenant_id, InvestigationWorkspaceNote.deleted_at.is_(None)).order_by(InvestigationWorkspaceNote.pinned.desc(), InvestigationWorkspaceNote.created_at.desc()).all(),
        "collaborators": db.query(InvestigationCollaborator).filter(InvestigationCollaborator.investigation_id == record.id, InvestigationCollaborator.tenant_id == user.tenant_id).all(),
    }


@router.patch("/investigations/{investigation_id}/status")
def set_investigation_status(investigation_id: str, new_status: str = Query(pattern="^(open|active|completed|archived)$"), db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.INVESTIGATIONS_UPDATE))):
    record = _investigation(db, user.tenant_id, investigation_id)
    if new_status in {"completed", "archived"} and Permission.INVESTIGATIONS_COMPLETE.value not in _permissions(db, user):
        raise HTTPException(status_code=403, detail={"error_code": "INVESTIGATION_ACCESS_DENIED", "message": "Completion permission is required"})
    record.status = new_status
    record.completed_at = get_utc_now() if new_status == "completed" else record.completed_at
    db.commit()
    audit_service.record(db, action="investigation_status_changed", user=user, resource_type="investigation", resource_id=record.id, details={"status": new_status})
    return record


def _resource_exists(db: Session, tenant_id: str, resource_type: str, resource_id: str) -> bool:
    model = {"event": SecurityEvent, "alert": Alert, "incident": Incident, "entity": SearchEntity, "saved_search": SavedSearch}[resource_type]
    return db.query(model.id).filter(model.id == resource_id, model.tenant_id == tenant_id).first() is not None


@router.post("/investigations/{investigation_id}/resources", status_code=201)
def add_resource(investigation_id: str, payload: ResourceCreate, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.INVESTIGATIONS_UPDATE))):
    _investigation(db, user.tenant_id, investigation_id)
    if not _resource_exists(db, user.tenant_id, payload.resource_type, payload.resource_id):
        raise HTTPException(status_code=404, detail={"error_code": "EVIDENCE_NOT_FOUND", "message": "Resource not found"})
    record = InvestigationResource(tenant_id=user.tenant_id, investigation_id=investigation_id, added_by_id=user.id, **payload.model_dump())
    db.add(record); db.commit(); db.refresh(record)
    return record


@router.post("/investigations/{investigation_id}/collaborators", status_code=201)
def add_collaborator(investigation_id: str, collaborator_user_id: str, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.INVESTIGATIONS_COLLABORATE))):
    _investigation(db, user.tenant_id, investigation_id)
    membership = db.query(OrganizationMembership).filter(
        OrganizationMembership.tenant_id == user.tenant_id,
        OrganizationMembership.user_id == collaborator_user_id,
        OrganizationMembership.is_active == True,
    ).first()
    if not membership:
        raise HTTPException(status_code=404, detail={"error_code": "INVESTIGATION_ACCESS_DENIED", "message": "Collaborator not found"})
    record = InvestigationCollaborator(tenant_id=user.tenant_id, investigation_id=investigation_id, user_id=collaborator_user_id, added_by_id=user.id)
    db.add(record); db.commit(); db.refresh(record)
    audit_service.record(db, action="investigation_collaborator_added", user=user, resource_type="investigation", resource_id=investigation_id, details={"collaborator_user_id": collaborator_user_id})
    return record


@router.post("/investigations/{investigation_id}/bookmarks", status_code=201)
def bookmark(investigation_id: str, payload: BookmarkCreate, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.EVIDENCE_BOOKMARK))):
    _investigation(db, user.tenant_id, investigation_id)
    if not _resource_exists(db, user.tenant_id, payload.resource_type, payload.resource_id):
        raise HTTPException(status_code=404, detail={"error_code": "EVIDENCE_NOT_FOUND", "message": "Resource not found"})
    record = EvidenceBookmark(tenant_id=user.tenant_id, investigation_id=investigation_id, created_by_id=user.id, **payload.model_dump())
    db.add(record); db.commit(); db.refresh(record)
    audit_service.record(db, action="evidence_bookmarked", user=user, resource_type="evidence_bookmark", resource_id=record.id, parent_resource_type="investigation", parent_resource_id=investigation_id, details={"resource_type": record.resource_type})
    return record


@router.post("/investigations/{investigation_id}/snapshots", status_code=201)
def snapshot(investigation_id: str, resource_type: str = Query(pattern="^(event|alert|incident|entity)$"), resource_id: str = Query(), db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.EVIDENCE_SNAPSHOT))):
    _investigation(db, user.tenant_id, investigation_id)
    if not _resource_exists(db, user.tenant_id, resource_type, resource_id):
        raise HTTPException(status_code=404, detail={"error_code": "EVIDENCE_NOT_FOUND", "message": "Resource not found"})
    raw_hash, parser_version, schema_version = None, None, None
    if resource_type == "event":
        event = db.query(SecurityEvent).filter(SecurityEvent.id == resource_id, SecurityEvent.tenant_id == user.tenant_id).first()
        projection = {"id": event.id, "timestamp": event.timestamp.isoformat(), "source": event.source, "severity": event.severity.value, "category": event.event_category, "class": event.event_class, "normalized_event": {key: (event.normalized_event or {}).get(key) for key in ("message", "actor", "device", "network")}}
        raw_hash = hashlib.sha256(json.dumps(event.raw_event, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        parser_version, schema_version = event.parser_version, event.schema_version
    else:
        model = {"alert": Alert, "incident": Incident, "entity": SearchEntity}[resource_type]
        item = db.query(model).filter(model.id == resource_id, model.tenant_id == user.tenant_id).first()
        projection = {"id": item.id, "type": resource_type, "title": getattr(item, "title", None) or getattr(item, "display_value", None), "status": str(getattr(item, "status", ""))}
    integrity = hashlib.sha256(json.dumps(projection, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
    record = EvidenceSnapshot(tenant_id=user.tenant_id, investigation_id=investigation_id, resource_type=resource_type, resource_id=resource_id, safe_projection=projection, raw_event_hash=raw_hash, integrity_hash=integrity, parser_version=parser_version, schema_version=schema_version, created_by_id=user.id)
    db.add(record); db.commit(); db.refresh(record)
    audit_service.record(db, action="evidence_snapshot_created", user=user, resource_type="evidence_snapshot", resource_id=record.id, parent_resource_type="investigation", parent_resource_id=investigation_id, details={"integrity_hash": integrity})
    return record


def _plain_text(value: str) -> str:
    return re.sub(r"<[^>]*>", "", value).strip()


@router.post("/investigations/{investigation_id}/notes", status_code=201)
def add_note(investigation_id: str, payload: NoteCreate, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.INVESTIGATIONS_UPDATE))):
    _investigation(db, user.tenant_id, investigation_id)
    content = _plain_text(payload.content)
    if not content:
        raise HTTPException(status_code=422, detail={"error_code": "SEARCH_VALUE_INVALID", "message": "Note content is empty"})
    record = InvestigationWorkspaceNote(tenant_id=user.tenant_id, investigation_id=investigation_id, author_id=user.id, content=content, tags=payload.tags, pinned=payload.pinned)
    db.add(record); db.commit(); db.refresh(record)
    return record


@router.put("/investigations/{investigation_id}/notes/{note_id}")
def edit_note(investigation_id: str, note_id: str, payload: NoteCreate, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.INVESTIGATIONS_UPDATE))):
    _investigation(db, user.tenant_id, investigation_id)
    note = db.query(InvestigationWorkspaceNote).filter(InvestigationWorkspaceNote.id == note_id, InvestigationWorkspaceNote.investigation_id == investigation_id, InvestigationWorkspaceNote.tenant_id == user.tenant_id).first()
    if not note or (note.author_id != user.id and Permission.INVESTIGATIONS_COLLABORATE.value not in _permissions(db, user)):
        raise HTTPException(status_code=404, detail={"error_code": "EVIDENCE_NOT_FOUND", "message": "Note not found"})
    db.add(InvestigationNoteRevision(tenant_id=user.tenant_id, note_id=note.id, version=note.version, content=note.content, changed_by_id=user.id))
    note.version += 1; note.content = _plain_text(payload.content); note.tags = payload.tags; note.pinned = payload.pinned
    db.commit(); db.refresh(note)
    return note


@router.post("/investigations/{investigation_id}/attachments/metadata", status_code=201)
def register_attachment_metadata(investigation_id: str, payload: AttachmentMetadataCreate, db: Session = Depends(get_db), user: User = Depends(require_permission(Permission.EVIDENCE_ATTACHMENT_UPLOAD))):
    _investigation(db, user.tenant_id, investigation_id)
    settings = get_settings()
    if payload.size_bytes > settings.INVESTIGATION_ATTACHMENT_MAX_BYTES:
        raise HTTPException(status_code=413, detail={"error_code": "ATTACHMENT_TOO_LARGE", "message": "Attachment exceeds the configured limit"})
    if payload.content_type not in settings.INVESTIGATION_ALLOWED_ATTACHMENT_TYPES:
        raise HTTPException(status_code=422, detail={"error_code": "ATTACHMENT_INVALID", "message": "Attachment type is not allowed"})
    extension = {"image/png": ".png", "image/jpeg": ".jpg", "application/pdf": ".pdf", "text/plain": ".txt", "text/csv": ".csv"}[payload.content_type]
    record = InvestigationAttachment(
        tenant_id=user.tenant_id, investigation_id=investigation_id, uploaded_by_id=user.id,
        display_name=re.sub(r"[^A-Za-z0-9 _.()-]", "_", payload.display_name)[:255],
        safe_filename=f"{secrets.token_hex(16)}{extension}", content_type=payload.content_type,
        size_bytes=payload.size_bytes, sha256=payload.sha256.lower(),
        classification=payload.classification, storage_status="metadata_only",
        malware_scan_status="not_stored",
    )
    db.add(record); db.commit(); db.refresh(record)
    audit_service.record(db, action="investigation_attachment_metadata_created", user=user, resource_type="investigation_attachment", resource_id=record.id, parent_resource_type="investigation", parent_resource_id=investigation_id, details={"content_type": record.content_type, "size_bytes": record.size_bytes, "storage_status": "metadata_only"})
    return record
