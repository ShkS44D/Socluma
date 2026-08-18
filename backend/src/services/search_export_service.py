from __future__ import annotations

import csv
import hashlib
import io
import json
import uuid
import zipfile
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from src.core.config import get_settings
from src.core.permissions import membership_permissions
from src.models.sqlalchemy import (
    InvestigationWorkspace, SearchExportJob, User,
)
from src.services.audit_management_service import LocalAuditArtifactStorage
from src.services.search_service import search_service
from src.utils.datetime_utils import ensure_utc, get_utc_now


class SearchExportService:
    def create_search_job(self, db: Session, user: User, definition: dict[str, Any], format_name: str):
        settings = get_settings()
        job = SearchExportJob(
            tenant_id=user.tenant_id, requested_by_id=user.id, format=format_name,
            job_type="search_export", definition=definition, status="queued",
            expires_at=get_utc_now() + timedelta(hours=settings.SEARCH_EXPORT_EXPIRE_HOURS),
        )
        db.add(job); db.commit(); db.refresh(job)
        return job

    def create_investigation_job(self, db: Session, user: User, investigation_id: str, format_name: str):
        record = db.query(InvestigationWorkspace).filter_by(id=investigation_id, tenant_id=user.tenant_id).first()
        if not record:
            raise LookupError("INVESTIGATION_NOT_FOUND")
        job = SearchExportJob(
            tenant_id=user.tenant_id, requested_by_id=user.id, investigation_id=record.id,
            format=format_name, job_type="investigation_report",
            definition={"investigation_id": record.id}, status="queued",
            expires_at=get_utc_now() + timedelta(hours=get_settings().SEARCH_EXPORT_EXPIRE_HOURS),
        )
        db.add(job); db.commit(); db.refresh(job)
        return job

    def run(self, db: Session, job_id: str):
        job = db.query(SearchExportJob).filter_by(id=job_id).first()
        if not job or job.status not in {"queued", "failed"}:
            return job
        job.status = "running"; db.commit()
        try:
            user = db.query(User).filter_by(id=job.requested_by_id, tenant_id=job.tenant_id, is_active=True).first()
            if not user:
                raise PermissionError("EXPORT_OWNER_DISABLED")
            if job.job_type == "search_export":
                payload, count, manifest = self._search_payload(db, user, job.definition, job.format)
            else:
                payload, count, manifest = self._investigation_payload(db, user, job.investigation_id, job.format)
            checksum = hashlib.sha256(payload).hexdigest()
            manifest.update({"checksum_sha256": checksum, "exported_at": get_utc_now().isoformat(),
                             "tenant_id": job.tenant_id, "requested_by_id": user.id})
            if job.format == "evidence_zip":
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr("records.jsonl", payload)
                    archive.writestr("manifest.json", json.dumps(manifest, indent=2, default=str))
                payload = buffer.getvalue()
                checksum = hashlib.sha256(payload).hexdigest()
                manifest["checksum_sha256"] = checksum
            suffix = {"csv": "csv", "jsonl": "jsonl", "markdown": "md", "evidence_zip": "zip"}[job.format]
            key = f"{job.tenant_id}/{job.id}.{suffix}"
            LocalAuditArtifactStorage(get_settings().AUDIT_EXPORT_DIRECTORY).write(key, payload)
            job.artifact_path, job.checksum, job.manifest = key, checksum, manifest
            job.result_count, job.status, job.completed_at = count, "completed", get_utc_now()
        except Exception as exc:
            job.status, job.error = "failed", type(exc).__name__
        db.commit(); db.refresh(job)
        return job

    def read(self, job: SearchExportJob) -> bytes:
        if job.status != "completed" or not job.artifact_path:
            raise RuntimeError("EXPORT_NOT_READY")
        if ensure_utc(job.expires_at) <= get_utc_now():
            raise RuntimeError("EXPORT_EXPIRED")
        return LocalAuditArtifactStorage(get_settings().AUDIT_EXPORT_DIRECTORY).read(job.artifact_path)

    def _search_payload(self, db, user, definition, format_name):
        settings, page, rows = get_settings(), 1, []
        permissions = membership_permissions(db, user)
        while len(rows) < settings.SEARCH_MAX_EXPORT_ROWS:
            result = search_service.execute(
                db, tenant_id=user.tenant_id, user_id=user.id, permission_values=permissions,
                query_text=definition.get("query", ""), resource_scope=definition.get("resource_scope", "events"),
                start=self._date(definition.get("start")), end=self._date(definition.get("end")),
                page=page, page_size=min(200, settings.SEARCH_MAX_PAGE_SIZE),
                sort_field=definition.get("sort_field", "timestamp"),
                sort_direction=definition.get("sort_direction", "desc"), record_history=False,
            )
            rows.extend(result["items"])
            if not result["has_next"]:
                break
            page += 1
        rows = rows[:settings.SEARCH_MAX_EXPORT_ROWS]
        manifest = {"job_type": "search_export", "definition": definition, "result_count": len(rows),
                    "limited": len(rows) >= settings.SEARCH_MAX_EXPORT_ROWS}
        return self._serialize(rows, format_name), len(rows), manifest

    def _investigation_payload(self, db, user, investigation_id, format_name):
        from src.models.sqlalchemy import EvidenceBookmark, EvidenceSnapshot, InvestigationWorkspaceNote
        record = db.query(InvestigationWorkspace).filter_by(id=investigation_id, tenant_id=user.tenant_id).first()
        if not record:
            raise LookupError("INVESTIGATION_NOT_FOUND")
        report = {
            "id": record.id, "title": record.title, "description": record.description,
            "status": record.status, "classification": record.classification,
            "bookmarks": [{"resource_type": x.resource_type, "resource_id": x.resource_id,
                           "comment": x.analyst_comment, "relevance": x.relevance}
                          for x in db.query(EvidenceBookmark).filter_by(tenant_id=user.tenant_id, investigation_id=record.id).all()],
            "snapshots": [{"resource_type": x.resource_type, "resource_id": x.resource_id,
                           "integrity_hash": x.integrity_hash, "classification": x.classification}
                          for x in db.query(EvidenceSnapshot).filter_by(tenant_id=user.tenant_id, investigation_id=record.id).all()],
            "analyst_notes": [{"statement": x.content, "author_id": x.author_id, "created_at": x.created_at}
                              for x in db.query(InvestigationWorkspaceNote).filter_by(tenant_id=user.tenant_id, investigation_id=record.id).all()],
            "limitations": "Observed evidence and analyst statements are distinguished; hashes prove stored-content integrity, not external legal authenticity.",
        }
        if format_name == "markdown":
            lines = [f"# {record.title}", "", record.description or "", "", f"Status: {record.status}", "",
                     "## Bookmarked evidence"]
            lines.extend(f"- {x['resource_type']} `{x['resource_id']}` — {x.get('relevance')}" for x in report["bookmarks"])
            lines.extend(["", "## Analyst statements"])
            lines.extend(f"- {x['statement']}" for x in report["analyst_notes"])
            return "\n".join(lines).encode(), len(report["bookmarks"]), {"job_type": "investigation_report", "investigation_id": record.id}
        return (json.dumps(report, default=str, separators=(",", ":")).encode(),
                len(report["bookmarks"]), {"job_type": "investigation_report", "investigation_id": record.id})

    @staticmethod
    def _serialize(rows, format_name):
        if format_name in {"jsonl", "evidence_zip"}:
            return b"\n".join(json.dumps(row, default=str, separators=(",", ":")).encode() for row in rows)
        output = io.StringIO()
        fields = sorted({key for row in rows for key in row if key not in {"raw_event", "normalized_event"}})
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(row.get(key), default=str) if isinstance(row.get(key), (dict, list)) else row.get(key) for key in fields})
        return output.getvalue().encode("utf-8-sig")

    @staticmethod
    def _date(value):
        return None if not value else ensure_utc(__import__("datetime").datetime.fromisoformat(value.replace("Z", "+00:00")))


search_export_service = SearchExportService()
