from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import os
import re
import secrets
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from src.core.config import get_settings
from src.core.crypto import decrypt_bytes, decrypt_json_secret, encrypt_bytes, encrypt_json_secret
from src.models.pydantic import AuditLog as AuditLogResponse
from src.models.sqlalchemy import (
    AuditArchiveJob,
    AuditChainState,
    AuditExportJob,
    AuditLegalHold,
    AuditLog,
    AuditRetentionPolicy,
    ConnectorCredential,
    User,
)
from src.services.audit_service import audit_service
from src.utils.datetime_utils import ensure_utc, get_utc_now


settings = get_settings()
SAFE_RETENTION_CLASSES = {
    "default": "default_retention_days",
    "security": "security_retention_days",
    "administrative": "administrative_retention_days",
    "authentication": "authentication_retention_days",
    "export": "export_retention_days",
}
EXPORT_FORMATS = {"csv", "jsonl", "evidence_zip"}
JOB_STATES = {"pending", "running", "completed", "failed", "expired", "cancelled"}


class LocalAuditArtifactStorage:
    def __init__(self, root: str):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        if not re.fullmatch(r"[a-f0-9-]{36}/[A-Za-z0-9_.-]{1,180}", key):
            raise ValueError("ARTIFACT_KEY_INVALID")
        path = (self.root / key).resolve()
        if self.root not in path.parents:
            raise ValueError("ARTIFACT_KEY_INVALID")
        return path

    def write(self, key: str, payload: bytes) -> str:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        stored_payload = encrypt_bytes(payload) if settings.AUDIT_ARTIFACT_ENCRYPTION_ENABLED else payload
        temporary.write_bytes(stored_payload)
        os.replace(temporary, path)
        return hashlib.sha256(payload).hexdigest()

    def read(self, key: str) -> bytes:
        payload = self._path(key).read_bytes()
        return decrypt_bytes(payload) if settings.AUDIT_ARTIFACT_ENCRYPTION_ENABLED else payload

    def delete(self, key: str) -> None:
        path = self._path(key)
        if path.exists():
            path.unlink()


class AuditManagementService:
    batch_size = 500

    def retention_policy(self, db: Session, tenant_id: str) -> AuditRetentionPolicy:
        policy = db.get(AuditRetentionPolicy, tenant_id)
        if policy:
            return policy
        policy = AuditRetentionPolicy(tenant_id=tenant_id)
        db.add(policy)
        db.flush()
        return policy

    def update_retention(
        self, db: Session, tenant_id: str, user: User, values: dict[str, Any]
    ) -> AuditRetentionPolicy:
        policy = self.retention_policy(db, tenant_id)
        before = self.policy_dict(policy)
        allowed = set(before)
        if not set(values).issubset(allowed):
            raise ValueError("RETENTION_POLICY_INVALID")
        for field, value in values.items():
            if field.endswith("_retention_days"):
                minimum = settings.AUDIT_RETENTION_MINIMUM_DAYS
                if not isinstance(value, int) or not minimum <= value <= settings.AUDIT_RETENTION_MAXIMUM_DAYS:
                    raise ValueError("RETENTION_MINIMUM_REQUIRED")
            if field == "archive_before_purge" and not isinstance(value, bool):
                raise ValueError("RETENTION_POLICY_INVALID")
            setattr(policy, field, value)
        policy.updated_by_id = user.id
        db.flush()
        audit_service.record(
            db, action="retention.policy.updated", user=user,
            resource_type="audit_retention_policy", resource_id=tenant_id,
            before_values=before, after_values=self.policy_dict(policy), commit=False, strict=True,
        )
        db.commit()
        db.refresh(policy)
        return policy

    def policy_dict(self, policy: AuditRetentionPolicy) -> dict[str, Any]:
        return {
            name: getattr(policy, name)
            for name in (
                "default_retention_days", "security_retention_days",
                "administrative_retention_days", "authentication_retention_days",
                "export_retention_days", "archive_before_purge", "archive_retention_days",
            )
        }

    def create_hold(self, db: Session, tenant_id: str, user: User, values: dict[str, Any]) -> AuditLegalHold:
        hold = AuditLegalHold(
            id=str(uuid.uuid4()), tenant_id=tenant_id, created_by_id=user.id,
            name=values["name"].strip()[:150], reason=values["reason"].strip()[:4000],
            start_at=values.get("start_at"), end_at=values.get("end_at"),
            category_filters=audit_service.sanitize(values.get("category_filters") or []),
            resource_filters=audit_service.sanitize(values.get("resource_filters") or []),
            safe_metadata=audit_service.sanitize(values.get("safe_metadata") or {}),
        )
        if not hold.name or not hold.reason or (
            hold.start_at and hold.end_at and ensure_utc(hold.start_at) > ensure_utc(hold.end_at)
        ):
            raise ValueError("LEGAL_HOLD_INVALID")
        db.add(hold)
        db.flush()
        audit_service.record(
            db, action="legal.hold.created", user=user, resource_type="audit_legal_hold",
            resource_id=hold.id, after_values={"name": hold.name, "start_at": hold.start_at,
            "end_at": hold.end_at, "category_filters": hold.category_filters,
            "resource_filters": hold.resource_filters}, commit=False, strict=True,
        )
        db.commit()
        db.refresh(hold)
        return hold

    def release_hold(self, db: Session, tenant_id: str, hold_id: str, user: User) -> AuditLegalHold:
        hold = db.query(AuditLegalHold).filter_by(id=hold_id, tenant_id=tenant_id).first()
        if not hold:
            raise LookupError("LEGAL_HOLD_NOT_FOUND")
        if hold.status != "active":
            raise RuntimeError("LEGAL_HOLD_ALREADY_RELEASED")
        user_id = user.id
        hold.status = "released"
        hold.released_by_id = user_id
        hold.released_at = get_utc_now()
        connection = db.connection()
        connection.info["legal_hold_release"] = True
        try:
            db.flush()
        finally:
            connection.info.pop("legal_hold_release", None)
        audit_service.record(
            db, action="legal.hold.released", user=user, resource_type="audit_legal_hold",
            resource_id=hold.id, before_values={"status": "active"},
            after_values={"status": "released", "released_at": hold.released_at},
            commit=False, strict=True,
        )
        db.commit()
        db.refresh(hold)
        return hold

    def _held(self, row: AuditLog, holds: list[AuditLegalHold]) -> bool:
        created = ensure_utc(row.created_at)
        for hold in holds:
            if hold.start_at and created < ensure_utc(hold.start_at):
                continue
            if hold.end_at and created > ensure_utc(hold.end_at):
                continue
            if hold.category_filters and row.category not in hold.category_filters:
                continue
            if hold.resource_filters:
                matched = any(
                    item.get("type") == row.resource_type
                    and (not item.get("id") or item.get("id") == row.resource_id)
                    for item in hold.resource_filters if isinstance(item, dict)
                )
                if not matched:
                    continue
            return True
        return False

    def run_retention(self, db: Session, tenant_id: str, *, requested_by_id: str | None = None) -> AuditArchiveJob:
        job = AuditArchiveJob(
            id=str(uuid.uuid4()), tenant_id=tenant_id, requested_by_id=requested_by_id,
            status="running", date_to=get_utc_now(),
        )
        db.add(job)
        db.commit()
        try:
            policy = self.retention_policy(db, tenant_id)
            holds = db.query(AuditLegalHold).filter_by(tenant_id=tenant_id, status="active").all()
            now = get_utc_now()
            eligible: list[AuditLog] = []
            query = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id).order_by(AuditLog.sequence_number.asc())
            for row in query.yield_per(self.batch_size):
                days = getattr(policy, SAFE_RETENTION_CLASSES.get(row.retention_class, "default_retention_days"))
                if ensure_utc(row.created_at) > now - timedelta(days=days):
                    break
                job.records_considered += 1
                if self._held(row, holds):
                    job.records_held += 1
                    # Never create a hole in the retained integrity chain.
                    break
                eligible.append(row)
                if len(eligible) >= self.batch_size:
                    break
            if eligible and policy.archive_before_purge:
                artifact, checksum = self._archive_payload(tenant_id, eligible, policy)
                key = f"{tenant_id}/{job.id}.jsonl.gz"
                LocalAuditArtifactStorage(settings.AUDIT_ARCHIVE_DIRECTORY).write(key, artifact)
                job.artifact_key = key
                job.manifest_checksum = checksum
                job.records_archived = len(eligible)
            if eligible:
                first_remaining = db.query(AuditLog).filter(
                    AuditLog.tenant_id == tenant_id,
                    AuditLog.sequence_number > eligible[-1].sequence_number,
                ).order_by(AuditLog.sequence_number.asc()).first()
                state = db.get(AuditChainState, tenant_id)
                if state and first_remaining:
                    state.first_retained_sequence = first_remaining.sequence_number
                    state.first_retained_previous_hash = first_remaining.previous_event_hash
                connection = db.connection()
                connection.info["audit_maintenance"] = True
                try:
                    ids = [row.id for row in eligible]
                    job.records_purged = db.query(AuditLog).filter(AuditLog.id.in_(ids)).delete(
                        synchronize_session=False
                    )
                finally:
                    connection.info.pop("audit_maintenance", None)
            job.status = "completed"
            job.completed_at = get_utc_now()
            audit_service.record(
                db, action="archive.retention.completed", tenant_id=tenant_id,
                actor_type="system_task", resource_type="audit_archive_job", resource_id=job.id,
                details={"considered": job.records_considered, "archived": job.records_archived,
                         "purged": job.records_purged, "held": job.records_held},
                idempotency_key=f"archive-job:{job.id}", commit=False, strict=True,
            )
            db.commit()
            db.refresh(job)
            return job
        except Exception:
            db.rollback()
            job = db.get(AuditArchiveJob, job.id)
            job.status = "failed"
            job.error_code = "ARCHIVE_JOB_FAILED"
            job.completed_at = get_utc_now()
            db.commit()
            raise

    def _archive_payload(
        self, tenant_id: str, rows: list[AuditLog], policy: AuditRetentionPolicy
    ) -> tuple[bytes, str]:
        lines = [
            json.dumps(AuditLogResponse.model_validate(row).model_dump(mode="json"),
                       sort_keys=True, separators=(",", ":"))
            for row in rows
        ]
        content = ("\n".join(lines) + "\n").encode()
        content_checksum = hashlib.sha256(content).hexdigest()
        manifest = {
            "format": "triageops-audit-jsonl-v1", "tenant_id": tenant_id,
            "created_at": get_utc_now().isoformat(), "record_count": len(rows),
            "first_sequence": rows[0].sequence_number, "last_sequence": rows[-1].sequence_number,
            "content_sha256": content_checksum, "archive_retention_days": policy.archive_retention_days,
        }
        manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        return gzip.compress(manifest_bytes + b"\n" + content), hashlib.sha256(manifest_bytes).hexdigest()

    def create_export(
        self, db: Session, tenant_id: str, user: User, export_format: str, filters: dict[str, Any]
    ) -> tuple[AuditExportJob, str]:
        if export_format not in EXPORT_FORMATS:
            raise ValueError("AUDIT_EVENT_INVALID")
        token = secrets.token_urlsafe(32)
        job = AuditExportJob(
            id=str(uuid.uuid4()), tenant_id=tenant_id, requested_by_id=user.id,
            format=export_format, filters=audit_service.sanitize(filters), status="pending",
            download_token_hash=hashlib.sha256(token.encode()).hexdigest(),
            expires_at=get_utc_now() + timedelta(hours=settings.AUDIT_EXPORT_EXPIRE_HOURS),
        )
        db.add(job)
        audit_service.record(
            db, action="export.audit.requested", user=user, resource_type="audit_export_job",
            resource_id=job.id, details={"format": export_format, "filters": filters},
            commit=False, strict=True,
        )
        db.commit()
        db.refresh(job)
        return job, token

    def process_export(self, db: Session, job_id: str) -> AuditExportJob:
        job = db.get(AuditExportJob, job_id)
        if not job or job.status != "pending":
            return job
        job.status = "running"
        db.commit()
        try:
            from src.api.v1.audit_logs import build_filtered_query
            query = build_filtered_query(db, job.tenant_id, **(job.filters or {})).order_by(AuditLog.sequence_number.asc())
            records = [AuditLogResponse.model_validate(row).model_dump(mode="json") for row in query.yield_per(self.batch_size)]
            payload, suffix = self._export_payload(db, job, records)
            key = f"{job.tenant_id}/{job.id}.{suffix}"
            job.checksum = LocalAuditArtifactStorage(settings.AUDIT_EXPORT_DIRECTORY).write(key, payload)
            job.artifact_key = key
            job.record_count = len(records)
            job.status = "completed"
            job.completed_at = get_utc_now()
            audit_service.record(
                db, action="export.audit.completed", tenant_id=job.tenant_id,
                actor_type="system_task", resource_type="audit_export_job", resource_id=job.id,
                details={"format": job.format, "record_count": job.record_count, "checksum": job.checksum},
                idempotency_key=f"export-complete:{job.id}", commit=False, strict=True,
            )
            db.commit()
            return job
        except Exception:
            db.rollback()
            job = db.get(AuditExportJob, job_id)
            job.status = "failed"
            job.error_code = "EXPORT_GENERATION_FAILED"
            db.commit()
            raise

    def _export_payload(self, db: Session, job: AuditExportJob, records: list[dict[str, Any]]) -> tuple[bytes, str]:
        if job.format == "jsonl":
            return ("\n".join(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in records) + "\n").encode(), "jsonl"
        if job.format == "csv":
            output = io.StringIO()
            fields = ["id", "created_at", "sequence_number", "actor_type", "user_id", "action",
                      "category", "severity", "resource_type", "resource_id", "status",
                      "ip_address", "request_id", "correlation_id", "failure_reason", "details"]
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            for record in records:
                record = dict(record)
                record["details"] = json.dumps(record.get("details") or {}, separators=(",", ":"))
                writer.writerow({field: record.get(field) for field in fields})
            return output.getvalue().encode(), "csv"
        data = ("\n".join(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in records) + "\n").encode()
        verification = audit_service.verify(db, job.tenant_id)
        manifest = {
            "format": "triageops-evidence-package-v1", "record_count": len(records),
            "created_at": get_utc_now().isoformat(), "audit_sha256": hashlib.sha256(data).hexdigest(),
            "integrity": verification,
        }
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("audit.jsonl", data)
            archive.writestr("integrity.json", json.dumps(verification, sort_keys=True))
            archive.writestr("manifest.json", json.dumps(manifest, sort_keys=True))
        return buffer.getvalue(), "zip"

    def expire_exports(self, db: Session) -> int:
        now = get_utc_now()
        jobs = db.query(AuditExportJob).filter(
            AuditExportJob.expires_at <= now,
            AuditExportJob.status.in_(["pending", "running", "completed", "cancelled"]),
        ).limit(self.batch_size).all()
        storage = LocalAuditArtifactStorage(settings.AUDIT_EXPORT_DIRECTORY)
        for job in jobs:
            if job.artifact_key:
                storage.delete(job.artifact_key)
            job.artifact_key = None
            job.status = "expired"
        db.commit()
        return len(jobs)

    def rotate_encrypted_fields(self, db: Session, tenant_id: str, user: User) -> dict[str, int]:
        current = settings.ENCRYPTION_CURRENT_KEY_VERSION
        changed_users = changed_credentials = 0
        for account in db.query(User).filter(User.tenant_id == tenant_id).yield_per(self.batch_size):
            for value_field, version_field in (
                ("mfa_secret_encrypted", "mfa_secret_key_version"),
                ("mfa_pending_secret_encrypted", "mfa_pending_secret_key_version"),
            ):
                value = getattr(account, value_field)
                if value and (getattr(account, version_field) or 1) != current:
                    setattr(account, value_field, encrypt_json_secret(decrypt_json_secret(value)))
                    setattr(account, version_field, current)
                    changed_users += 1
        for credential in db.query(ConnectorCredential).filter(
            ConnectorCredential.tenant_id == tenant_id,
            ConnectorCredential.encryption_key_version != current,
        ).yield_per(self.batch_size):
            credential.encrypted_secret = encrypt_json_secret(decrypt_json_secret(credential.encrypted_secret))
            credential.encryption_key_version = current
            credential.rotated_at = get_utc_now()
            changed_credentials += 1
        audit_service.record(
            db, action="encryption.rotation.completed", user=user,
            resource_type="organization", resource_id=tenant_id,
            details={"user_fields_rotated": changed_users, "credentials_rotated": changed_credentials,
                     "target_key_version": current}, commit=False, strict=True,
        )
        db.commit()
        return {"user_fields_rotated": changed_users, "credentials_rotated": changed_credentials,
                "target_key_version": current}


audit_management_service = AuditManagementService()
