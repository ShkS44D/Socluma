from __future__ import annotations

import csv
import html
import hashlib
import io
import json
import secrets
import zipfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable
from urllib.parse import urljoin

import httpx
from sqlalchemy import or_
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from src.core.config import get_settings
from src.core.crypto import (
    decrypt_bytes,
    decrypt_json_secret,
    encrypt_bytes,
    encrypt_json_secret,
    encrypted_key_version,
    fingerprint_secret,
)
from src.models.pydantic import IOCCreate
from src.models.sqlalchemy import (
    Alert,
    DetectionRule,
    DetectionRuleVersion,
    IOC,
    IOCBulkActionJob,
    IOCHuntJob,
    IOCImportJob,
    IOCImportRowResult,
    IOCListEntry,
    IOCNotificationState,
    IOCReportJob,
    IOCResponseRecommendation,
    IOCReviewAssignment,
    IOCReviewHistory,
    IOCSighting,
    IOCWatchlist,
    IOCWatchlistMember,
    Incident,
    OrganizationMembership,
    OrganizationStatus,
    RuleType,
    Severity,
    SensitiveActionApproval,
    Tenant,
    ThreatIntelligenceRelationship,
    ThreatSourceCredential,
    ThreatSyncConfiguration,
    ThreatSyncJob,
    User,
)
from src.services.approval_service import approval_service
from src.services.audit_management_service import LocalAuditArtifactStorage
from src.services.detection_lifecycle_service import detection_lifecycle_service
from src.services.ioc_exchange_service import export_stix_bundle, parse_stix_bundle, validate_sync_url
from src.services.ioc_intelligence_service import (
    IOCDuplicateError,
    IOCValidationError,
    ioc_intelligence_service,
    normalize_ioc,
)
from src.services.ioc_service import ioc_service
from src.utils.datetime_utils import ensure_utc, get_utc_now


SUPPORTED_PROVIDERS = {"virustotal", "abuseipdb", "otx", "taxii", "misp"}
MISP_TYPE_MAP = {
    "ip-src": "ipv4",
    "ip-dst": "ipv4",
    "ip-src|port": "ipv4",
    "ip-dst|port": "ipv4",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "email-src": "email",
    "email-dst": "email",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
    "filename": "file_name",
    "filename|md5": "md5",
    "filename|sha1": "sha1",
    "filename|sha256": "sha256",
    "mutex": "mutex",
    "regkey": "registry_key",
    "user-agent": "user_agent",
    "ja3-fingerprint-md5": "ja3",
}
RESPONSE_ACTIONS = {
    "block_ip", "block_cidr", "block_domain", "block_url", "quarantine_hash",
    "add_to_edr_watchlist", "add_to_firewall_blocklist", "add_to_email_security_blocklist",
    "isolate_affected_host", "investigate_affected_user",
}
ALLOWED_BULK_ACTIONS = {
    "enrich", "rescore", "activate", "monitor", "expire", "revoke",
    "false_positive", "allowlist", "add_tags", "remove_tags",
    "add_to_watchlist", "remove_from_watchlist", "hunt", "export",
    "assign_reviewer",
}


class IOCCommercialError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class IOCCommercialService:
    def __init__(self) -> None:
        self.settings = get_settings()

    @staticmethod
    def credential_public(row: ThreatSourceCredential) -> dict[str, Any]:
        return {
            "id": row.id,
            "provider": row.provider,
            "name": row.name,
            "base_url": row.base_url,
            "configured": bool(row.encrypted_credentials),
            "credential_fingerprint": row.credential_fingerprint[:16],
            "encryption_key_version": row.encryption_key_version,
            "status": row.status,
            "tls_verify": row.tls_verify,
            "safe_metadata": row.safe_metadata or {},
            "last_tested_at": row.last_tested_at,
            "last_successful_use_at": row.last_successful_use_at,
            "last_rotated_at": row.last_rotated_at,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    def create_credential(
        self, db: Session, user: User, payload: dict[str, Any]
    ) -> ThreatSourceCredential:
        provider = str(payload.get("provider") or "").strip().lower()
        if provider not in SUPPORTED_PROVIDERS:
            raise IOCCommercialError("THREAT_SOURCE_CREDENTIAL_INVALID", "Unsupported threat source")
        credentials = payload.get("credentials")
        if not isinstance(credentials, dict) or not credentials:
            raise IOCCommercialError("THREAT_SOURCE_CREDENTIAL_INVALID", "Credentials are required")
        if any(not str(value).strip() for value in credentials.values()):
            raise IOCCommercialError("THREAT_SOURCE_CREDENTIAL_INVALID", "Credential values cannot be empty")
        base_url = str(payload.get("base_url") or "").strip() or None
        if provider in {"taxii", "misp"}:
            if not base_url:
                raise IOCCommercialError("THREAT_SOURCE_CREDENTIAL_INVALID", "A secure source URL is required")
            base_url = self.validate_external_url(base_url)
        row = ThreatSourceCredential(
            tenant_id=user.tenant_id,
            provider=provider,
            name=str(payload.get("name") or provider).strip()[:150],
            base_url=base_url,
            encrypted_credentials=encrypt_json_secret(credentials),
            encryption_key_version=self.settings.ENCRYPTION_CURRENT_KEY_VERSION,
            credential_fingerprint=fingerprint_secret(credentials),
            safe_metadata={
                "credential_fields": sorted(credentials),
                "description": str(payload.get("description") or "")[:500],
            },
            tls_verify=True,
            created_by=user.id,
            updated_by=user.id,
            last_rotated_at=get_utc_now(),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row

    def rotate_credential(
        self, db: Session, tenant_id: str, credential_id: str, user_id: str, credentials: dict[str, Any]
    ) -> ThreatSourceCredential:
        row = self.require_credential(db, tenant_id, credential_id)
        if not isinstance(credentials, dict) or not credentials:
            raise IOCCommercialError("THREAT_SOURCE_CREDENTIAL_INVALID", "Replacement credentials are required")
        row.encrypted_credentials = encrypt_json_secret(credentials)
        row.encryption_key_version = self.settings.ENCRYPTION_CURRENT_KEY_VERSION
        row.credential_fingerprint = fingerprint_secret(credentials)
        row.safe_metadata = {**(row.safe_metadata or {}), "credential_fields": sorted(credentials)}
        row.last_rotated_at = get_utc_now()
        row.updated_by = user_id
        row.status = "active"
        db.commit()
        db.refresh(row)
        return row

    @staticmethod
    def require_credential(db: Session, tenant_id: str, credential_id: str) -> ThreatSourceCredential:
        row = db.query(ThreatSourceCredential).filter_by(id=credential_id, tenant_id=tenant_id).first()
        if not row:
            raise IOCCommercialError("THREAT_SOURCE_NOT_CONFIGURED", "Threat source is not configured")
        return row

    def validate_external_url(self, url: str) -> str:
        validated = validate_sync_url(url)
        host = httpx.URL(validated).host or ""
        allow = {item.casefold() for item in self.settings.THREAT_SOURCE_ALLOWED_DESTINATIONS}
        if allow and host.casefold() not in allow:
            raise IOCCommercialError("THREAT_SOURCE_CREDENTIAL_INVALID", "Destination is not approved")
        return validated

    def safe_request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict | None = None,
    ) -> httpx.Response:
        current = self.validate_external_url(url)
        for _ in range(self.settings.THREAT_SOURCE_MAX_REDIRECTS + 1):
            try:
                with httpx.Client(
                    timeout=self.settings.THREAT_SOURCE_REQUEST_TIMEOUT_SECONDS,
                    verify=True,
                    follow_redirects=False,
                ) as client:
                    with client.stream(
                        method, current, headers=headers, json=json_body
                    ) as streamed:
                        if streamed.is_redirect:
                            location = streamed.headers.get("location")
                            if not location:
                                raise IOCCommercialError(
                                    "THREAT_SOURCE_CONNECTION_FAILED",
                                    "Invalid redirect response",
                                )
                            current = self.validate_external_url(
                                urljoin(current, location)
                            )
                            continue
                        try:
                            content_length = int(
                                streamed.headers.get("content-length") or 0
                            )
                        except ValueError:
                            content_length = 0
                        if content_length > self.settings.THREAT_SOURCE_MAX_RESPONSE_BYTES:
                            raise IOCCommercialError(
                                "THREAT_SOURCE_CONNECTION_FAILED",
                                "Threat source response exceeds configured limit",
                            )
                        content = bytearray()
                        for chunk in streamed.iter_bytes():
                            content.extend(chunk)
                            if len(content) > self.settings.THREAT_SOURCE_MAX_RESPONSE_BYTES:
                                raise IOCCommercialError(
                                    "THREAT_SOURCE_CONNECTION_FAILED",
                                    "Threat source response exceeds configured limit",
                                )
                        return httpx.Response(
                            status_code=streamed.status_code,
                            headers=streamed.headers,
                            content=bytes(content),
                            request=streamed.request,
                        )
            except IOCCommercialError:
                raise
            except httpx.HTTPError as exc:
                raise IOCCommercialError(
                    "THREAT_SOURCE_CONNECTION_FAILED",
                    "Threat source connection failed",
                ) from exc
        raise IOCCommercialError("THREAT_SOURCE_CONNECTION_FAILED", "Threat source redirected too many times")

    def test_credential(self, db: Session, tenant_id: str, credential_id: str) -> dict[str, Any]:
        row = self.require_credential(db, tenant_id, credential_id)
        secret = decrypt_json_secret(row.encrypted_credentials, key_version=row.encryption_key_version)
        try:
            if row.provider == "virustotal":
                response = self.safe_request("GET", "https://www.virustotal.com/api/v3/users/current", headers={"x-apikey": str(secret.get("api_key", ""))})
            elif row.provider == "abuseipdb":
                response = self.safe_request("GET", "https://api.abuseipdb.com/api/v2/check?ipAddress=192.0.2.1", headers={"Key": str(secret.get("api_key", "")), "Accept": "application/json"})
            elif row.provider == "otx":
                response = self.safe_request("GET", "https://otx.alienvault.com/api/v1/user/me", headers={"X-OTX-API-KEY": str(secret.get("api_key", ""))})
            else:
                response = self.safe_request("GET", row.base_url or "", headers=self._source_headers(row, secret))
            if response.status_code >= 400:
                raise IOCCommercialError("THREAT_SOURCE_CONNECTION_FAILED", "Threat source rejected the connection")
        except (httpx.HTTPError, ValueError) as exc:
            row.last_tested_at = get_utc_now()
            db.commit()
            if isinstance(exc, IOCCommercialError):
                raise
            raise IOCCommercialError("THREAT_SOURCE_CONNECTION_FAILED", "Threat source connection failed") from exc
        row.last_tested_at = row.last_successful_use_at = get_utc_now()
        db.commit()
        return {"connected": True, "provider": row.provider, "tested_at": row.last_tested_at}

    @staticmethod
    def _source_headers(row: ThreatSourceCredential, secret: dict) -> dict[str, str]:
        if row.provider == "misp":
            return {"Authorization": str(secret.get("api_key", "")), "Accept": "application/json"}
        token = str(secret.get("token") or secret.get("api_key") or "")
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    def create_sync_configuration(self, db: Session, user: User, payload: dict) -> ThreatSyncConfiguration:
        provider = str(payload.get("provider") or "").lower()
        if provider not in {"taxii", "misp"}:
            raise IOCCommercialError("THREAT_SOURCE_CREDENTIAL_INVALID", "Only TAXII and MISP synchronization are supported")
        credential = self.require_credential(db, user.tenant_id, str(payload.get("credential_id") or ""))
        if credential.provider != provider:
            raise IOCCommercialError("THREAT_SOURCE_CREDENTIAL_INVALID", "Credential provider does not match configuration")
        api_root = self.validate_external_url(str(payload.get("api_root") or credential.base_url or ""))
        schedule = payload.get("schedule_seconds")
        if schedule is not None and int(schedule) < 3600:
            raise IOCCommercialError("TAXII_SYNC_CONFLICT" if provider == "taxii" else "MISP_SYNC_CONFLICT", "Synchronization interval must be at least one hour")
        defaults = {
            "import_mode": payload.get("import_mode") or "review_required",
            "default_reliability": min(max(int(payload.get("default_reliability") or 50), 0), 100),
            "default_tlp": payload.get("default_tlp") or "TLP:AMBER",
            "default_lifecycle": payload.get("default_lifecycle") or "new",
            "watchlist_id": payload.get("watchlist_id"),
            "enrich": bool(payload.get("enrich")),
            "hunt": bool(payload.get("hunt")),
        }
        row = ThreatSyncConfiguration(
            tenant_id=user.tenant_id,
            credential_id=credential.id,
            provider=provider,
            name=str(payload.get("name") or f"{provider.upper()} synchronization")[:150],
            api_root=api_root,
            collection_id=payload.get("collection_id"),
            settings=defaults,
            safe_cursor={},
            schedule_seconds=int(schedule) if schedule else None,
            enabled=bool(payload.get("enabled", False)),
            created_by=user.id,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row

    def start_sync(self, db: Session, user: User, configuration_id: str, direction: str = "pull") -> ThreatSyncJob:
        config = db.query(ThreatSyncConfiguration).filter_by(id=configuration_id, tenant_id=user.tenant_id).first()
        if not config:
            raise IOCCommercialError("TAXII_COLLECTION_NOT_FOUND", "Synchronization configuration not found")
        tenant = db.get(Tenant, user.tenant_id)
        if not tenant or tenant.status != OrganizationStatus.ACTIVE:
            raise IOCCommercialError("TAXII_SYNC_CONFLICT", "Organization is not active")
        running = db.query(ThreatSyncJob).filter(
            ThreatSyncJob.tenant_id == user.tenant_id,
            ThreatSyncJob.configuration_id == config.id,
            ThreatSyncJob.status.in_(["pending", "running"]),
        ).first()
        if running:
            raise IOCCommercialError("TAXII_SYNC_CONFLICT" if config.provider == "taxii" else "MISP_SYNC_CONFLICT", "Synchronization is already running")
        job = ThreatSyncJob(
            tenant_id=user.tenant_id,
            configuration_id=config.id,
            provider=config.provider,
            direction=direction,
            counts={"imported": 0, "updated": 0, "duplicates": 0, "rejected": 0, "failed": 0, "unsupported": 0},
            failure_details={},
            requested_by=user.id,
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    def process_sync(self, db: Session, job_id: str, tenant_id: str) -> ThreatSyncJob:
        job = db.query(ThreatSyncJob).filter_by(id=job_id, tenant_id=tenant_id).first()
        if not job:
            raise IOCCommercialError("TAXII_SYNC_FAILED", "Synchronization job not found")
        if job.cancellation_requested or job.status == "cancelled":
            job.status, job.completed_at = "cancelled", get_utc_now()
            db.commit()
            return job
        config = db.query(ThreatSyncConfiguration).filter_by(id=job.configuration_id, tenant_id=tenant_id).first()
        if not config:
            raise IOCCommercialError("TAXII_SYNC_FAILED", "Synchronization configuration not found")
        credential = self.require_credential(db, tenant_id, config.credential_id)
        job.status, job.started_at, job.progress = "running", get_utc_now(), 5
        db.commit()
        try:
            if job.direction == "push" and config.provider == "misp":
                self._misp_export(db, config, credential, job)
            elif config.provider == "taxii":
                self._taxii_pull(db, config, credential, job)
            else:
                self._misp_pull(db, config, credential, job)
            if job.status == "cancelled" or job.cancellation_requested:
                job.status, job.completed_at = "cancelled", get_utc_now()
                db.commit()
                return job
            job.status, job.progress, job.completed_at = "completed", 100, get_utc_now()
            config.cursor_updated_at = get_utc_now()
            credential.last_successful_use_at = get_utc_now()
            flag_modified(job, "counts")
            db.commit()
        except IOCCommercialError as exc:
            db.rollback()
            job = db.query(ThreatSyncJob).filter_by(id=job_id, tenant_id=tenant_id).first()
            job.status, job.failure_code, job.completed_at = "failed", exc.code, get_utc_now()
            job.failure_details = {"message": exc.message}
            db.commit()
        return job

    def _taxii_pull(self, db: Session, config: ThreatSyncConfiguration, credential: ThreatSourceCredential, job: ThreatSyncJob) -> None:
        secret = decrypt_json_secret(credential.encrypted_credentials, key_version=credential.encryption_key_version)
        headers = {**self._source_headers(credential, secret), "Accept": "application/taxii+json;version=2.1"}
        collection = config.collection_id
        if not collection:
            raise IOCCommercialError("TAXII_COLLECTION_NOT_FOUND", "A TAXII collection is required")
        url = f"{config.api_root.rstrip('/')}/collections/{collection}/objects/"
        cursor = (config.safe_cursor or {}).get("added_after")
        if cursor:
            url += f"?added_after={cursor}"
        object_count = 0
        pages = 0
        latest = cursor
        while url:
            if job.cancellation_requested:
                job.status, job.completed_at = "cancelled", get_utc_now()
                db.commit()
                return
            pages += 1
            if pages > self.settings.TAXII_SYNC_MAX_PAGES:
                raise IOCCommercialError("TAXII_SYNC_FAILED", "TAXII page limit exceeded")
            response = self.safe_request("GET", url, headers=headers)
            if response.status_code == 404:
                raise IOCCommercialError("TAXII_COLLECTION_NOT_FOUND", "TAXII collection not found")
            if response.status_code >= 400:
                raise IOCCommercialError("TAXII_SYNC_FAILED", "TAXII synchronization failed")
            payload = response.json()
            objects = payload.get("objects") or []
            object_count += len(objects)
            if object_count > self.settings.TAXII_SYNC_MAX_OBJECTS:
                raise IOCCommercialError("TAXII_SYNC_FAILED", "TAXII object limit exceeded")
            parsed = parse_stix_bundle({"type": "bundle", "id": f"bundle--{secrets.token_hex(16)}", "objects": objects})
            self._import_normalized_rows(db, config, job, parsed["indicators"])
            job.counts["unsupported"] += len(parsed["unsupported"])
            latest = response.headers.get("X-TAXII-Date-Added-Last") or latest
            next_value = payload.get("next")
            url = self.validate_external_url(urljoin(url, str(next_value))) if payload.get("more") and next_value else ""
            job.progress = min(95, 5 + pages)
            flag_modified(job, "counts")
            db.commit()
        config.safe_cursor = {"added_after": latest or get_utc_now().isoformat()}

    def _misp_pull(self, db: Session, config: ThreatSyncConfiguration, credential: ThreatSourceCredential, job: ThreatSyncJob) -> None:
        secret = decrypt_json_secret(credential.encrypted_credentials, key_version=credential.encryption_key_version)
        headers = self._source_headers(credential, secret)
        body = {"returnFormat": "json", "limit": self.settings.MISP_SYNC_MAX_OBJECTS}
        timestamp = (config.safe_cursor or {}).get("timestamp")
        if timestamp:
            body["timestamp"] = timestamp
        response = self.safe_request("POST", f"{config.api_root.rstrip('/')}/attributes/restSearch", headers=headers, json_body=body)
        if response.status_code >= 400:
            raise IOCCommercialError("MISP_SYNC_FAILED", "MISP synchronization failed")
        payload = response.json()
        attributes = payload.get("response", {}).get("Attribute") or payload.get("Attribute") or []
        if len(attributes) > self.settings.MISP_SYNC_MAX_OBJECTS:
            raise IOCCommercialError("MISP_SYNC_FAILED", "MISP object limit exceeded")
        rows, unsupported = [], 0
        for attribute in attributes:
            mapped = self._map_misp_attribute(attribute)
            if mapped:
                rows.append(mapped)
            else:
                unsupported += 1
        self._import_normalized_rows(db, config, job, rows)
        job.counts["unsupported"] += unsupported
        config.safe_cursor = {"timestamp": get_utc_now().isoformat()}

    def _misp_export(self, db: Session, config: ThreatSyncConfiguration, credential: ThreatSourceCredential, job: ThreatSyncJob) -> None:
        secret = decrypt_json_secret(credential.encrypted_credentials, key_version=credential.encryption_key_version)
        rows = db.query(IOC).filter(
            IOC.tenant_id == config.tenant_id,
            IOC.lifecycle_status == "active",
            IOC.review_status.in_(["approved", "completed"]),
            IOC.tlp != "TLP:RED",
        ).limit(self.settings.MISP_SYNC_MAX_OBJECTS).all()
        exported = 0
        for ioc in rows:
            body = {"value": ioc.normalized_value, "type": self._misp_export_type(ioc.type.value), "to_ids": True, "comment": "Exported by TriageOps"}
            response = self.safe_request("POST", f"{config.api_root.rstrip('/')}/attributes/add", headers=self._source_headers(credential, secret), json_body=body)
            if response.status_code < 400:
                exported += 1
            else:
                job.counts["failed"] += 1
        job.counts["exported"] = exported

    @staticmethod
    def _misp_export_type(ioc_type: str) -> str:
        return {"ipv4": "ip-dst", "ipv6": "ip-dst", "file_name": "filename", "registry_key": "regkey"}.get(ioc_type, ioc_type)

    def _map_misp_attribute(self, attribute: dict) -> dict | None:
        mapped_type = MISP_TYPE_MAP.get(str(attribute.get("type") or ""))
        if not mapped_type:
            return None
        value = str(attribute.get("value") or "")
        if "|" in value and "|" in str(attribute.get("type") or ""):
            parts = value.split("|")
            value = parts[-1] if mapped_type in {"md5", "sha1", "sha256"} else parts[0]
        normalized = normalize_ioc(mapped_type, value)
        tags = [str(item.get("name")) for item in attribute.get("Tag") or [] if item.get("name")]
        tlp = next((tag.upper().replace("TLP:", "TLP:") for tag in tags if tag.lower().startswith("tlp:")), "TLP:AMBER")
        return {
            "type": normalized.type,
            "value": value,
            "normalized_value": normalized.canonical,
            "display_value": normalized.display,
            "source": "misp",
            "external_source_ids": {"misp_uuid": attribute.get("uuid")},
            "source_references": [],
            "tags": tags,
            "tlp": tlp,
        }

    def _import_normalized_rows(self, db: Session, config: ThreatSyncConfiguration, job: ThreatSyncJob, rows: Iterable[dict]) -> None:
        defaults = config.settings or {}
        for item in rows:
            try:
                lifecycle = "active" if defaults.get("import_mode") == "trusted" else defaults.get("default_lifecycle", "new")
                created = ioc_service.create_ioc(
                    db,
                    config.tenant_id,
                    job.requested_by or "",
                    IOCCreate(
                        type=item["type"],
                        value=item.get("value") or item.get("normalized_value"),
                        source=item.get("source") or config.provider,
                        source_reliability=int(defaults.get("default_reliability", 50)),
                        confidence_score=int(item.get("confidence_score") or 50),
                        tlp=item.get("tlp") or defaults.get("default_tlp", "TLP:AMBER"),
                        lifecycle_status=lifecycle,
                        source_references=item.get("source_references") or [],
                        external_source_ids=item.get("external_source_ids") or {},
                        stix_id=item.get("stix_id"),
                        tags=item.get("tags") or [],
                    ),
                )
                job.counts["imported"] += 1
                if defaults.get("watchlist_id"):
                    self._add_watchlist_member(db, config.tenant_id, defaults["watchlist_id"], created.id)
            except IOCDuplicateError:
                job.counts["duplicates"] += 1
            except (IOCValidationError, ValueError, TypeError):
                job.counts["rejected"] += 1

    @staticmethod
    def _add_watchlist_member(db: Session, tenant_id: str, watchlist_id: str, ioc_id: str) -> None:
        if not db.query(IOCWatchlist).filter_by(id=watchlist_id, tenant_id=tenant_id).first():
            return
        if not db.query(IOCWatchlistMember).filter_by(tenant_id=tenant_id, watchlist_id=watchlist_id, ioc_id=ioc_id).first():
            db.add(IOCWatchlistMember(tenant_id=tenant_id, watchlist_id=watchlist_id, ioc_id=ioc_id))
            db.commit()

    def create_import_job(self, db: Session, user: User, filename: str, format_name: str, payload: bytes, options: dict) -> IOCImportJob:
        if len(payload) > self.settings.IOC_BULK_IMPORT_MAX_BYTES:
            raise IOCCommercialError("IOC_IMPORT_INVALID", "Import exceeds configured size limit")
        if format_name not in {"csv", "json", "jsonl", "stix", "misp"}:
            raise IOCCommercialError("IOC_IMPORT_INVALID", "Unsupported import format")
        safe_name = Path(filename or "import").name.replace("\x00", "")[:255]
        artifact = encrypt_bytes(payload)
        key = f"{user.tenant_id}/{secrets.token_hex(16)}.ioc-import.bin"
        LocalAuditArtifactStorage(self.settings.IOC_COMMERCIAL_ARTIFACT_DIRECTORY).write(key, artifact)
        job = IOCImportJob(
            tenant_id=user.tenant_id,
            format=format_name,
            original_filename=safe_name,
            artifact_key=key,
            artifact_checksum=hashlib.sha256(payload).hexdigest(),
            status="uploaded",
            dry_run=bool(options.get("dry_run", True)),
            options=options,
            counts={"valid": 0, "invalid": 0, "duplicates": 0, "created": 0},
            requested_by=user.id,
            expires_at=get_utc_now() + timedelta(hours=self.settings.IOC_IMPORT_ARTIFACT_HOURS),
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    def process_import(self, db: Session, job_id: str, tenant_id: str) -> IOCImportJob:
        job = db.query(IOCImportJob).filter_by(id=job_id, tenant_id=tenant_id).first()
        if not job:
            raise IOCCommercialError("IOC_IMPORT_NOT_READY", "Import job not found")
        job.status, job.progress = "running", 5
        db.commit()
        try:
            encrypted = LocalAuditArtifactStorage(self.settings.IOC_COMMERCIAL_ARTIFACT_DIRECTORY).read(job.artifact_key)
            payload = decrypt_bytes(encrypted)
            rows = self._parse_import_rows(job.format, payload)
            for row_number, item in enumerate(rows, 1):
                if row_number > self.settings.IOC_BULK_IMPORT_MAX_ROWS:
                    raise IOCCommercialError("IOC_BULK_LIMIT_EXCEEDED", "Import row limit exceeded")
                if job.cancellation_requested:
                    job.status, job.completed_at = "cancelled", get_utc_now()
                    db.commit()
                    return job
                self._process_import_row(db, job, row_number, item)
                if row_number % 100 == 0:
                    job.progress = min(95, 5 + int(row_number / self.settings.IOC_BULK_IMPORT_MAX_ROWS * 90))
                    db.commit()
            job.status, job.progress, job.completed_at = "validated" if job.dry_run else "completed", 100, get_utc_now()
            flag_modified(job, "counts")
            db.commit()
        except IOCCommercialError as exc:
            db.rollback()
            job = db.query(IOCImportJob).filter_by(id=job_id, tenant_id=tenant_id).first()
            job.status, job.error_code, job.completed_at = "failed", exc.code, get_utc_now()
            db.commit()
        return job

    def _parse_import_rows(self, format_name: str, payload: bytes) -> Iterable[dict]:
        text = payload.decode("utf-8-sig")
        if format_name == "csv":
            yield from csv.DictReader(io.StringIO(text))
        elif format_name == "jsonl":
            for line in io.StringIO(text):
                if line.strip():
                    yield json.loads(line)
        elif format_name == "json":
            data = json.loads(text)
            yield from (data if isinstance(data, list) else data.get("items") or [])
        elif format_name == "stix":
            yield from parse_stix_bundle(json.loads(text))["indicators"]
        else:
            data = json.loads(text)
            events = data.get("response") or data.get("Event") or []
            if isinstance(events, dict):
                events = [events]
            for event in events:
                body = event.get("Event") or event
                for attribute in body.get("Attribute") or []:
                    mapped = self._map_misp_attribute(attribute)
                    if mapped:
                        yield mapped

    def _process_import_row(self, db: Session, job: IOCImportJob, row_number: int, item: dict) -> None:
        options = job.options or {}
        try:
            kind = item.get(options.get("type_field", "type")) or item.get("ioc_type")
            value = item.get(options.get("value_field", "value")) or item.get("normalized_value")
            normalized = normalize_ioc(kind, value)
            duplicate = db.query(IOC).filter_by(
                tenant_id=job.tenant_id,
                type=normalized.type,
                normalized_value=normalized.canonical,
            ).first()
            if duplicate:
                status, ioc_id = "duplicate", duplicate.id
                job.counts["duplicates"] += 1
            elif job.dry_run:
                status, ioc_id = "valid", None
                job.counts["valid"] += 1
            else:
                created = ioc_service.create_ioc(
                    db,
                    job.tenant_id,
                    job.requested_by or "",
                    IOCCreate(
                        type=normalized.type,
                        value=value,
                        source=item.get("source") or options.get("source") or "bulk_import",
                        confidence_score=int(item.get("confidence_score") or options.get("confidence", 50)),
                        source_reliability=int(item.get("source_reliability") or options.get("source_reliability", 50)),
                        tlp=item.get("tlp") or options.get("tlp", "TLP:AMBER"),
                        lifecycle_status=options.get("lifecycle_status", "new"),
                        tags=list(set((item.get("tags") or []) + (options.get("tags") or []))),
                        stix_id=item.get("stix_id"),
                        external_source_ids=item.get("external_source_ids") or {},
                        source_references=item.get("source_references") or [],
                    ),
                )
                status, ioc_id = "created", created.id
                job.counts["created"] += 1
                if options.get("watchlist_id"):
                    self._add_watchlist_member(db, job.tenant_id, options["watchlist_id"], created.id)
            result = IOCImportRowResult(
                tenant_id=job.tenant_id,
                job_id=job.id,
                row_number=row_number,
                status=status,
                ioc_id=ioc_id,
                safe_details={"type": normalized.type, "normalized_value_hash": hashlib.sha256(normalized.canonical.encode()).hexdigest()},
            )
        except (IOCValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
            job.counts["invalid"] += 1
            result = IOCImportRowResult(
                tenant_id=job.tenant_id,
                job_id=job.id,
                row_number=row_number,
                status="invalid",
                error_code="IOC_VALUE_INVALID",
                safe_details={"message": str(exc)[:300]},
            )
        db.add(result)
        db.flush()

    def create_bulk_job(self, db: Session, user: User, payload: dict, confirmed: bool) -> IOCBulkActionJob:
        action = str(payload.get("action") or "")
        ioc_ids = list(dict.fromkeys(payload.get("ioc_ids") or []))
        if action not in ALLOWED_BULK_ACTIONS:
            raise IOCCommercialError("IOC_BULK_LIMIT_EXCEEDED", "Unsupported bulk action")
        if not ioc_ids or len(ioc_ids) > self.settings.IOC_BULK_ACTION_MAX_SIZE:
            raise IOCCommercialError("IOC_BULK_LIMIT_EXCEEDED", "Bulk action size is invalid")
        matched = db.query(IOC.id).filter(IOC.tenant_id == user.tenant_id, IOC.id.in_(ioc_ids)).count()
        if matched != len(ioc_ids):
            raise IOCCommercialError("IOC_BULK_LIMIT_EXCEEDED", "Bulk action contains unavailable IOCs")
        destructive = action in {"expire", "revoke", "false_positive", "allowlist"}
        preview = {"requested": len(ioc_ids), "matched": matched, "destructive": destructive, "requires_confirmation": destructive}
        job = IOCBulkActionJob(
            tenant_id=user.tenant_id,
            action=action,
            status="pending" if confirmed or not destructive else "preview",
            preview=preview,
            request={"ioc_ids": ioc_ids, "options": payload.get("options") or {}},
            results=[],
            requested_by=user.id,
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    def process_bulk(self, db: Session, job_id: str, tenant_id: str) -> IOCBulkActionJob:
        job = db.query(IOCBulkActionJob).filter_by(id=job_id, tenant_id=tenant_id).first()
        if not job or job.status == "preview":
            raise IOCCommercialError("IOC_IMPORT_NOT_READY", "Bulk action is not ready")
        job.status = "running"
        db.commit()
        ids = job.request.get("ioc_ids") or []
        options = job.request.get("options") or {}
        results = []
        for index, ioc_id in enumerate(ids):
            if job.cancellation_requested:
                job.status, job.completed_at = "cancelled", get_utc_now()
                break
            ioc = db.query(IOC).filter_by(id=ioc_id, tenant_id=tenant_id).first()
            if not ioc:
                results.append({"ioc_id": ioc_id, "status": "not_found"})
                continue
            try:
                self._apply_bulk_action(db, job.action, ioc, options)
                results.append({"ioc_id": ioc_id, "status": "completed"})
            except (IOCValidationError, IOCCommercialError, ValueError) as exc:
                results.append({"ioc_id": ioc_id, "status": "failed", "error_code": getattr(exc, "code", "IOC_STATE_INVALID")})
            job.progress = int(((index + 1) / len(ids)) * 100)
        job.results = results
        if job.status != "cancelled":
            job.status, job.completed_at = "completed", get_utc_now()
        db.commit()
        return job

    def _apply_bulk_action(self, db: Session, action: str, ioc: IOC, options: dict) -> None:
        if action == "rescore":
            ioc_intelligence_service.recalculate(db, ioc)
        elif action in {"activate", "monitor", "expire", "revoke", "false_positive", "allowlist"}:
            target = {
                "activate": "active", "monitor": "monitoring", "expire": "expired",
                "revoke": "revoked", "false_positive": "false_positive", "allowlist": "allowlisted",
            }[action]
            ioc_intelligence_service.transition(ioc, target, options.get("reason") or f"Bulk {action}")
        elif action in {"add_tags", "remove_tags"}:
            tags = set(ioc.tags or [])
            requested = set(options.get("tags") or [])
            ioc.tags = sorted(tags | requested if action == "add_tags" else tags - requested)
        elif action in {"add_to_watchlist", "remove_from_watchlist"}:
            watchlist_id = str(options.get("watchlist_id") or "")
            if action == "add_to_watchlist":
                self._add_watchlist_member(db, ioc.tenant_id, watchlist_id, ioc.id)
            else:
                db.query(IOCWatchlistMember).filter_by(tenant_id=ioc.tenant_id, watchlist_id=watchlist_id, ioc_id=ioc.id).delete()
        elif action == "assign_reviewer":
            self.assign_reviewer(db, ioc.tenant_id, ioc.id, str(options.get("reviewer_id") or ""), None, options.get("due_at"))
        elif action == "hunt":
            db.add(IOCHuntJob(tenant_id=ioc.tenant_id, ioc_id=ioc.id, query={"days": int(options.get("days") or 30), "event_limit": self.settings.IOC_HUNT_MAX_EVENTS}))
        elif action == "enrich":
            from src.services.threat_intel_service import threat_intel_service
            threat_intel_service.enrich_ioc(db, ioc)
        db.add(ioc)
        db.flush()

    def assign_reviewer(self, db: Session, tenant_id: str, ioc_id: str, reviewer_id: str, assigned_by: str | None, due_at=None) -> IOCReviewAssignment:
        membership = db.query(OrganizationMembership).filter_by(
            tenant_id=tenant_id, user_id=reviewer_id, is_active=True
        ).first()
        ioc = db.query(IOC).filter_by(id=ioc_id, tenant_id=tenant_id).first()
        if not membership or not ioc:
            raise IOCCommercialError("IOC_REVIEW_ASSIGNMENT_INVALID", "Reviewer must be an active member of this organization")
        db.query(IOCReviewAssignment).filter_by(tenant_id=tenant_id, ioc_id=ioc_id, status="assigned").update({"status": "reassigned", "completed_at": get_utc_now()})
        row = IOCReviewAssignment(
            tenant_id=tenant_id, ioc_id=ioc_id, reviewer_id=reviewer_id,
            assigned_by=assigned_by, due_at=due_at,
        )
        ioc.reviewed_by = reviewer_id
        ioc.review_status = "assigned"
        db.add(row)
        db.flush()
        db.add(IOCReviewHistory(
            tenant_id=tenant_id, ioc_id=ioc_id, assignment_id=row.id,
            actor_id=assigned_by, action="assigned", after_values={"reviewer_id": reviewer_id},
        ))
        db.commit()
        db.refresh(row)
        return row

    def review_decision(self, db: Session, user: User, ioc_id: str, payload: dict) -> IOC:
        ioc = db.query(IOC).filter_by(id=ioc_id, tenant_id=user.tenant_id).first()
        if not ioc:
            raise IOCCommercialError("IOC_REVIEW_ASSIGNMENT_INVALID", "IOC not found")
        action = str(payload.get("action") or "")
        if action == "approve_activate" and ioc.created_by == user.id and bool(payload.get("prevent_self_approval", True)):
            raise IOCCommercialError("IOC_REVIEW_ASSIGNMENT_INVALID", "IOC creator cannot self-approve")
        before = {"lifecycle_status": ioc.lifecycle_status, "confidence_score": ioc.confidence_score, "source_reliability": ioc.source_reliability}
        if payload.get("confidence_score") is not None:
            ioc.confidence_score = min(max(int(payload["confidence_score"]), 0), 100)
        if payload.get("source_reliability") is not None:
            ioc.source_reliability = min(max(int(payload["source_reliability"]), 0), 100)
        transitions = {
            "approve_activate": "active", "request_changes": "under_review",
            "false_positive": "false_positive", "allowlist": "allowlisted",
            "revoke": "revoked", "archive": "archived",
        }
        if action in transitions:
            ioc_intelligence_service.transition(ioc, transitions[action], str(payload.get("comment") or action))
        ioc.review_status = "approved" if action == "approve_activate" else action
        ioc.reviewed_by = user.id
        ioc.reviewed_at = get_utc_now()
        ioc_intelligence_service.recalculate(db, ioc)
        revision = db.query(IOCReviewHistory).filter_by(tenant_id=user.tenant_id, ioc_id=ioc.id).count() + 1
        db.add(IOCReviewHistory(
            tenant_id=user.tenant_id, ioc_id=ioc.id, actor_id=user.id,
            action=action, comment=str(payload.get("comment") or "")[:5000], revision=revision,
            before_values=before,
            after_values={"lifecycle_status": ioc.lifecycle_status, "confidence_score": ioc.confidence_score, "source_reliability": ioc.source_reliability},
        ))
        db.query(IOCReviewAssignment).filter_by(tenant_id=user.tenant_id, ioc_id=ioc.id, status="assigned").update({"status": "completed", "completed_at": get_utc_now()})
        db.commit()
        db.refresh(ioc)
        return ioc

    def graph(self, db: Session, tenant_id: str, ioc_id: str, depth: int, min_confidence: int = 0) -> dict:
        depth = min(max(depth, 1), self.settings.IOC_GRAPH_MAX_DEPTH)
        root = db.query(IOC).filter_by(id=ioc_id, tenant_id=tenant_id).first()
        if not root:
            raise IOCCommercialError("IOC_RELATIONSHIP_LIMIT_EXCEEDED", "IOC not found")
        nodes: dict[str, dict] = {
            f"ioc:{root.id}": {"id": root.id, "type": "ioc", "label": root.display_value, "href": f"/threat-intel/{root.id}"}
        }
        edges: list[dict] = []
        frontier = {root.id}
        for _ in range(depth):
            if not frontier:
                break
            relationships = db.query(ThreatIntelligenceRelationship).filter(
                ThreatIntelligenceRelationship.tenant_id == tenant_id,
                ThreatIntelligenceRelationship.confidence >= min_confidence,
                or_(
                    ThreatIntelligenceRelationship.source_id.in_(frontier),
                    ThreatIntelligenceRelationship.target_id.in_(frontier),
                ),
            ).limit(self.settings.IOC_GRAPH_MAX_EDGES - len(edges) + 1).all()
            next_frontier = set()
            for item in relationships:
                for object_type, object_id in ((item.source_type, item.source_id), (item.target_type, item.target_id)):
                    key = f"{object_type}:{object_id}"
                    if key not in nodes:
                        nodes[key] = {"id": object_id, "type": object_type, "label": object_id}
                        if object_type == "ioc":
                            next_frontier.add(object_id)
                edges.append({
                    "id": item.id, "source": f"{item.source_type}:{item.source_id}",
                    "target": f"{item.target_type}:{item.target_id}",
                    "type": item.relationship_type, "origin": item.origin,
                    "confidence": item.confidence, "evidence_count": len(item.evidence_references or []),
                })
                if len(nodes) > self.settings.IOC_GRAPH_MAX_NODES or len(edges) > self.settings.IOC_GRAPH_MAX_EDGES:
                    raise IOCCommercialError("IOC_RELATIONSHIP_LIMIT_EXCEEDED", "Relationship graph exceeds configured limits")
            frontier = next_frontier
        sightings = db.query(IOCSighting).filter_by(tenant_id=tenant_id, ioc_id=ioc_id).limit(100).all()
        for item in sightings:
            event_key = f"event:{item.event_id}"
            nodes[event_key] = {"id": item.event_id, "type": "event", "label": item.event_id, "href": f"/events/{item.event_id}"}
            edges.append({"id": f"sighting:{item.id}", "source": f"ioc:{ioc_id}", "target": event_key, "type": "observed-in", "origin": "observed", "confidence": item.confidence, "evidence_count": 1})
        return {"nodes": list(nodes.values()), "edges": edges, "truncated": len(nodes) >= self.settings.IOC_GRAPH_MAX_NODES or len(edges) >= self.settings.IOC_GRAPH_MAX_EDGES, "limits": {"depth": depth, "nodes": self.settings.IOC_GRAPH_MAX_NODES, "edges": self.settings.IOC_GRAPH_MAX_EDGES}}

    def generate_detection(self, db: Session, user: User, ioc_id: str, payload: dict) -> DetectionRule:
        ioc = db.query(IOC).filter_by(id=ioc_id, tenant_id=user.tenant_id).first()
        if not ioc:
            raise IOCCommercialError("IOC_DETECTION_GENERATION_FAILED", "IOC not found")
        fields = payload.get("fields") or self._default_detection_fields(ioc.type.value)
        allowed = set(self._default_detection_fields(ioc.type.value))
        if not fields or any(field not in allowed for field in fields):
            raise IOCCommercialError("IOC_DETECTION_GENERATION_FAILED", "Selected matching fields are unsupported")
        definition = {
            "kind": "event_match",
            "conditions": [{"field": field, "operator": "eq", "value": ioc.normalized_value} for field in fields],
            "condition_logic": "any",
            "window_seconds": 10,
            "group_by": payload.get("group_by") or [],
            "alert_policy": {
                "severity": payload.get("severity") or "medium",
                "confidence": min(max(int(payload.get("confidence") or ioc.confidence_score), 0), 100),
                "suppression_seconds": min(max(int(payload.get("suppression_seconds") or 300), 0), 86400),
            },
            "provenance": {"source_type": "ioc", "source_id": ioc.id, "content_hash": ioc.content_hash},
        }
        validation = detection_lifecycle_service.validate(definition, db=db)
        if not validation["valid"]:
            raise IOCCommercialError("IOC_DETECTION_GENERATION_FAILED", "Generated detection did not validate")
        rule = DetectionRule(
            tenant_id=user.tenant_id,
            name=str(payload.get("name") or f"IOC match: {ioc.display_value}")[:255],
            description=f"Draft generated from IOC {ioc.id}",
            type=RuleType.CUSTOM,
            rule_type=RuleType.CUSTOM,
            severity=Severity(str(payload.get("severity") or "medium")),
            enabled=False,
            detection_kind="event_match",
            lifecycle_status="draft",
            created_by=user.id,
            owner_id=user.id,
            tags=["ioc-generated", f"ioc:{ioc.id}"],
            protected=False,
        )
        db.add(rule)
        db.flush()
        version = detection_lifecycle_service.create_version(db, rule, user.id, definition, summary=f"Generated from IOC {ioc.id}")
        version.source_metadata = {"source_type": "ioc", "source_id": ioc.id, "content_hash": ioc.content_hash}
        db.add(ThreatIntelligenceRelationship(
            tenant_id=user.tenant_id, relationship_type="detects",
            source_type="detection_rule", source_id=rule.id,
            target_type="ioc", target_id=ioc.id, confidence=100,
            created_by=user.id, source="ioc_detection_generation",
            evidence_references=[ioc.content_hash], origin="analyst_created",
        ))
        db.commit()
        db.refresh(rule)
        return rule

    @staticmethod
    def _default_detection_fields(ioc_type: str) -> list[str]:
        if ioc_type in {"ipv4", "ipv6", "ip", "cidr"}:
            return ["source.ip", "destination.ip"]
        if ioc_type == "domain":
            return ["domain"]
        if ioc_type == "url":
            return ["url"]
        if ioc_type in {"md5", "sha1", "sha256", "sha512", "hash"}:
            return {
                "md5": ["file.hash.md5"],
                "sha1": ["file.hash.sha1"],
                "sha256": ["file.hash.sha256"],
            }.get(ioc_type, ["file.hash.sha256"])
        if ioc_type == "email":
            return ["user.name"]
        return ["message"]

    def create_recommendation(self, db: Session, user: User, ioc_id: str, payload: dict) -> IOCResponseRecommendation:
        ioc = db.query(IOC).filter_by(id=ioc_id, tenant_id=user.tenant_id).first()
        action = str(payload.get("action") or "")
        if not ioc or action not in RESPONSE_ACTIONS:
            raise IOCCommercialError("IOC_RESPONSE_RECOMMENDATION_INVALID", "Response recommendation is invalid")
        safe_context = {
            "risk_score": ioc.risk_score,
            "risk_reasons": ioc.risk_reasons,
            "confidence": ioc.confidence_score,
            "internal_sightings": ioc.internal_sighting_count,
            "target_connector_type": str(payload.get("target_connector_type") or "")[:80],
        }
        approval_payload = SimpleNamespace(
            action_type="ioc.response.execute",
            target_resource_type="ioc",
            target_resource_id=ioc.id,
            safe_metadata={"action": action, "target_connector_type": safe_context["target_connector_type"], "ioc_content_hash": ioc.content_hash},
            expires_in_minutes=self.settings.IOC_RESPONSE_RECOMMENDATION_HOURS * 60,
        )
        approval = approval_service.create(db, user, approval_payload)
        fingerprint = approval.request_fingerprint
        row = db.query(IOCResponseRecommendation).filter_by(tenant_id=user.tenant_id, request_fingerprint=fingerprint).first()
        if row:
            return row
        row = IOCResponseRecommendation(
            tenant_id=user.tenant_id, ioc_id=ioc.id, action=action,
            target_connector_type=safe_context["target_connector_type"] or None,
            safe_context=safe_context, request_fingerprint=fingerprint,
            requester_id=user.id, approval_id=approval.id,
            expires_at=get_utc_now() + timedelta(hours=self.settings.IOC_RESPONSE_RECOMMENDATION_HOURS),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row

    def notification_allowed(self, db: Session, tenant_id: str, event_type: str, resource_id: str, tlp: str, recipient_scope: dict | None = None) -> bool:
        if tlp == "TLP:RED" and not (recipient_scope or {}).get("explicit_authorized_recipients"):
            return False
        key = hashlib.sha256(f"{tenant_id}:{event_type}:{resource_id}".encode()).hexdigest()
        now = get_utc_now()
        row = db.query(IOCNotificationState).filter_by(tenant_id=tenant_id, deduplication_key=key).first()
        if row and ensure_utc(row.cooldown_until) > now:
            return False
        if not row:
            row = IOCNotificationState(
                tenant_id=tenant_id, event_type=event_type, deduplication_key=key,
                recipient_scope=recipient_scope or {}, cooldown_until=now,
            )
            db.add(row)
        row.cooldown_until = now + timedelta(seconds=self.settings.IOC_NOTIFICATION_COOLDOWN_SECONDS)
        row.last_delivered_at = now
        row.delivery_status = "queued"
        row.delivery_count = (row.delivery_count or 0) + 1
        db.commit()
        return True

    def create_report(self, db: Session, user: User, report_type: str, format_name: str, filters: dict) -> IOCReportJob:
        formats = {"csv", "json", "jsonl", "markdown", "html", "stix", "zip"}
        if format_name not in formats:
            raise IOCCommercialError("IOC_REPORT_NOT_READY", "Report format is unsupported")
        job = IOCReportJob(
            tenant_id=user.tenant_id, report_type=report_type, format=format_name,
            filters=filters, manifest={}, requested_by=user.id,
            expires_at=get_utc_now() + timedelta(hours=self.settings.IOC_REPORT_ARTIFACT_HOURS),
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    def process_report(self, db: Session, job_id: str, tenant_id: str) -> IOCReportJob:
        job = db.query(IOCReportJob).filter_by(id=job_id, tenant_id=tenant_id).first()
        if not job:
            raise IOCCommercialError("IOC_REPORT_NOT_READY", "Report job not found")
        job.status = "running"
        db.commit()
        rows = db.query(IOC).filter(IOC.tenant_id == tenant_id, IOC.tlp != "TLP:RED").order_by(IOC.risk_score.desc()).limit(self.settings.IOC_REPORT_MAX_ROWS).all()
        records = [{
            "id": row.id, "type": row.type.value, "value": row.display_value,
            "risk_score": row.risk_score, "confidence": row.confidence_score,
            "source_reliability": row.source_reliability, "lifecycle_status": row.lifecycle_status,
            "tlp": row.tlp, "sightings": row.internal_sighting_count,
        } for row in rows]
        if job.format == "stix":
            payload = json.dumps(export_stix_bundle(rows, allow_tlp_red=False), sort_keys=True, default=str).encode()
        else:
            payload = self._report_payload(job.format, records)
        checksum = hashlib.sha256(payload).hexdigest()
        key = f"{tenant_id}/{job.id}.ioc-report.{self._report_extension(job.format)}"
        LocalAuditArtifactStorage(self.settings.IOC_COMMERCIAL_ARTIFACT_DIRECTORY).write(key, encrypt_bytes(payload))
        job.artifact_key, job.checksum = key, checksum
        job.manifest = {"sha256": checksum, "row_count": len(records), "format": job.format, "tlp_red_excluded": True}
        job.status, job.completed_at = "completed", get_utc_now()
        db.commit()
        return job

    def cleanup_expired_artifacts(self, db: Session) -> dict[str, int]:
        """Expire commercial artifacts without exposing or silently retaining payloads."""
        now = get_utc_now()
        storage = LocalAuditArtifactStorage(self.settings.IOC_COMMERCIAL_ARTIFACT_DIRECTORY)
        expired_imports = db.query(IOCImportJob).filter(
            IOCImportJob.expires_at <= now,
            IOCImportJob.status != "expired",
        ).limit(1000).all()
        expired_reports = db.query(IOCReportJob).filter(
            IOCReportJob.expires_at <= now,
            IOCReportJob.status != "expired",
        ).limit(1000).all()
        deleted = 0
        for job in [*expired_imports, *expired_reports]:
            if job.artifact_key:
                try:
                    storage.delete(job.artifact_key)
                    deleted += 1
                except (FileNotFoundError, ValueError):
                    pass
            job.status = "expired"
        cutoff = now - timedelta(days=self.settings.THREAT_SYNC_JOB_RETENTION_DAYS)
        pruned_sync_jobs = db.query(ThreatSyncJob).filter(
            ThreatSyncJob.created_at < cutoff,
            ThreatSyncJob.status.in_(["completed", "failed", "cancelled"]),
        ).delete(synchronize_session=False)
        db.commit()
        return {
            "expired_imports": len(expired_imports),
            "expired_reports": len(expired_reports),
            "artifacts_deleted": deleted,
            "sync_jobs_pruned": pruned_sync_jobs,
        }

    @staticmethod
    def _report_payload(format_name: str, records: list[dict]) -> bytes:
        if format_name == "csv":
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=list(records[0]) if records else ["id"])
            writer.writeheader()
            writer.writerows(records)
            return output.getvalue().encode()
        if format_name == "jsonl":
            return ("\n".join(json.dumps(item, sort_keys=True, default=str) for item in records) + "\n").encode()
        if format_name in {"markdown", "html"}:
            title = "# TriageOps IOC Intelligence Report\n\n"
            body = "\n".join(f"- {item['type']} `{item['value']}` — risk {item['risk_score']}, {item['sightings']} sightings" for item in records)
            text = title + body
            return (f"<html><body><pre>{html.escape(text)}</pre></body></html>" if format_name == "html" else text).encode()
        if format_name == "zip":
            manifest = json.dumps({"format": "triageops-evidence", "row_count": len(records)}, sort_keys=True).encode()
            data = json.dumps({"items": records}, sort_keys=True, default=str).encode()
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("manifest.json", manifest)
                archive.writestr("iocs.json", data)
                archive.writestr("checksums.sha256", f"{hashlib.sha256(data).hexdigest()}  iocs.json\n")
            return output.getvalue()
        return json.dumps({"items": records}, sort_keys=True, default=str).encode()

    @staticmethod
    def _report_extension(format_name: str) -> str:
        return {"markdown": "md", "stix": "json", "zip": "zip"}.get(format_name, format_name)


ioc_commercial_service = IOCCommercialService()
