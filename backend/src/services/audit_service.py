from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from sqlalchemy import event
from sqlalchemy.orm import Session

from src.core.config import get_settings
from src.core.logging import logger
from src.models.sqlalchemy import (
    AuditChainState,
    AuditLegalHold,
    AuditLog,
    EventType,
    OrganizationMembership,
    SecurityEvent,
    Severity,
    User,
)
from src.utils.datetime_utils import ensure_utc, get_utc_now


settings = get_settings()

AUDIT_CATEGORIES = frozenset({
    "authentication", "account_security", "users", "memberships", "roles",
    "permissions", "organizations", "approvals", "api_keys", "collectors",
    "ingestion", "alerts", "incidents", "detections", "sigma", "playbooks",
    "soar", "threat_intelligence", "assets", "triage_ai", "configuration",
    "exports", "retention", "data_protection", "system",
})
ACTION_PREFIX_CATEGORY = {
    "auth": "authentication", "login": "authentication", "logout": "authentication",
    "registration": "authentication", "refresh": "authentication",
    "account": "account_security", "recovery": "account_security",
    "session": "account_security", "password": "account_security", "mfa": "account_security",
    "email": "account_security", "user": "users", "membership": "memberships",
    "invitation": "memberships", "role": "roles", "permission": "permissions",
    "organization": "organizations", "deletion": "organizations", "approval": "approvals",
    "api": "api_keys", "collector": "collectors", "source": "collectors",
    "event": "ingestion", "simulation": "ingestion", "external": "alerts",
    "alert": "alerts", "incident": "incidents", "investigation": "incidents",
    "analyst": "incidents",
    "detection": "detections", "sigma": "sigma", "playbook": "playbooks",
    "soar": "soar", "connector": "soar", "credential": "soar",
    "ioc": "threat_intelligence", "threat": "threat_intelligence", "asset": "assets",
    "ai": "triage_ai", "triage": "triage_ai", "audit": "exports",
    "export": "exports", "retention": "retention", "legal": "retention",
    "archive": "retention", "data": "data_protection", "encryption": "data_protection",
    "system": "system", "bootstrap": "system",
}
STABLE_ACTION_ALIASES = {
    "login_success": "login",
}
VALID_ACTION = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,9}$")
VALID_RESULTS = {"success", "failure", "denied", "pending"}
VALID_SEVERITIES = {"debug", "info", "low", "medium", "high", "critical"}
VALID_ACTOR_TYPES = {"user", "api_key", "collector", "system_task", "service"}
VALID_CLASSIFICATIONS = {"public", "internal", "confidential", "restricted", "secret"}


class AuditMutationError(RuntimeError):
    pass


@event.listens_for(AuditLog, "before_update")
@event.listens_for(AuditLog, "before_delete")
def _protect_audit_log(_mapper, connection, _target):
    if not connection.info.get("audit_maintenance"):
        raise AuditMutationError("Audit records are append-only")


@event.listens_for(AuditLegalHold, "before_delete")
def _protect_legal_hold_delete(_mapper, _connection, _target):
    raise AuditMutationError("Legal-hold history is append-only")


@event.listens_for(AuditLegalHold, "before_update")
def _protect_legal_hold_update(_mapper, connection, _target):
    if not connection.info.get("legal_hold_release"):
        raise AuditMutationError("Legal holds may only transition from active to released")


class AuditService:
    _SENSITIVE = {
        "password", "secret", "token", "authorization", "cookie", "api_key",
        "apikey", "private_key", "recovery_code", "recoverycode", "mfa_code",
        "totp", "deletion_pin", "encryption_key", "credential", "smtp_password",
        "database_password",
    }
    max_depth = 6
    max_items = 200
    max_string = 2000
    max_payload_bytes = 16_384

    def normalize_action(self, action: str) -> tuple[str, str]:
        normalized = STABLE_ACTION_ALIASES.get(action, action.strip().lower())
        normalized = re.sub(r"\.+", ".", normalized)
        if not VALID_ACTION.fullmatch(normalized):
            raise ValueError("AUDIT_EVENT_INVALID")
        prefix = re.split(r"[._-]", normalized, maxsplit=1)[0]
        category = ACTION_PREFIX_CATEGORY.get(prefix)
        if not category or category not in AUDIT_CATEGORIES:
            raise ValueError("AUDIT_EVENT_INVALID")
        return normalized, category

    def sanitize(self, value: Any) -> Any:
        seen: set[int] = set()
        item_count = 0

        def visit(item: Any, depth: int) -> Any:
            nonlocal item_count
            if depth > self.max_depth:
                return "[MAX_DEPTH]"
            if item is None or isinstance(item, (bool, int, float)):
                return item
            if isinstance(item, (datetime, date)):
                dt = ensure_utc(item) if isinstance(item, datetime) else item
                return dt.isoformat()
            if isinstance(item, Enum):
                return visit(item.value, depth)
            if isinstance(item, str):
                return item[:self.max_string]
            if isinstance(item, bytes):
                return "[BINARY_REDACTED]"
            if not isinstance(item, (dict, list, tuple, set)):
                return f"[UNSERIALIZABLE:{type(item).__name__}]"
            identity = id(item)
            if identity in seen:
                return "[CIRCULAR]"
            seen.add(identity)
            try:
                if isinstance(item, dict):
                    output = {}
                    for key, nested in item.items():
                        item_count += 1
                        if item_count > self.max_items:
                            output["__truncated__"] = True
                            break
                        safe_key = str(key)[:100]
                        folded = safe_key.casefold().replace("-", "_").replace(" ", "_")
                        output[safe_key] = (
                            "[REDACTED]"
                            if any(word in folded for word in self._SENSITIVE)
                            else visit(nested, depth + 1)
                        )
                    return output
                output = []
                for nested in list(item):
                    item_count += 1
                    if item_count > self.max_items:
                        output.append("[TRUNCATED]")
                        break
                    output.append(visit(nested, depth + 1))
                return output
            finally:
                seen.remove(identity)

        sanitized = visit(value, 0)
        encoded = json.dumps(sanitized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if len(encoded.encode("utf-8")) > self.max_payload_bytes:
            return {"__truncated__": True, "sha256": hashlib.sha256(encoded.encode()).hexdigest()}
        return sanitized

    def _canonical(self, values: dict[str, Any]) -> bytes:
        return json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

    def _hash(self, values: dict[str, Any], *, key_version: int) -> str:
        if settings.AUDIT_INTEGRITY_KEYS_JSON:
            keys = json.loads(settings.AUDIT_INTEGRITY_KEYS_JSON)
            material = keys.get(str(key_version))
            if not material:
                raise ValueError("AUDIT_INTEGRITY_FAILED")
        else:
            if key_version != settings.AUDIT_INTEGRITY_KEY_VERSION:
                raise ValueError("AUDIT_INTEGRITY_FAILED")
            material = settings.AUDIT_INTEGRITY_KEY or settings.REFRESH_TOKEN_SECRET or ""
        key = material.encode()
        return hmac.new(key, self._canonical(values), hashlib.sha256).hexdigest()

    def _legacy_hash(self, record: AuditLog) -> str:
        material = "|".join((
            record.previous_event_hash or "", record.id, record.tenant_id or "",
            str(record.sequence_number or 0),
        ))
        return hashlib.sha256(material.encode()).hexdigest()

    def _hash_values(self, record: AuditLog) -> dict[str, Any]:
        return {
            "id": record.id,
            "tenant_id": record.tenant_id,
            "sequence_number": record.sequence_number,
            "previous_event_hash": record.previous_event_hash,
            "created_at": ensure_utc(record.created_at).isoformat(),
            "actor_type": record.actor_type,
            "user_id": record.user_id,
            "action": record.action,
            "category": record.category,
            "severity": record.severity,
            "status": record.status,
            "resource_type": record.resource_type,
            "resource_id": record.resource_id,
            "request_id": record.request_id,
            "correlation_id": record.correlation_id,
            "failure_reason": record.failure_reason,
            "before_values": record.before_values or {},
            "after_values": record.after_values or {},
            "details": record.details or {},
            "retention_class": record.retention_class,
            "data_classification": record.data_classification,
        }

    def record(
        self,
        db: Session,
        *,
        action: str,
        user: Optional[User] = None,
        tenant_id: Optional[str] = None,
        actor_type: str = "user",
        actor_membership_id: Optional[str] = None,
        actor_session_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        parent_resource_type: Optional[str] = None,
        parent_resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        actor_role: Optional[str] = None,
        status: str = "success",
        severity: str = "info",
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        approval_request_id: Optional[str] = None,
        failure_reason: Optional[str] = None,
        before_values: Optional[dict[str, Any]] = None,
        after_values: Optional[dict[str, Any]] = None,
        details: Optional[dict[str, Any]] = None,
        event_source: str = "application",
        retention_class: Optional[str] = None,
        data_classification: str = "confidential",
        idempotency_key: Optional[str] = None,
        commit: bool = True,
        strict: bool = False,
    ) -> Optional[AuditLog]:
        try:
            stable_action, category = self.normalize_action(action)
            selected_tenant = tenant_id or (user.tenant_id if user else None)
            status = {"failed": "failure", "error": "failure", "forbidden": "denied"}.get(status, status)
            if actor_type not in VALID_ACTOR_TYPES or status not in VALID_RESULTS:
                raise ValueError("AUDIT_EVENT_INVALID")
            if severity not in VALID_SEVERITIES:
                raise ValueError("AUDIT_EVENT_INVALID")
            if data_classification not in VALID_CLASSIFICATIONS:
                raise ValueError("DATA_CLASSIFICATION_INVALID")
            if idempotency_key and selected_tenant:
                existing = db.query(AuditLog).filter_by(
                    tenant_id=selected_tenant, idempotency_key=idempotency_key[:128]
                ).first()
                if existing:
                    return existing

            membership = None
            if user and selected_tenant:
                membership = db.query(OrganizationMembership).filter_by(
                    tenant_id=selected_tenant, user_id=user.id
                ).first()
            now = get_utc_now()
            record = AuditLog(
                id=str(__import__("uuid").uuid4()),
                tenant_id=selected_tenant,
                user_id=user.id if user else None,
                actor_membership_id=actor_membership_id or (membership.id if membership else None),
                actor_session_id=actor_session_id,
                actor_type=actor_type,
                action=stable_action,
                category=category,
                severity=severity,
                resource_type=resource_type,
                resource_id=resource_id,
                parent_resource_type=parent_resource_type,
                parent_resource_id=parent_resource_id,
                ip_address=ip_address[:64] if ip_address else None,
                actor_role=actor_role or (
                    membership.role.value if membership and not membership.custom_role_id
                    else membership.custom_role.name if membership and membership.custom_role
                    else None
                ),
                status=status,
                user_agent=user_agent[:512] if user_agent else None,
                request_id=request_id[:128] if request_id else None,
                correlation_id=correlation_id[:128] if correlation_id else request_id[:128] if request_id else None,
                approval_request_id=approval_request_id,
                failure_reason=failure_reason[:255] if failure_reason else None,
                before_values=self.sanitize(before_values or {}),
                after_values=self.sanitize(after_values or {}),
                details=self.sanitize(details or {}),
                event_source=event_source[:50],
                retention_class=retention_class or self._retention_class(category),
                data_classification=data_classification,
                hash_algorithm_version=1,
                integrity_key_version=settings.AUDIT_INTEGRITY_KEY_VERSION,
                idempotency_key=idempotency_key[:128] if idempotency_key else None,
                created_at=now,
            )
            if selected_tenant:
                state_values = {
                    "tenant_id": selected_tenant,
                    "last_sequence": 0,
                    "key_version": settings.AUDIT_INTEGRITY_KEY_VERSION,
                }
                dialect = db.get_bind().dialect.name
                if dialect == "sqlite":
                    from sqlalchemy.dialects.sqlite import insert as dialect_insert
                    db.execute(dialect_insert(AuditChainState).values(**state_values).on_conflict_do_nothing())
                elif dialect == "postgresql":
                    from sqlalchemy.dialects.postgresql import insert as dialect_insert
                    db.execute(dialect_insert(AuditChainState).values(**state_values).on_conflict_do_nothing())
                state = db.query(AuditChainState).filter_by(
                    tenant_id=selected_tenant
                ).with_for_update().first()
                if not state:
                    state = AuditChainState(
                        tenant_id=selected_tenant,
                        last_sequence=0,
                        key_version=settings.AUDIT_INTEGRITY_KEY_VERSION,
                    )
                    db.add(state)
                    db.flush()
                record.sequence_number = state.last_sequence + 1
                record.previous_event_hash = state.last_event_hash
                record.event_hash = self._hash(
                    self._hash_values(record), key_version=record.integrity_key_version
                )
                state.last_sequence = record.sequence_number
                state.last_event_hash = record.event_hash
                state.key_version = record.integrity_key_version
            db.add(record)
            if commit:
                db.commit()
                db.refresh(record)
            else:
                db.flush()
            self._detect_suspicious(db, record, commit=commit)
            return record
        except Exception:
            db.rollback()
            logger.exception("Failed to write audit log for %s", action)
            if strict:
                raise
            return None

    def _retention_class(self, category: str) -> str:
        if category in {"authentication", "account_security"}:
            return "authentication"
        if category == "exports":
            return "export"
        if category in {"permissions", "organizations", "retention", "data_protection"}:
            return "security"
        return "administrative"

    def verify(self, db: Session, tenant_id: str) -> dict[str, Any]:
        state = db.get(AuditChainState, tenant_id)
        rows = db.query(AuditLog).filter_by(tenant_id=tenant_id).order_by(
            AuditLog.sequence_number.asc()
        ).all()
        previous = state.first_retained_previous_hash if state else None
        expected_sequence = state.first_retained_sequence if state else 1
        for row in rows:
            if row.sequence_number != expected_sequence:
                return self._verification(False, len(rows), expected_sequence, "missing_record")
            if row.previous_event_hash != previous:
                return self._verification(False, len(rows), row.sequence_number, "previous_hash_mismatch")
            expected_hash = (
                self._legacy_hash(row) if row.hash_algorithm_version == 0
                else self._hash(self._hash_values(row), key_version=row.integrity_key_version)
            )
            if not hmac.compare_digest(row.event_hash or "", expected_hash):
                self._integrity_alert(db, tenant_id, row.sequence_number)
                return self._verification(False, len(rows), row.sequence_number, "hash_mismatch")
            previous = row.event_hash
            expected_sequence += 1
        if state and (state.last_sequence != expected_sequence - 1 or state.last_event_hash != previous):
            return self._verification(False, len(rows), expected_sequence, "chain_state_mismatch")
        return self._verification(True, len(rows), None, None)

    def _verification(self, valid: bool, count: int, sequence, reason) -> dict[str, Any]:
        return {
            "status": "verified" if valid else "failed",
            "verified_record_count": count if valid else max(0, (sequence or 1) - 1),
            "first_invalid_sequence": sequence,
            "reason": reason,
        }

    def _detect_suspicious(self, db: Session, record: AuditLog, *, commit: bool) -> None:
        if not record.tenant_id:
            return
        if record.status == "success" and record.action.startswith("export."):
            since = get_utc_now() - timedelta(hours=1)
            count = db.query(AuditLog).filter(
                AuditLog.tenant_id == record.tenant_id,
                AuditLog.user_id == record.user_id,
                AuditLog.action.like("export.%"),
                AuditLog.created_at >= since,
            ).count()
            recent = db.query(SecurityEvent).filter(
                SecurityEvent.tenant_id == record.tenant_id,
                SecurityEvent.source == "suspicious-administration",
                SecurityEvent.created_at >= since,
            ).first()
            if count >= 10 and not recent:
                db.add(SecurityEvent(
                    tenant_id=record.tenant_id, source="suspicious-administration",
                    event_type=EventType.ALERT, severity=Severity.HIGH,
                    timestamp=get_utc_now(),
                    raw_event={"reason_code": "AUDIT_EXPORT_SPIKE", "actor_id": record.user_id},
                    normalized_event={"count": count, "window_minutes": 60},
                ))
                if commit:
                    db.commit()
            return
        if record.status not in {"denied", "failure"}:
            return
        serious = (
            record.action.startswith(("permission.", "organization.", "api.key."))
            or record.failure_reason in {"TENANT_MISMATCH", "FINAL_OWNER_PROTECTED", "PRIVILEGE_ESCALATION_BLOCKED"}
        )
        if not serious:
            return
        since = get_utc_now() - timedelta(minutes=15)
        count = db.query(AuditLog).filter(
            AuditLog.tenant_id == record.tenant_id,
            AuditLog.user_id == record.user_id,
            AuditLog.status.in_(["denied", "failure"]),
            AuditLog.created_at >= since,
        ).count()
        recent = db.query(SecurityEvent).filter(
            SecurityEvent.tenant_id == record.tenant_id,
            SecurityEvent.source == "suspicious-administration",
            SecurityEvent.created_at >= since,
        ).first()
        if count >= 5 and not recent:
            db.add(SecurityEvent(
                tenant_id=record.tenant_id,
                source="suspicious-administration",
                event_type=EventType.ALERT,
                severity=Severity.HIGH,
                timestamp=get_utc_now(),
                raw_event={"reason_code": "REPEATED_ADMIN_DENIALS", "actor_id": record.user_id},
                normalized_event={"count": count, "window_minutes": 15},
            ))
            if commit:
                db.commit()

    def _integrity_alert(self, db: Session, tenant_id: str, sequence: int) -> None:
        db.add(SecurityEvent(
            tenant_id=tenant_id,
            source="audit-integrity",
            event_type=EventType.ALERT,
            severity=Severity.CRITICAL,
            timestamp=get_utc_now(),
            raw_event={"reason_code": "AUDIT_INTEGRITY_FAILED"},
            normalized_event={"first_invalid_sequence": sequence},
        ))
        db.commit()


audit_service = AuditService()
