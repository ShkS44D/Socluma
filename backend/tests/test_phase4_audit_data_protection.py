import json
import tempfile
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from src.core.config import get_settings
from src.core.crypto import (
    DecryptionError, decrypt_bytes, decrypt_json_secret, encrypt_bytes,
    encrypt_json_secret, encrypted_key_version,
)
from src.core.database import Base
from src.models.sqlalchemy import AuditLegalHold, AuditLog, Tenant, User, UserRole
from src.services.audit_management_service import audit_management_service
from src.services.audit_service import AuditMutationError, audit_service
from src.utils.datetime_utils import get_utc_now


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    tenant = Tenant(name="Phase 4", slug="phase-4")
    session.add(tenant)
    session.flush()
    user = User(
        tenant_id=tenant.id, email="phase4-owner@example.com",
        hashed_password="not-used", role=UserRole.ADMIN,
    )
    session.add(user)
    session.commit()
    yield session, tenant, user
    session.close()
    engine.dispose()


def test_audit_chain_context_sanitization_and_idempotency(db):
    session, tenant, user = db
    first = audit_service.record(
        session, action="permission.access.denied", user=user, status="denied",
        severity="high", before_values={"nested": {"password": "never-store"}},
        after_values={"authorization": "Bearer never-store"},
        details={"mfa_secret": "never-store", "safe": "visible"},
        idempotency_key="phase4-denial-1", strict=True,
    )
    duplicate = audit_service.record(
        session, action="permission.access.denied", user=user, status="denied",
        idempotency_key="phase4-denial-1", strict=True,
    )
    second = audit_service.record(
        session, action="organization.settings.updated", user=user,
        details={"token": "never-store"}, strict=True,
    )
    assert duplicate.id == first.id
    assert second.sequence_number == first.sequence_number + 1
    assert second.previous_event_hash == first.event_hash
    assert first.before_values["nested"]["password"] == "[REDACTED]"
    assert first.after_values["authorization"] == "[REDACTED]"
    serialized = json.dumps([first.before_values, first.after_values, first.details])
    assert "never-store" not in serialized
    assert audit_service.verify(session, tenant.id)["status"] == "verified"


def test_audit_is_immutable_and_tampering_is_detected(db):
    session, tenant, _user = db
    row = audit_service.record(
        session, action="system.health.checked", tenant_id=tenant.id,
        actor_type="system_task", strict=True,
    )
    row.details = {"modified": True}
    with pytest.raises(AuditMutationError):
        session.commit()
    session.rollback()
    session.execute(text("UPDATE audit_logs SET action='system.tampered' WHERE id=:id"), {"id": row.id})
    session.commit()
    result = audit_service.verify(session, tenant.id)
    assert result["status"] == "failed"
    assert result["reason"] == "hash_mismatch"


def test_retention_minimum_and_legal_hold_lifecycle(db):
    session, tenant, user = db
    with pytest.raises(ValueError, match="RETENTION_MINIMUM_REQUIRED"):
        audit_management_service.update_retention(
            session, tenant.id, user, {"default_retention_days": 1}
        )
    session.rollback()
    hold = audit_management_service.create_hold(
        session, tenant.id, user, {"name": "Investigation", "reason": "Preserve evidence"}
    )
    assert hold.status == "active"
    released = audit_management_service.release_hold(session, tenant.id, hold.id, user)
    assert released.status == "released"
    with pytest.raises(RuntimeError, match="LEGAL_HOLD_ALREADY_RELEASED"):
        audit_management_service.release_hold(session, tenant.id, hold.id, user)


def test_export_job_uses_safe_key_and_sanitized_records(db):
    session, tenant, user = db
    audit_service.record(
        session, action="organization.settings.updated", user=user,
        details={"password": "never-export", "field": "allowed"}, strict=True,
    )
    settings = get_settings()
    old_directory = settings.AUDIT_EXPORT_DIRECTORY
    with tempfile.TemporaryDirectory() as directory:
        settings.AUDIT_EXPORT_DIRECTORY = directory
        try:
            job, token = audit_management_service.create_export(session, tenant.id, user, "jsonl", {})
            audit_management_service.process_export(session, job.id)
            session.refresh(job)
            assert job.status == "completed"
            assert job.artifact_key.startswith(f"{tenant.id}/")
            assert token not in (job.download_token_hash or "")
            payload = (Path(directory) / job.artifact_key).read_text()
            assert "never-export" not in payload
            assert "[REDACTED]" in payload
        finally:
            settings.AUDIT_EXPORT_DIRECTORY = old_directory


def test_versioned_encryption_reads_previous_key_and_fails_closed():
    settings = get_settings()
    old_json = settings.ENCRYPTION_KEYS_JSON
    old_version = settings.ENCRYPTION_CURRENT_KEY_VERSION
    try:
        settings.ENCRYPTION_KEYS_JSON = json.dumps({
            "1": "phase4-old-encryption-key-material-at-least-32",
            "2": "phase4-new-encryption-key-material-at-least-32",
        })
        settings.ENCRYPTION_CURRENT_KEY_VERSION = 1
        old_ciphertext = encrypt_json_secret({"secret": "value"})
        settings.ENCRYPTION_CURRENT_KEY_VERSION = 2
        assert encrypted_key_version(old_ciphertext) == 1
        assert decrypt_json_secret(old_ciphertext) == {"secret": "value"}
        assert encrypted_key_version(encrypt_json_secret({"secret": "new"})) == 2
        encrypted_payload = encrypt_bytes(b"audit artifact")
        assert b"audit artifact" not in encrypted_payload
        assert decrypt_bytes(encrypted_payload) == b"audit artifact"
        settings.ENCRYPTION_KEYS_JSON = json.dumps({
            "2": "phase4-new-encryption-key-material-at-least-32",
        })
        with pytest.raises(DecryptionError, match="DECRYPTION_FAILED"):
            decrypt_json_secret(old_ciphertext)
    finally:
        settings.ENCRYPTION_KEYS_JSON = old_json
        settings.ENCRYPTION_CURRENT_KEY_VERSION = old_version
