from __future__ import annotations

import os
import tempfile
from datetime import timedelta

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from src.core.config import Settings
from src.core.database import Base, SafeSession
from src.core.security import get_password_hash
from src.api.deps import get_current_user, get_db
from src.main import app
from src.models.pydantic import Organization, OrganizationCreate
from src.models.sqlalchemy import (
    AuditLog,
    EventType,
    OrganizationMembership,
    OrganizationRole,
    OrganizationStatus,
    OrganizationUsage,
    Playbook,
    PlaybookStep,
    PlaybookStepType,
    SecurityEvent,
    Severity,
    Tenant,
    User,
    UserRole,
)
from src.services.organization_service import organization_service
from src.services.usage_service import usage_service
from src.utils.datetime_utils import ensure_utc, get_utc_now


@pytest.fixture()
def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    factory = sessionmaker(bind=engine, class_=SafeSession, autoflush=False, autocommit=False)
    Base.metadata.create_all(engine)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
        os.remove(path)


def _owner_and_org(db):
    primary = Tenant(name="Primary", slug="organization-primary")
    db.add(primary)
    db.flush()
    owner = User(
        tenant_id=primary.id,
        email="organization-owner@example.com",
        hashed_password=get_password_hash("Socluma-Test-Passphrase-2026!"),
        role=UserRole.ADMIN,
    )
    db.add(owner)
    db.flush()
    organization_service.ensure_primary_membership(db, owner, OrganizationRole.OWNER, commit=False)
    target = organization_service.create_organization(
        db,
        owner,
        OrganizationCreate(name="Target", slug="organization-target", deletion_pin="1234"),
    )
    db.commit()
    return owner, target


def test_deletion_request_is_scheduled_idempotent_and_cancellable(db):
    owner, target = _owner_and_org(db)
    scheduled = organization_service.delete_organization(db, owner, target.id, "1234")
    first_purge_at = scheduled.scheduled_purge_at
    assert scheduled.status == OrganizationStatus.PENDING_DELETION
    assert scheduled.is_active is False
    assert ensure_utc(first_purge_at) > get_utc_now()
    serialized = Organization.model_validate(scheduled).model_dump(mode="json")
    assert serialized["scheduled_purge_at"].endswith("Z")

    repeated = organization_service.delete_organization(db, owner, target.id, "0000")
    assert repeated.scheduled_purge_at == first_purge_at
    assert db.query(AuditLog).filter_by(action="organization_deletion_requested").count() == 1

    cancelled = organization_service.cancel_deletion(db, owner, target.id)
    assert cancelled.status == OrganizationStatus.ACTIVE
    assert cancelled.scheduled_purge_at is None
    assert db.query(AuditLog).filter_by(action="organization_deletion_cancelled").count() == 1


def test_wrong_pin_lockout_and_non_owner_cannot_cancel(db):
    owner, target = _owner_and_org(db)
    viewer = User(
        tenant_id=target.id,
        email="organization-viewer@example.com",
        hashed_password=get_password_hash("Socluma-Test-Passphrase-2026!"),
        role=UserRole.VIEWER,
    )
    db.add(viewer)
    db.flush()
    db.add(
        OrganizationMembership(
            tenant_id=target.id,
            user_id=viewer.id,
            role=OrganizationRole.VIEWER,
            is_active=True,
        )
    )
    db.commit()

    for _ in range(5):
        with pytest.raises(HTTPException) as exc:
            organization_service.delete_organization(db, owner, target.id, "9999")
        assert exc.value.status_code == 400
    db.refresh(target)
    assert target.deletion_pin_locked_until is not None
    with pytest.raises(HTTPException) as locked:
        organization_service.delete_organization(db, owner, target.id, "1234")
    assert locked.value.status_code == 423

    target.deletion_pin_locked_until = None
    db.commit()
    organization_service.delete_organization(db, owner, target.id, "1234")
    with pytest.raises(HTTPException) as exc:
        organization_service.cancel_deletion(db, viewer, target.id)
    assert exc.value.status_code == 403


def test_purge_requires_eligibility_and_preserves_audit_evidence(db):
    owner, target = _owner_and_org(db)
    playbook = Playbook(tenant_id=target.id, name="Purge me", created_by=owner.id)
    db.add(playbook)
    db.flush()
    db.add(
        PlaybookStep(
            playbook_id=playbook.id,
            name="Dependent child",
            type=PlaybookStepType.END,
            order=1,
            config={},
        )
    )
    db.commit()
    playbook_id = playbook.id
    organization_service.delete_organization(db, owner, target.id, "1234")
    with pytest.raises(HTTPException) as exc:
        organization_service.purge_organization(db, target.id)
    assert exc.value.status_code == 409

    target.scheduled_purge_at = get_utc_now() - timedelta(seconds=1)
    db.commit()
    purged = organization_service.purge_organization(db, target.id)
    assert purged.status == OrganizationStatus.DELETED
    assert purged.deleted_at is not None
    assert purged.deletion_pin_hash is None
    assert db.query(OrganizationMembership).filter_by(tenant_id=target.id).count() == 0
    assert db.query(Playbook).filter_by(tenant_id=target.id).count() == 0
    assert db.query(PlaybookStep).filter_by(playbook_id=playbook_id).count() == 0
    assert db.query(AuditLog).filter_by(tenant_id=target.id, action="organization_purged").count() == 1


def test_usage_is_tenant_scoped_records_storage_and_history(db):
    owner, target = _owner_and_org(db)
    other = Tenant(name="Other", slug="organization-other")
    db.add(other)
    db.flush()
    db.add_all(
        [
            SecurityEvent(
                tenant_id=target.id,
                source="test",
                event_type=EventType.PROCESS,
                raw_event={"command": "suspicious.exe --payload"},
                normalized_event={"process": {"name": "suspicious.exe"}},
                severity=Severity.HIGH,
                timestamp=get_utc_now(),
            ),
            SecurityEvent(
                tenant_id=other.id,
                source="other",
                event_type=EventType.LOGIN,
                raw_event={"user": "other"},
                normalized_event={"user": {"name": "other"}},
                severity=Severity.LOW,
                timestamp=get_utc_now(),
            ),
        ]
    )
    db.commit()
    usage_service.increment_request(db, target.id, triage_ai=True)
    values = organization_service.usage(db, owner, target.id)
    assert values["event_count"] == 1
    assert values["storage_bytes"] > 0
    assert values["api_request_count"] == 1
    assert values["triage_ai_request_count"] == 1
    history = organization_service.usage_history(
        db, owner, target.id, get_utc_now().date(), get_utc_now().date()
    )
    assert len(history) == 1
    assert history[0].event_count == 1


def test_safe_session_rolls_back_failed_commit(db):
    db.add_all([Tenant(name="One", slug="duplicate"), Tenant(name="Two", slug="duplicate")])
    with pytest.raises(IntegrityError):
        db.commit()
    assert db.query(Tenant).filter_by(slug="duplicate").count() == 0


def test_production_configuration_rejects_placeholders_and_unsafe_docs():
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        USE_SQLITE=False,
        USE_REDIS_MOCK=False,
        POSTGRES_SERVER="postgres.internal",
        POSTGRES_PASSWORD="socluma_secret",
        REDIS_HOST="redis.internal",
        SECRET_KEY="a" * 48,
        JWT_SECRET_KEY="b" * 48,
        REFRESH_TOKEN_SECRET="c" * 48,
        COLLECTOR_TOKEN_SECRET="d" * 48,
        OPENAI_API_KEY="e" * 48,
        ALLOWED_HOSTS=["socluma.example.com"],
        BACKEND_CORS_ORIGINS=["https://socluma.example.com"],
        DOCS_ENABLED=False,
        SECURE_COOKIE=True,
        FRONTEND_PUBLIC_URL="https://socluma.example.com",
        AUTH_EMAIL_CAPTURE=False,
        AUTH_DEV_EXPOSE_TOKENS=False,
    )
    with pytest.raises(RuntimeError, match="POSTGRES_PASSWORD"):
        settings.validate_for_runtime()

    valid = settings.model_copy(
        update={
            "POSTGRES_PASSWORD": "production-database-password",
            "OPENAI_API_KEY": "production-openai-key",
        }
    )
    valid.validate_for_runtime()


def test_critical_organization_constraints_exist(db):
    inspector = inspect(db.get_bind())
    tenant_columns = {column["name"] for column in inspector.get_columns("tenants")}
    assert {
        "deletion_requested_at",
        "scheduled_purge_at",
        "deleted_at",
        "deletion_requested_by_id",
    } <= tenant_columns
    usage_uniques = {
        tuple(item["column_names"])
        for item in inspector.get_unique_constraints("organization_usage")
    }
    assert ("tenant_id", "snapshot_date") in usage_uniques


def test_migration_health_detects_database_behind(monkeypatch):
    import src.main as main_module

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    test_engine = create_engine(f"sqlite:///{path}")
    try:
        with test_engine.begin() as connection:
            connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
            connection.execute(text("INSERT INTO alembic_version (version_num) VALUES ('20260727_1200')"))
        monkeypatch.setattr(main_module, "engine", test_engine)
        result = main_module._check_migration_status()
        assert result.status == "error"
        assert "required revision 20260801_2000" in result.detail
    finally:
        test_engine.dispose()
        os.remove(path)


def test_authenticated_api_request_is_recorded_by_middleware(db, monkeypatch):
    import src.main as main_module

    owner, target = _owner_and_org(db)
    factory = sessionmaker(bind=db.get_bind(), class_=SafeSession, autoflush=False, autocommit=False)

    def override_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    def override_user(request: Request):
        session = factory()
        try:
            user = session.get(User, owner.id)
            session.expunge(user)
        finally:
            session.close()
        request.state.tenant_id = owner.tenant_id
        request.state.user_id = owner.id
        return user

    monkeypatch.setattr(main_module, "SessionLocal", factory)
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        client = TestClient(app)
        response = client.get("/api/v1/organizations")
        assert response.status_code == 200, response.text
        check = factory()
        try:
            daily = check.query(OrganizationUsage).filter_by(
                tenant_id=owner.tenant_id,
                snapshot_date=get_utc_now().date(),
            ).one()
            assert daily.api_request_count == 1
        finally:
            check.close()
        invalid_range = client.get(
            f"/api/v1/organizations/{owner.tenant_id}/usage/history"
            "?start_date=2026-07-30&end_date=2026-07-01"
        )
        assert invalid_range.status_code == 422
        assert invalid_range.json()["error_code"] == "usage_date_range_invalid"
        assert invalid_range.json()["detail"] == "start_date must not be after end_date"
    finally:
        app.dependency_overrides.clear()
