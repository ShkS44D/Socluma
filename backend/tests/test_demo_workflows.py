import hashlib
import os
import tempfile

from sqlalchemy import create_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import sessionmaker

from scripts import reset_test_demo, seed_test_demo
from src.core.database import Base
from src.core.security import verify_password
from src.models.sqlalchemy import (
    Collector,
    CollectorStatus,
    Incident,
    IndicatorType,
    IOC,
    OrganizationMembership,
    OrganizationRole,
    Tenant,
    User,
)


def test_indicator_type_uses_stable_values_for_postgresql():
    column_type = IOC.__table__.c.type.type
    dialect = postgresql.dialect()
    assert column_type.bind_processor(dialect)(IndicatorType.IPV4) == "ipv4"
    assert column_type.result_processor(dialect, None)("ipv4") is IndicatorType.IPV4


def test_test_seed_is_idempotent_offline_and_reset_preserves_other_tenants(monkeypatch, tmp_path):
    fd, path = tempfile.mkstemp(suffix=".db"); os.close(fd)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(engine)
    db = Session()
    other = Tenant(name="Unrelated Customer", slug="unrelated-customer")
    db.add(other); db.flush()
    existing_owner = User(
        tenant_id=other.id,
        email=seed_test_demo.OWNER_EMAIL_DEFAULT,
        hashed_password="preserved-existing-password-hash",
    )
    db.add(existing_owner)
    legacy_token = hashlib.sha256(f"{other.id}:offline-demo".encode()).hexdigest()
    db.add(Collector(
        tenant_id=other.id,
        name="Legacy Demo Collector",
        type="windows",
        hostname="legacy-demo-ws01",
        token=f"disabled-{legacy_token}",
        token_lookup_hash=legacy_token,
        status=CollectorStatus.OFFLINE,
    ))
    db.commit(); unrelated_id = other.id; existing_owner_id = existing_owner.id; db.close()

    monkeypatch.setattr(seed_test_demo.get_settings(), "IOC_COMMERCIAL_ARTIFACT_DIRECTORY", str(tmp_path / "reports"))
    monkeypatch.setattr(reset_test_demo.get_settings(), "IOC_COMMERCIAL_ARTIFACT_DIRECTORY", str(tmp_path / "reports"))
    monkeypatch.setattr("httpx.Client.request", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("external call")))

    first = seed_test_demo.seed(
        confirmed=True, owner_password="Owner-Demo-Passphrase-2026!",
        analyst_password="Analyst-Demo-Passphrase-2026!", session_factory=Session,
    )
    first_check = Session()
    first_ioc_count = first_check.query(IOC).filter_by(tenant_id=first["tenant_id"]).count()
    first_check.close()
    second = seed_test_demo.seed(
        confirmed=True, owner_password="Owner-Demo-Passphrase-2026!",
        analyst_password="Updated-Analyst-Demo-Passphrase-2026!", session_factory=Session,
    )
    assert first["tenant_id"] == second["tenant_id"]
    check = Session()
    assert check.query(Tenant).filter_by(slug=seed_test_demo.DEMO_SLUG).count() == 1
    assert check.query(Incident).filter_by(tenant_id=first["tenant_id"]).count() == 1
    assert first_ioc_count >= 3
    assert check.query(IOC).filter_by(
        tenant_id=first["tenant_id"], normalized_value="demo-user"
    ).count() == 0
    assert check.query(IOC).filter_by(tenant_id=first["tenant_id"]).count() == first_ioc_count
    demo_analyst = check.query(User).filter_by(email=seed_test_demo.ANALYST_EMAIL_DEFAULT).one()
    assert verify_password("Updated-Analyst-Demo-Passphrase-2026!", demo_analyst.hashed_password)
    assert not verify_password("Analyst-Demo-Passphrase-2026!", demo_analyst.hashed_password)
    assert demo_analyst.failed_login_attempts == 0
    assert demo_analyst.locked_until is None
    check.close()

    default_seed = seed_test_demo.seed(
        confirmed=True,
        owner_password="Owner-Demo-Passphrase-2026!",
        analyst_password="Default-Analyst-Demo-Passphrase-2026!",
        analyst_email="default.analyst@example.com",
        target_tenant_slug="unrelated-customer",
        allow_existing_tenant=True,
        session_factory=Session,
    )
    assert default_seed["tenant_id"] == unrelated_id
    check = Session()
    repaired_collectors = check.query(Collector).filter_by(
        tenant_id=unrelated_id,
        token_lookup_hash=legacy_token,
    ).all()
    assert len(repaired_collectors) == 1
    assert repaired_collectors[0].name == "demo-collector"
    assert repaired_collectors[0].status == CollectorStatus.ONLINE
    default_ioc_count = check.query(IOC).filter_by(tenant_id=unrelated_id).count()
    assert default_ioc_count >= 3
    check.close()

    recreated = reset_test_demo.reset(
        confirmed=True, owner_password="Owner-Demo-Passphrase-2026!",
        analyst_password="Analyst-Demo-Passphrase-2026!", session_factory=Session,
    )
    check = Session()
    assert check.query(Tenant).filter_by(id=unrelated_id, slug="unrelated-customer").count() == 1
    assert check.query(IOC).filter_by(tenant_id=unrelated_id).count() == default_ioc_count
    preserved_owner = check.query(User).filter_by(id=existing_owner_id, tenant_id=unrelated_id).one()
    assert preserved_owner.hashed_password == "preserved-existing-password-hash"
    assert check.query(OrganizationMembership).filter_by(
        tenant_id=recreated["tenant_id"], user_id=existing_owner_id,
        role=OrganizationRole.OWNER, is_active=True,
    ).count() == 1
    assert check.query(Tenant).filter_by(id=recreated["tenant_id"], slug=seed_test_demo.DEMO_SLUG).count() == 1
    check.close(); engine.dispose(); os.remove(path)


def test_test_seed_and_reset_require_explicit_confirmation():
    try:
        seed_test_demo.seed(confirmed=False, owner_password="x", analyst_password="y")
    except RuntimeError as exc:
        assert "unconfirmed" in str(exc)
    else:
        raise AssertionError("seed accepted an unconfirmed database")

    try:
        reset_test_demo.reset(confirmed=False, owner_password="x", analyst_password="y")
    except RuntimeError as exc:
        assert "not confirmed" in str(exc)
    else:
        raise AssertionError("reset accepted an unconfirmed database")
