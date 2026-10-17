import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.api.deps import get_current_user, get_db
from src.core.database import Base
from src.main import app
from src.models.sqlalchemy import (
    IOC,
    IndicatorType,
    OrganizationMembership,
    OrganizationRole,
    Tenant,
    User,
    UserRole,
)


@pytest.fixture()
def ioc_api():
    with tempfile.TemporaryDirectory(prefix="socluma-ioc-api-") as directory:
        path = f"{directory}/ioc-api.db"
        engine = create_engine(
            f"sqlite:///{path}", connect_args={"check_same_thread": False}
        )
        session_factory = sessionmaker(bind=engine)
        Base.metadata.create_all(engine)
        db = session_factory()
        tenant = Tenant(name="IOC API", slug="ioc-api")
        other = Tenant(name="Other IOC API", slug="other-ioc-api")
        db.add_all([tenant, other])
        db.flush()
        owner = User(
            tenant_id=tenant.id,
            email="ioc-api-owner@example.test",
            hashed_password="not-used",
            full_name="IOC API Owner",
            role=UserRole.ADMIN,
        )
        db.add(owner)
        db.flush()
        db.add(
            OrganizationMembership(
                tenant_id=tenant.id,
                user_id=owner.id,
                role=OrganizationRole.OWNER,
                is_active=True,
            )
        )
        foreign_ioc = IOC(
            tenant_id=other.id,
            type=IndicatorType.DOMAIN,
            value="foreign.example",
            normalized_value="foreign.example",
            display_value="foreign.example",
            lifecycle_status="active",
        )
        db.add(foreign_ioc)
        db.commit()
        owner_id, foreign_ioc_id = owner.id, foreign_ioc.id
        db.close()

        def override_db():
            session = session_factory()
            try:
                yield session
            finally:
                session.close()

        def override_user():
            session = session_factory()
            try:
                return session.get(User, owner_id)
            finally:
                session.close()

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[get_current_user] = override_user
        try:
            yield TestClient(app), session_factory, foreign_ioc_id
        finally:
            app.dependency_overrides.clear()
            engine.dispose()


def create_ioc(client: TestClient, value: str, kind: str = "domain") -> dict:
    response = client.post(
        "/api/v1/iocs",
        json={
            "type": kind,
            "value": value,
            "source": "api-test",
            "confidence_score": 70,
            "source_reliability": 60,
            "lifecycle_status": "active",
            "tlp": "TLP:AMBER",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_ioc_crud_duplicate_stats_and_tenant_isolation(ioc_api):
    client, _session_factory, foreign_ioc_id = ioc_api
    created = create_ioc(client, "API[.]Example")
    assert created["normalized_value"] == "api.example"
    duplicate = client.post(
        "/api/v1/iocs",
        json={"type": "domain", "value": "api.example", "source": "duplicate"},
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["error_code"] == "IOC_DUPLICATE"
    listing = client.get("/api/v1/iocs?search=api.example")
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    stats = client.get("/api/v1/iocs/stats")
    assert stats.status_code == 200
    assert stats.json()["total_iocs"] == 1
    assert client.get(f"/api/v1/iocs/{foreign_ioc_id}").status_code == 404


def test_stix_preview_watchlist_relationship_and_graph(ioc_api):
    client, _session_factory, _foreign_ioc_id = ioc_api
    first = create_ioc(client, "one.example")
    second = create_ioc(client, "two.example")
    preview = client.post(
        "/api/v1/iocs/stix/import?dry_run=true",
        json={
            "type": "bundle",
            "id": "bundle--00000000-0000-4000-8000-000000000100",
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--00000000-0000-4000-8000-000000000101",
                    "pattern": "[ipv4-addr:value = '192.0.2.100']",
                }
            ],
        },
    )
    assert preview.status_code == 200, preview.text
    assert preview.json()["dry_run"] is True
    assert preview.json()["created"] == 0

    watchlist = client.post(
        "/api/v1/iocs/watchlists",
        json={"name": "Critical IOC Watchlist", "policies": {"notify_on_sighting": True}},
    )
    assert watchlist.status_code == 201, watchlist.text
    watchlist_id = watchlist.json()["id"]
    member = client.post(
        f"/api/v1/iocs/watchlists/{watchlist_id}/members/{first['id']}"
    )
    assert member.status_code == 201, member.text
    detail = client.get(f"/api/v1/ioc-commercial/watchlists/{watchlist_id}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["match_statistics"]["members"] == 1

    relationship = client.post(
        "/api/v1/iocs/relationships",
        json={
            "relationship_type": "communicates-with",
            "source_type": "ioc",
            "source_id": first["id"],
            "target_type": "ioc",
            "target_id": second["id"],
            "confidence": 90,
            "evidence_references": ["case:api-test"],
        },
    )
    assert relationship.status_code == 201, relationship.text
    graph = client.get(f"/api/v1/ioc-commercial/graph/{first['id']}?depth=2")
    assert graph.status_code == 200, graph.text
    assert {node["id"] for node in graph.json()["nodes"]} >= {
        first["id"],
        second["id"],
    }
    assert graph.json()["edges"][0]["evidence_count"] == 1


def test_threat_source_api_never_returns_plaintext_credentials(ioc_api):
    client, session_factory, _foreign_ioc_id = ioc_api
    secret = "api-test-commercial-secret"
    created = client.post(
        "/api/v1/ioc-commercial/sources",
        json={
            "provider": "virustotal",
            "name": "API test source",
            "credentials": {"api_key": secret},
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["configured"] is True
    assert secret not in created.text
    assert "encrypted_credentials" not in body
    source_id = body["id"]

    listing = client.get("/api/v1/ioc-commercial/sources")
    assert listing.status_code == 200
    assert secret not in listing.text
    rotated = client.post(
        f"/api/v1/ioc-commercial/sources/{source_id}/rotate",
        json={"credentials": {"api_key": "rotated-test-secret"}},
    )
    assert rotated.status_code == 200, rotated.text
    assert "rotated-test-secret" not in rotated.text

    db = session_factory()
    try:
        from src.models.sqlalchemy import ThreatSourceCredential

        stored = db.query(ThreatSourceCredential).filter_by(id=source_id).one()
        assert secret not in stored.encrypted_credentials
        assert "rotated-test-secret" not in stored.encrypted_credentials
    finally:
        db.close()
