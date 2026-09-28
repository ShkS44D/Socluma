import os
import tempfile

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.api.deps import get_current_user, get_db
from src.core.database import Base
from src.core.security import get_password_hash
from src.main import app
from src.models.sqlalchemy import OrganizationMembership, OrganizationRole, Tenant, User, UserRole


def test_pin_custom_roles_and_tenant_scoped_audit_export():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    session_factory = sessionmaker(bind=engine)
    Base.metadata.create_all(engine)
    db = session_factory()
    tenant = Tenant(name="Primary", slug="primary")
    other = Tenant(name="Other", slug="other")
    db.add_all([tenant, other])
    db.flush()
    owner = User(tenant_id=tenant.id, email="owner-security@example.com",
                 hashed_password=get_password_hash("VigilantAI-Test-Passphrase-2026!"), role=UserRole.ADMIN)
    db.add(owner)
    db.flush()
    db.add(OrganizationMembership(tenant_id=tenant.id, user_id=owner.id, role=OrganizationRole.OWNER))
    db.commit()
    owner_id, tenant_id, other_id = owner.id, tenant.id, other.id
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
    client = TestClient(app)
    try:
        pin_response = client.put(
            f"/api/v1/organizations/{tenant_id}/deletion-pin",
            json={"pin": "1234", "current_password": "VigilantAI-Test-Passphrase-2026!"},
        )
        assert pin_response.status_code == 204, pin_response.text
        role_response = client.post(
            "/api/v1/access-control/roles",
            json={"name": "Export reviewer", "permissions": ["audit.read", "audit.export"]},
        )
        assert role_response.status_code == 201, role_response.text
        assert role_response.json()["permissions"] == ["audit.export", "audit.view"]
        logs = client.get("/api/v1/audit-logs")
        assert logs.status_code == 200, logs.text
        assert all(item["tenant_id"] == tenant_id for item in logs.json()["items"])
        exported = client.get("/api/v1/audit-logs/export?format=csv")
        assert exported.status_code == 200
        assert exported.headers["content-type"].startswith("text/csv")
        failed_delete = client.request("DELETE", f"/api/v1/organizations/{other_id}", json={"pin": "0000"})
        assert failed_delete.status_code == 404
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
        os.remove(path)
