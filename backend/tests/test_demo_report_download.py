import tempfile
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.api.deps import get_current_user, get_db
from src.core.database import Base
from src.main import app
from src.models.sqlalchemy import OrganizationMembership, OrganizationRole, Tenant, User, UserRole
from src.services.ioc_commercial_service import ioc_commercial_service
from src.utils.datetime_utils import get_utc_now


def test_authenticated_report_download_states_and_tenant_isolation(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'reports.db'}", connect_args={"check_same_thread": False})
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(engine)
    db = Session()
    tenant, other = Tenant(name="Reports", slug="reports"), Tenant(name="Other", slug="other-reports")
    db.add_all([tenant, other]); db.flush()
    owner = User(tenant_id=tenant.id, email="owner@reports.invalid", hashed_password="unused", role=UserRole.ADMIN)
    viewer = User(tenant_id=tenant.id, email="viewer@reports.invalid", hashed_password="unused", role=UserRole.VIEWER)
    outsider = User(tenant_id=other.id, email="owner@other.invalid", hashed_password="unused", role=UserRole.ADMIN)
    db.add_all([owner, viewer, outsider]); db.flush()
    tenant_id, other_id = tenant.id, other.id
    owner_id, viewer_id, outsider_id = owner.id, viewer.id, outsider.id
    db.add_all([
        OrganizationMembership(tenant_id=tenant.id, user_id=owner.id, role=OrganizationRole.OWNER, is_active=True),
        OrganizationMembership(tenant_id=tenant.id, user_id=viewer.id, role=OrganizationRole.VIEWER, is_active=True),
        OrganizationMembership(tenant_id=other.id, user_id=outsider.id, role=OrganizationRole.OWNER, is_active=True),
    ]); db.commit()
    monkeypatch.setattr(ioc_commercial_service.settings, "IOC_COMMERCIAL_ARTIFACT_DIRECTORY", str(tmp_path / "artifacts"))
    current = {"id": owner_id}
    def override_db():
        session = Session()
        try: yield session
        finally: session.close()
    def override_user():
        session = Session()
        try: return session.get(User, current["id"])
        finally: session.close()
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = override_user
    client = TestClient(app)
    try:
        db = Session(); owner_db = db.get(User, owner_id); outsider_db = db.get(User, outsider_id)
        report = ioc_commercial_service.create_report(db, owner_db, "demo", "json", {})
        ioc_commercial_service.process_report(db, report.id, tenant_id)
        foreign = ioc_commercial_service.create_report(db, outsider_db, "demo", "json", {})
        ioc_commercial_service.process_report(db, foreign.id, other_id)
        report_id, foreign_id = report.id, foreign.id
        db.close()

        response = client.get(f"/api/v1/ioc-commercial/reports/{report_id}/download")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["content-disposition"] == f'attachment; filename="vigilantai-ioc-report-{report_id}.json"'

        current["id"] = viewer_id
        assert client.get(f"/api/v1/ioc-commercial/reports/{report_id}/download").status_code == 403
        assert client.get("/api/v1/ioc-commercial/bulk-actions").status_code == 403
        current["id"] = owner_id
        assert client.get("/api/v1/ioc-commercial/bulk-actions").status_code == 200
        assert client.get(f"/api/v1/ioc-commercial/reports/{foreign_id}/download").status_code == 404

        db = Session(); expired = db.get(__import__("src.models.sqlalchemy", fromlist=["IOCReportJob"]).IOCReportJob, report_id)
        expired.expires_at = get_utc_now() - timedelta(seconds=1); db.commit(); db.close()
        assert client.get(f"/api/v1/ioc-commercial/reports/{report_id}/download").status_code == 410
    finally:
        app.dependency_overrides.clear(); client.close(); engine.dispose()


def test_ioc_bulk_permission_is_canonical_in_route_and_sidebar():
    repository = __import__("pathlib").Path(__file__).resolve().parents[2]
    app_source = (repository / "frontend/src/App.tsx").read_text(encoding="utf-8")
    navigation_source = (repository / "frontend/src/components/layout/DashboardLayout.tsx").read_text(encoding="utf-8")
    permission_source = (repository / "backend/src/core/permissions.py").read_text(encoding="utf-8")
    assert 'permission="ioc.bulk_manage"' in app_source
    assert "can('ioc.bulk_manage')" in navigation_source
    assert 'IOC_BULK_MANAGE = "ioc.bulk_manage"' in permission_source
    assert "ioc.bulk.manage" not in app_source + navigation_source + permission_source
