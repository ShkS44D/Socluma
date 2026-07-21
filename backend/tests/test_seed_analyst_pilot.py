import os
import tempfile

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from scripts import seed_analyst_pilot as pilot
from src.core.database import Base
from src.models.sqlalchemy import (
    Alert,
    DetectionRule,
    Incident,
    IncidentAlert,
    IncidentMitreMapping,
    Tenant,
    User,
    UserRole,
)
from src.services.default_detection_rules import DEFAULT_DETECTION_RULES


def test_pilot_seed_is_strict_idempotent_tenant_scoped_and_offline(monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(engine)
    db = Session()
    try:
        pilot_tenant = Tenant(name="Pilot", slug="pilot")
        other_tenant = Tenant(name="Other", slug="other")
        db.add_all([pilot_tenant, other_tenant])
        db.flush()
        analyst = User(
            tenant_id=pilot_tenant.id,
            email="pilot@example.com",
            hashed_password="unused",
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add(analyst)
        for definition in DEFAULT_DETECTION_RULES:
            values = dict(definition)
            values.setdefault("query", "")
            values.setdefault("sigma_rule", "")
            db.add(DetectionRule(tenant_id=pilot_tenant.id, **values))
        db.commit()

        def forbidden_provider_call(*_args, **_kwargs):
            raise AssertionError("seed attempted an AI or external provider call")

        original_ai = forbidden_provider_call
        original_threat = forbidden_provider_call
        monkeypatch.setattr(pilot, "SessionLocal", Session)
        monkeypatch.setattr(pilot.settings, "ADMIN_EMAIL", analyst.email)
        monkeypatch.setattr(pilot.incident_service, "_run_ai_analysis", original_ai)
        monkeypatch.setattr(pilot.threat_intel_service, "lookup_incident_indicators", original_threat)
        monkeypatch.setattr("httpx.Client.request", forbidden_provider_call)
        monkeypatch.setattr("requests.sessions.Session.request", forbidden_provider_call)

        first = pilot.seed()
        first_check = Session()
        first_ids = {item.id for item in first_check.query(Incident).filter(Incident.tenant_id == pilot_tenant.id)}
        first_check.close()
        second = pilot.seed()
        second_check = Session()
        second_ids = {item.id for item in second_check.query(Incident).filter(Incident.tenant_id == pilot_tenant.id)}
        second_check.close()

        assert len(first) == len(pilot.ALL_SCENARIO_NAMES) == 7
        assert first_ids == second_ids
        assert pilot.incident_service._run_ai_analysis is original_ai
        assert pilot.threat_intel_service.lookup_incident_indicators is original_threat

        check = Session()
        try:
            pilot_incidents = check.query(Incident).filter(Incident.tenant_id == pilot_tenant.id).all()
            correlated = [item for item in pilot_incidents if item.title in {
                pilot._title(name) for name, _simulation in pilot.SCENARIOS
            }]
            assert len(pilot_incidents) == 7
            assert len(correlated) == 4
            assert all(check.query(IncidentAlert).filter_by(incident_id=item.id).count() >= 2 for item in correlated)
            assert all(item.correlation_score and item.correlation_score >= 45 for item in correlated)
            assert all(check.query(IncidentMitreMapping).filter_by(
                incident_id=item.id, mapping_source="correlated",
            ).count() >= 1 for item in correlated)
            assert check.query(Incident).filter(Incident.tenant_id == other_tenant.id).count() == 0
            assert check.query(Alert).filter(Alert.tenant_id == other_tenant.id).count() == 0
        finally:
            check.close()
    finally:
        db.close()
        engine.dispose()
        try:
            os.remove(path)
        except PermissionError:
            pass
