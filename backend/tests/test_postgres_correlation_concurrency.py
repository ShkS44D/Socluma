import os
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.models.sqlalchemy import (
    Alert, AlertSource, AlertSourceType, AlertStatus, Incident, IncidentAlert, Severity, Tenant,
)
from src.services.incident_service import incident_service
from src.services.mitre_technique_service import mitre_technique_service


def test_postgresql_workers_create_one_incident_for_two_related_alerts():
    url = os.getenv("TEST_POSTGRES_DATABASE_URL")
    if not url:
        pytest.skip("TEST_POSTGRES_DATABASE_URL is not configured")
    engine = create_engine(url, pool_pre_ping=True)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    seed = Session()
    suffix = uuid.uuid4().hex
    tenant = Tenant(name=f"Concurrency {suffix}", slug=f"concurrency-{suffix}")
    seed.add(tenant)
    seed.flush()
    source = AlertSource(tenant_id=tenant.id, name="Concurrency EDR", type=AlertSourceType.API)
    seed.add(source)
    seed.flush()
    mitre_technique_service.bootstrap_catalog(seed)
    alerts = [
        Alert(
            tenant_id=tenant.id, source_id=source.id, severity=Severity.HIGH, status=AlertStatus.OPEN,
            raw_data={"hostname": f"host-{suffix}", "agent_id": f"agent-{suffix}"},
            ocsf_data={"attack_techniques": [technique]}, why_matched=f"Concurrent evidence for {technique}",
        )
        for technique in ("T1059.001", "T1003.001")
    ]
    seed.add_all(alerts)
    seed.commit()
    alert_ids = [item.id for item in alerts]
    tenant_id = tenant.id
    seed.close()

    def process(alert_id: str) -> str | None:
        session = Session()
        try:
            alert = session.query(Alert).filter_by(id=alert_id).one()
            incident = incident_service.process_alert(session, alert, allow_external_enrichment=False)
            return incident.id if incident else None
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(process, alert_ids))

    verify = Session()
    try:
        incidents = verify.query(Incident).filter_by(tenant_id=tenant_id).all()
        assert len(incidents) == 1
        links = verify.query(IncidentAlert).filter_by(incident_id=incidents[0].id).all()
        assert {link.alert_id for link in links} == set(alert_ids)
        assert all(verify.query(Alert).filter_by(id=alert_id).one().incident_id == incidents[0].id for alert_id in alert_ids)
        assert set(filter(None, results)) == {incidents[0].id}
    finally:
        verify.close()
        engine.dispose()
