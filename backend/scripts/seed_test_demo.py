"""Seed the deterministic, offline TriageOps demonstration dataset."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy.orm import Session

from src.core.config import get_settings
from src.core.database import SessionLocal
from src.core.security import get_password_hash
from src.models.pydantic import IOCCreate, SecurityEventCreate
from src.models.sqlalchemy import (
    Alert, AlertSource, AlertSourceType, AlertStatus, Collector, CollectorStatus,
    DetectionMatch, DetectionRule, EventType, IndicatorType, Incident,
    IOCHuntJob, IOCReportJob, IOCSighting, IOCWatchlist, IOCWatchlistMember,
    AuthSession, LogSource, LogSourceStatus, LogSourceType, OrganizationMembership,
    OrganizationRole, RefreshToken, RuleType, Severity, Tenant, User, UserRole,
)
from src.services.audit_service import audit_service
from src.services.incident_service import incident_service
from src.services.ioc_commercial_service import ioc_commercial_service
from src.services.ioc_service import ioc_service
from src.services.mitre_technique_service import mitre_technique_service
from src.services.security_event_service import security_event_service
from src.utils.datetime_utils import get_utc_now


DEMO_SLUG = "test-demo"
DEMO_NAME = "TriageOps Demo"
OWNER_EMAIL_DEFAULT = "demo.owner@example.com"
ANALYST_EMAIL_DEFAULT = "demo.analyst@example.com"


def _guard(confirmed: bool) -> None:
    settings = get_settings()
    if settings.ENVIRONMENT.casefold() in {"production", "prod"}:
        raise RuntimeError("TriageOps demo seeding is disabled in production")
    if not confirmed:
        raise RuntimeError("Database is unconfirmed; pass --confirm-test-demo-seed")


def _get_or_create(db: Session, model, defaults: dict | None = None, **lookup):
    row = db.query(model).filter_by(**lookup).first()
    if row:
        return row, False
    row = model(**lookup, **(defaults or {}))
    db.add(row)
    db.flush()
    return row, True


def _ensure_user(db: Session, tenant: Tenant, email: str, password: str, role: UserRole, org_role: OrganizationRole):
    row = db.query(User).filter(User.email == email).first()
    if not row:
        row = User(
            tenant_id=tenant.id, email=email, hashed_password=get_password_hash(password),
            full_name=f"TriageOps Demo {org_role.value.replace('_', ' ').title()}", role=role,
            is_active=True, email_verified_at=get_utc_now(), email_verification_exempt=True,
        )
        db.add(row); db.flush()
    else:
        other_membership = db.query(OrganizationMembership.id).filter(
            OrganizationMembership.user_id == row.id,
            OrganizationMembership.tenant_id != tenant.id,
        ).first()
        if str(row.tenant_id) == str(tenant.id) and other_membership is None:
            # An account owned exclusively by the reserved demo tenant is
            # disposable synthetic data. Honor the explicitly supplied
            # password on every seed and invalidate sessions issued for an
            # earlier run. Accounts shared with another organization are
            # intentionally left untouched.
            now = get_utc_now()
            row.hashed_password = get_password_hash(password)
            row.password_changed_at = now
            row.role = role
            row.is_active = True
            row.failed_login_attempts = 0
            row.locked_until = None
            row.last_failed_login_at = None
            db.query(RefreshToken).filter(
                RefreshToken.user_id == row.id,
                RefreshToken.revoked_at.is_(None),
            ).update(
                {RefreshToken.revoked_at: now, RefreshToken.revocation_reason: "demo_reseed"},
                synchronize_session=False,
            )
            db.query(AuthSession).filter(
                AuthSession.user_id == row.id,
                AuthSession.revoked_at.is_(None),
            ).update(
                {AuthSession.revoked_at: now, AuthSession.revocation_reason: "demo_reseed"},
                synchronize_session=False,
            )
    # Existing users can belong to more than one organization. For a shared
    # account preserve its home organization, password, and security state;
    # only add the explicit demo membership below.
    membership, _ = _get_or_create(
        db, OrganizationMembership, tenant_id=tenant.id, user_id=row.id,
        defaults={"role": org_role, "is_active": True},
    )
    membership.role, membership.is_active = org_role, True
    return row


def _ensure_rule(db: Session, tenant_id: str, owner_id: str, name: str, event_type: EventType, technique: str, severity: Severity):
    row = db.query(DetectionRule).filter_by(tenant_id=tenant_id, name=name).first()
    if row:
        return row
    row = DetectionRule(
        tenant_id=tenant_id, name=name, description="Deterministic synthetic demonstration rule.",
        type=RuleType.CUSTOM, rule_type=RuleType.CUSTOM, event_type=event_type,
        severity=severity, enabled=True, lifecycle_status="production", detection_kind="event_match",
        condition={"demo_marker": DEMO_SLUG}, mitre_technique_id=technique,
        owner_id=owner_id, created_by=owner_id, confidence=0.9, risk_contribution=30,
        tags=["synthetic-demo", "controlled"], protected=True,
    )
    db.add(row); db.flush()
    return row


def _ensure_attack_story(db: Session, tenant: Tenant, owner: User, collector: Collector):
    title = "[SYNTHETIC DEMO] Credential compromise to command-and-control progression"
    incident = db.query(Incident).filter_by(tenant_id=tenant.id, title=title).first()
    if incident:
        events = db.query(DetectionMatch).filter_by(tenant_id=tenant.id).all()
        return incident, [item.event for item in events if item.event is not None]

    mitre_technique_service.bootstrap_catalog(db, ["T1110", "T1059", "T1059.001", "T1071"])
    source, _ = _get_or_create(
        db, AlertSource, tenant_id=tenant.id, name="TriageOps Demo EDR",
        defaults={"type": AlertSourceType.API, "enabled": True, "is_active": True},
    )
    specs = [
        ("Repeated sign-in failures", EventType.LOGIN, "T1110", Severity.HIGH,
         {"user": "demo-user", "source_ip": "192.0.2.44", "hostname": "demo-ws01", "outcome": "failure"}),
        ("Encoded PowerShell execution", EventType.PROCESS, "T1059.001", Severity.CRITICAL,
         {"user": "demo-user", "source_ip": "192.0.2.44", "hostname": "demo-ws01", "process": "powershell.exe", "command_line": "powershell.exe -EncodedCommand <synthetic>"}),
        ("Suspicious DNS beacon", EventType.NETWORK, "T1071", Severity.HIGH,
         {"user": "demo-user", "source_ip": "192.0.2.44", "destination_ip": "198.51.100.23", "hostname": "demo-ws01", "domain": "beacon.demo.invalid"}),
    ]
    latest_incident = None
    events = []
    original_ai_analysis = incident_service._run_ai_analysis
    incident_service._run_ai_analysis = lambda *_args, **_kwargs: None
    try:
      for index, (rule_name, event_type, technique, severity, evidence) in enumerate(specs):
        rule = _ensure_rule(db, tenant.id, owner.id, f"[SYNTHETIC DEMO] {rule_name}", event_type, technique, severity)
        timestamp = get_utc_now() - timedelta(minutes=9 - index * 3)
        event = security_event_service.create_event(db, tenant.id, SecurityEventCreate(
            source="demo-collector", event_type=event_type, severity=severity,
            timestamp=timestamp, raw_event={**evidence, "demo": True},
            normalized_event={**evidence, "collector_id": collector.id, "demo_story": DEMO_SLUG},
        ))
        events.append(event)
        alert = Alert(
            tenant_id=tenant.id, source_id=source.id, detection_rule_id=rule.id, event_id=event.id,
            ocsf_data={**evidence, "attack_techniques": [technique]}, raw_data=evidence,
            risk_score=90 if severity == Severity.CRITICAL else 75, severity=severity,
            status=AlertStatus.OPEN, matched_condition=f"Controlled {rule_name.casefold()} signature matched",
            why_matched=f"Event matched {rule.name}; evidence is synthetic and scoped to the TriageOps demo.",
            created_at=timestamp,
        )
        db.add(alert); db.flush()
        db.add(DetectionMatch(
            tenant_id=tenant.id, event_id=event.id, rule_id=rule.id, alert_id=alert.id,
            matched=True, severity=severity, triggered_at=timestamp,
            matched_conditions=[{"field": "demo_story", "operator": "eq", "value": DEMO_SLUG}],
            confidence=.9, risk_contribution=30, mitre_mappings=[technique],
            data_source_provenance={"collector_id": collector.id, "source": "demo-collector"},
            explanation={"why_matched": alert.why_matched, "evidence_event_id": event.id},
        ))
        db.commit()
        candidate = incident_service.process_alert(db, alert, allow_external_enrichment=False)
        if candidate:
            latest_incident = candidate
    finally:
      incident_service._run_ai_analysis = original_ai_analysis
    if latest_incident is None:
        raise RuntimeError("Controlled alerts did not produce a correlated incident")
    latest_incident.title = title
    latest_incident.description = "Controlled multi-stage activity showing credential access, execution, and command-and-control evidence."
    latest_incident.ai_summary = "Deterministic fallback: related evidence indicates a synthetic credential-to-execution-to-beacon progression."
    latest_incident.why_suspicious = "Three distinct detections share the same user, host, source address, and bounded time window."
    latest_incident.recommended_actions = ["Validate the affected user", "Inspect the host process tree", "Contain only after authorized approval"]
    db.commit(); db.refresh(latest_incident)
    return latest_incident, events


def _ensure_iocs(db: Session, tenant: Tenant, owner: User):
    definitions = [
        (IndicatorType.IPV4, "198.51.100.23", Severity.CRITICAL, 92, 88, "active", "TLP:AMBER"),
        (IndicatorType.DOMAIN, "beacon.demo.invalid", Severity.HIGH, 84, 80, "monitoring", "TLP:GREEN"),
        (IndicatorType.SHA256, "a" * 64, Severity.MEDIUM, 70, 65, "under_review", "TLP:AMBER"),
    ]
    rows = []
    for ioc_type, value, severity, confidence, reliability, lifecycle, tlp in definitions:
        row = db.query(__import__("src.models.sqlalchemy", fromlist=["IOC"]).IOC).filter_by(
            tenant_id=tenant.id, type=ioc_type, normalized_value=value.casefold(),
        ).first()
        if not row:
            row = ioc_service.create_ioc(db, tenant.id, owner.id, IOCCreate(
                type=ioc_type, value=value, description="Synthetic TriageOps demonstration indicator.",
                source="test-controlled-offline", severity=severity, confidence_score=confidence,
                source_reliability=reliability, lifecycle_status=lifecycle, tlp=tlp,
                source_references=["urn:triageops:demo"], classification="controlled-demo",
                tags=["synthetic-demo", "synthetic"],
            ))
        row.enrichment_status = "completed_offline"
        row.last_enriched_at = get_utc_now()
        row.risk_reasons = [{"reason": "controlled_demo_confidence", "score": row.risk_score}]
        rows.append(row)
    db.commit()
    return rows


def seed(*, confirmed: bool, owner_password: str, analyst_password: str,
         owner_email: str = OWNER_EMAIL_DEFAULT, analyst_email: str = ANALYST_EMAIL_DEFAULT,
         target_tenant_slug: str = DEMO_SLUG, allow_existing_tenant: bool = False,
         session_factory=SessionLocal) -> dict:
    _guard(confirmed)
    if not owner_password or not analyst_password:
        raise RuntimeError("Set TEST_DEMO_OWNER_PASSWORD and TEST_DEMO_ANALYST_PASSWORD")
    db = session_factory()
    try:
        if target_tenant_slug == DEMO_SLUG:
            tenant, created = _get_or_create(
                db, Tenant, slug=DEMO_SLUG,
                defaults={"name": DEMO_NAME, "description": "Synthetic, isolated TriageOps demonstration dataset.",
                          "industry": "Technology", "country": "Demo", "timezone": "UTC",
                          "sensitive_action_approval_mode": "one_person"},
            )
            tenant.name, tenant.is_active = DEMO_NAME, True
        else:
            if not allow_existing_tenant:
                raise RuntimeError("Existing-tenant seeding requires an explicitly authorized seed entrypoint")
            tenant = db.query(Tenant).filter_by(slug=target_tenant_slug).first()
            if not tenant:
                raise RuntimeError(f"Target organization does not exist: {target_tenant_slug}")
            if not tenant.is_active:
                raise RuntimeError(f"Target organization is inactive: {target_tenant_slug}")
            created = False
        owner = _ensure_user(db, tenant, owner_email, owner_password, UserRole.ADMIN, OrganizationRole.OWNER)
        analyst = _ensure_user(db, tenant, analyst_email, analyst_password, UserRole.ANALYST, OrganizationRole.SOC_MANAGER)
        # Service methods scope through the active tenant on their actor. Use a
        # non-persistent view so commits cannot reload or modify the existing
        # account's home organization.
        owner_actor = SimpleNamespace(
            id=owner.id,
            tenant_id=tenant.id,
            email=owner.email,
            role=owner.role,
            is_active=owner.is_active,
        )
        log_source, _ = _get_or_create(
            db, LogSource, tenant_id=tenant.id, name="Controlled Windows Telemetry",
            defaults={"type": LogSourceType.WINDOWS_EDR, "description": "Controlled offline telemetry source.",
                      "status": LogSourceStatus.ACTIVE, "last_seen": get_utc_now()},
        )
        log_source.status = LogSourceStatus.ACTIVE
        log_source.last_seen = get_utc_now()
        token_stub = hashlib.sha256(f"{tenant.id}:offline-demo".encode()).hexdigest()
        collector = db.query(Collector).filter(
            Collector.tenant_id == tenant.id,
            ((Collector.name == "demo-collector") | (Collector.token_lookup_hash == token_stub)),
        ).first()
        if not collector:
            collector = Collector(
                tenant_id=tenant.id,
                name="demo-collector",
                token=f"disabled-{token_stub}",
                token_lookup_hash=token_stub,
            )
            db.add(collector)
        collector.log_source_id = log_source.id
        collector.name = "demo-collector"
        collector.type = "windows"
        collector.hostname = "demo-ws01"
        collector.status = CollectorStatus.ONLINE
        collector.health_status = "healthy"
        collector.last_seen = get_utc_now()
        collector.last_ingestion_at = get_utc_now()
        collector.events_collected = max(collector.events_collected or 0, 3)
        collector.events_submitted = max(collector.events_submitted or 0, 3)
        collector.events_accepted = max(collector.events_accepted or 0, 3)
        db.flush()
        db.commit()
        incident, events = _ensure_attack_story(db, tenant, owner, collector)
        iocs = _ensure_iocs(db, tenant, owner)
        alerts = db.query(Alert).filter_by(tenant_id=tenant.id, incident_id=incident.id).order_by(Alert.created_at).all()
        for index, ioc in enumerate(iocs[:2]):
            event = events[min(index + 1, len(events) - 1)]
            if not db.query(IOCSighting).filter_by(tenant_id=tenant.id, ioc_id=ioc.id, event_id=event.id, matched_field="normalized_event").first():
                db.add(IOCSighting(
                    tenant_id=tenant.id, ioc_id=ioc.id, ioc_content_hash=ioc.content_hash,
                    event_id=event.id, alert_id=alerts[min(index + 1, len(alerts) - 1)].id,
                    incident_id=incident.id, collector_id=collector.id, user_value="demo-user",
                    host="demo-ws01", source_ip="192.0.2.44", destination_ip="198.51.100.23",
                    data_source="demo-collector", matched_field="normalized_event",
                    matched_value=ioc.normalized_value, first_observed=event.timestamp, last_observed=event.timestamp,
                    confidence=100, detection_source="controlled_demo", match_method="exact",
                ))
                ioc.internal_sighting_count = (ioc.internal_sighting_count or 0) + 1
                ioc.first_internal_sighting = ioc.first_internal_sighting or event.timestamp
                ioc.last_internal_sighting = event.timestamp
        watchlist, _ = _get_or_create(
            db, IOCWatchlist, tenant_id=tenant.id, name="Priority Indicators",
            defaults={"description": "Indicators used in the controlled attack story.", "owner_id": owner.id,
                      "collaborators": [analyst.id], "tags": ["synthetic-demo"],
                      "policies": {"continuous_matching": True, "notification_cooldown_seconds": 900},
                      "tlp": "TLP:AMBER", "status": "active"},
        )
        for ioc in iocs:
            _get_or_create(db, IOCWatchlistMember, tenant_id=tenant.id, watchlist_id=watchlist.id, ioc_id=ioc.id)
        hunt, _ = _get_or_create(
            db, IOCHuntJob, tenant_id=tenant.id, ioc_id=iocs[0].id,
            defaults={"requested_by": analyst.id, "status": "completed", "query": {"days": 30, "event_limit": 10000, "watchlist_id": watchlist.id},
                      "progress": 100, "events_scanned": len(events), "matches_found": 1,
                      "truncated": False, "started_at": get_utc_now(), "completed_at": get_utc_now()},
        )
        db.commit()
        draft = db.query(DetectionRule).filter_by(tenant_id=tenant.id, name="[SYNTHETIC DEMO] IOC containment signal draft").first()
        if not draft:
            draft = ioc_commercial_service.generate_detection(db, owner_actor, iocs[0].id, {"name": "[SYNTHETIC DEMO] IOC containment signal draft", "severity": "high"})
        recommendation = db.query(__import__("src.models.sqlalchemy", fromlist=["IOCResponseRecommendation"]).IOCResponseRecommendation).filter_by(
            tenant_id=tenant.id, ioc_id=iocs[0].id, status="pending_approval",
        ).first()
        if not recommendation:
            recommendation = ioc_commercial_service.create_recommendation(
                db, analyst, iocs[0].id, {"action": "block_ip", "target_connector_type": "controlled-demo-no-connector"},
            )
        report = db.query(IOCReportJob).filter_by(tenant_id=tenant.id, report_type="test_demo", format="json", status="completed").first()
        if not report:
            report = ioc_commercial_service.create_report(db, owner_actor, "test_demo", "json", {"demo": True})
            report = ioc_commercial_service.process_report(db, report.id, tenant.id)
        audit_service.record(db, action="ioc.demo_seeded", user=owner_actor, tenant_id=tenant.id,
                             resource_type="tenant", resource_id=tenant.id,
                             details={"created_tenant": created, "incident_id": incident.id, "ioc_count": len(iocs)})
        return {
            "tenant_id": tenant.id, "owner_id": owner.id, "analyst_id": analyst.id,
            "incident_id": incident.id, "ioc_ids": [row.id for row in iocs],
            "watchlist_id": watchlist.id, "hunt_id": hunt.id, "draft_rule_id": draft.id,
            "recommendation_id": recommendation.id, "report_id": report.id,
            "owner_email": owner.email, "analyst_email": analyst.email,
            "tenant_slug": tenant.slug,
        }
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-test-demo-seed", action="store_true")
    parser.add_argument("--owner-email", default=os.getenv("TEST_DEMO_OWNER_EMAIL", OWNER_EMAIL_DEFAULT))
    parser.add_argument("--analyst-email", default=os.getenv("TEST_DEMO_ANALYST_EMAIL", ANALYST_EMAIL_DEFAULT))
    args = parser.parse_args()
    result = seed(
        confirmed=args.confirm_test_demo_seed,
        owner_password=os.getenv("TEST_DEMO_OWNER_PASSWORD", ""),
        analyst_password=os.getenv("TEST_DEMO_ANALYST_PASSWORD", ""),
        owner_email=args.owner_email, analyst_email=args.analyst_email,
    )
    print(f"TriageOps demo ready for tenant {result['tenant_id']}")
    print(f"Owner account: {result['owner_email']} (password supplied via TEST_DEMO_OWNER_PASSWORD)")
    print(f"Analyst account: {result['analyst_email']} (password supplied via TEST_DEMO_ANALYST_PASSWORD)")
    print(f"Incident: {result['incident_id']} | Report: {result['report_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
