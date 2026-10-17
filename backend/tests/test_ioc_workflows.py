import pytest
from datetime import timedelta
import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.core.crypto import decrypt_bytes, decrypt_json_secret
from src.core.database import Base
from src.models.sqlalchemy import (
    DetectionRuleVersion,
    IOC,
    IOCBulkActionJob,
    IOCImportRowResult,
    IOCNotificationState,
    IOCReviewHistory,
    IndicatorType,
    OrganizationMembership,
    OrganizationRole,
    SecurityEvent,
    Severity,
    Tenant,
    ThreatIntelligenceRelationship,
    ThreatSourceCredential,
    User,
    UserRole,
)
from src.services.approval_service import approval_service
from src.services.audit_management_service import LocalAuditArtifactStorage
from src.services.ioc_commercial_service import (
    IOCCommercialError,
    ioc_commercial_service,
)
from src.services.ioc_intelligence_service import IOCValidationError
from src.utils.datetime_utils import get_utc_now


@pytest.fixture()
def commercial_db(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    tenant = Tenant(name="Commercial IOC", slug="commercial-ioc")
    session.add(tenant)
    session.flush()
    user = User(
        tenant_id=tenant.id,
        email="commercial-ioc@example.test",
        hashed_password="not-used-in-service-tests",
        full_name="Commercial IOC Tester",
        role=UserRole.ADMIN,
    )
    session.add(user)
    session.flush()
    session.add(
        OrganizationMembership(
            tenant_id=tenant.id,
            user_id=user.id,
            role=OrganizationRole.OWNER,
            is_active=True,
        )
    )
    session.commit()
    monkeypatch.setattr(
        ioc_commercial_service.settings,
        "IOC_COMMERCIAL_ARTIFACT_DIRECTORY",
        str(tmp_path / "artifacts"),
    )
    yield session, tenant, user
    session.close()
    engine.dispose()


def test_credentials_are_encrypted_and_public_response_is_redacted(commercial_db):
    db, tenant, user = commercial_db
    row = ioc_commercial_service.create_credential(
        db,
        user,
        {
            "provider": "virustotal",
            "name": "Production",
            "credentials": {"api_key": "commercial-secret-value"},
        },
    )
    persisted = db.query(ThreatSourceCredential).filter_by(
        id=row.id, tenant_id=tenant.id
    ).one()
    assert "commercial-secret-value" not in persisted.encrypted_credentials
    assert decrypt_json_secret(
        persisted.encrypted_credentials,
        key_version=persisted.encryption_key_version,
    ) == {"api_key": "commercial-secret-value"}
    public = ioc_commercial_service.credential_public(persisted)
    assert "encrypted_credentials" not in public
    assert "api_key" not in public
    assert public["configured"] is True


def test_credential_rotation_changes_ciphertext_and_fingerprint(commercial_db):
    db, _tenant, user = commercial_db
    row = ioc_commercial_service.create_credential(
        db, user, {"provider": "otx", "name": "OTX", "credentials": {"api_key": "old-secret"}}
    )
    old_ciphertext, old_fingerprint = row.encrypted_credentials, row.credential_fingerprint
    rotated = ioc_commercial_service.rotate_credential(
        db, user.tenant_id, row.id, user.id, {"api_key": "new-secret"}
    )
    assert rotated.encrypted_credentials != old_ciphertext
    assert rotated.credential_fingerprint != old_fingerprint
    assert decrypt_json_secret(
        rotated.encrypted_credentials,
        key_version=rotated.encryption_key_version,
    ) == {"api_key": "new-secret"}


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/feed",
        "https://127.0.0.1/feed",
        "https://169.254.169.254/latest/meta-data",
        "https://user:password@example.com/feed",
        "file:///etc/passwd",
    ],
)
def test_external_source_ssrf_guards(url):
    with pytest.raises((IOCValidationError, IOCCommercialError)):
        ioc_commercial_service.validate_external_url(url)


def test_safe_request_streams_with_size_bound(monkeypatch):
    original_client = httpx.Client
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, content=b"x" * 32, request=request)
    )
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: original_client(transport=transport, timeout=kwargs["timeout"]),
    )
    monkeypatch.setattr(
        ioc_commercial_service, "validate_external_url", lambda url: url
    )
    monkeypatch.setattr(
        ioc_commercial_service.settings, "THREAT_SOURCE_MAX_RESPONSE_BYTES", 16
    )
    with pytest.raises(IOCCommercialError, match="exceeds configured limit"):
        ioc_commercial_service.safe_request("GET", "https://feed.example.test/data")


def test_safe_request_revalidates_redirect_destination(monkeypatch):
    original_client = httpx.Client
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            302,
            headers={"location": "https://127.0.0.1/private"},
            request=request,
        )
    )
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: original_client(transport=transport, timeout=kwargs["timeout"]),
    )
    checked = []

    def validate(url):
        checked.append(url)
        if "127.0.0.1" in url:
            raise IOCCommercialError("THREAT_SOURCE_CREDENTIAL_INVALID", "blocked")
        return url

    monkeypatch.setattr(ioc_commercial_service, "validate_external_url", validate)
    with pytest.raises(IOCCommercialError, match="blocked"):
        ioc_commercial_service.safe_request("GET", "https://feed.example.test/data")
    assert checked == [
        "https://feed.example.test/data",
        "https://127.0.0.1/private",
    ]


def test_misp_mapping_normalizes_composites_and_preserves_safe_provenance():
    mapped = ioc_commercial_service._map_misp_attribute(
        {
            "type": "filename|sha256",
            "value": f"malware.exe|{'A' * 64}",
            "uuid": "misp-attribute-1",
            "Tag": [{"name": "tlp:green"}, {"name": "campaign:test"}],
        }
    )
    assert mapped["type"] == "sha256"
    assert mapped["normalized_value"] == "a" * 64
    assert mapped["external_source_ids"] == {"misp_uuid": "misp-attribute-1"}
    assert mapped["tlp"] == "TLP:GREEN"


def test_csv_dry_run_reports_partial_row_results_without_creating_iocs(commercial_db):
    db, tenant, user = commercial_db
    job = ioc_commercial_service.create_import_job(
        db,
        user,
        "demo.csv",
        "csv",
        b"type,value,source\nipv4,192.0.2.10,demo\ndomain,invalid,demo\n",
        {"dry_run": True, "tlp": "TLP:AMBER"},
    )
    result = ioc_commercial_service.process_import(db, job.id, tenant.id)
    assert result.status == "validated"
    assert result.counts == {"valid": 1, "invalid": 1, "duplicates": 0, "created": 0}
    assert db.query(IOC).filter_by(tenant_id=tenant.id).count() == 0
    assert [row.status for row in db.query(IOCImportRowResult).order_by(
        IOCImportRowResult.row_number
    )] == ["valid", "invalid"]


def test_notification_dedup_and_tlp_red_restriction(commercial_db):
    db, tenant, _user = commercial_db
    assert ioc_commercial_service.notification_allowed(
        db, tenant.id, "ioc_sighting", "ioc-1", "TLP:AMBER"
    )
    assert not ioc_commercial_service.notification_allowed(
        db, tenant.id, "ioc_sighting", "ioc-1", "TLP:AMBER"
    )
    assert not ioc_commercial_service.notification_allowed(
        db, tenant.id, "ioc_sighting", "ioc-red", "TLP:RED"
    )
    assert db.query(IOCNotificationState).filter_by(tenant_id=tenant.id).count() == 1


def test_graph_is_tenant_scoped_and_bounded(commercial_db, monkeypatch):
    db, tenant, _user = commercial_db
    other = Tenant(name="Other", slug="other")
    db.add(other)
    db.flush()
    root = IOC(
        tenant_id=tenant.id,
        type=IndicatorType.IPV4,
        value="192.0.2.20",
        normalized_value="192.0.2.20",
        display_value="192.0.2.20",
        lifecycle_status="active",
    )
    foreign = IOC(
        tenant_id=other.id,
        type=IndicatorType.IPV4,
        value="192.0.2.21",
        normalized_value="192.0.2.21",
        display_value="192.0.2.21",
        lifecycle_status="active",
    )
    db.add_all([root, foreign])
    db.commit()
    monkeypatch.setattr(ioc_commercial_service.settings, "IOC_GRAPH_MAX_NODES", 1)
    result = ioc_commercial_service.graph(db, tenant.id, root.id, depth=3)
    assert [node["id"] for node in result["nodes"]] == [root.id]
    assert foreign.id not in {node["id"] for node in result["nodes"]}
    assert len(result["nodes"]) <= 1


def test_report_artifact_is_encrypted_checksum_bound_and_excludes_tlp_red(commercial_db):
    db, tenant, user = commercial_db
    db.add_all(
        [
            IOC(
                tenant_id=tenant.id,
                type=IndicatorType.DOMAIN,
                value="report.example",
                normalized_value="report.example",
                display_value="report.example",
                lifecycle_status="active",
                tlp="TLP:AMBER",
            ),
            IOC(
                tenant_id=tenant.id,
                type=IndicatorType.DOMAIN,
                value="restricted.example",
                normalized_value="restricted.example",
                display_value="restricted.example",
                lifecycle_status="active",
                tlp="TLP:RED",
            ),
        ]
    )
    db.commit()
    job = ioc_commercial_service.create_report(db, user, "intelligence", "json", {})
    completed = ioc_commercial_service.process_report(db, job.id, tenant.id)
    assert completed.status == "completed"
    assert completed.manifest["row_count"] == 1
    encrypted = LocalAuditArtifactStorage(
        ioc_commercial_service.settings.IOC_COMMERCIAL_ARTIFACT_DIRECTORY
    ).read(completed.artifact_key)
    plaintext = decrypt_bytes(encrypted)
    assert b"report.example" in plaintext
    assert b"restricted.example" not in plaintext
    assert completed.checksum


def test_expired_artifacts_are_deleted_and_jobs_marked_expired(commercial_db):
    db, tenant, user = commercial_db
    job = ioc_commercial_service.create_import_job(
        db,
        user,
        "expired.csv",
        "csv",
        b"type,value\nipv4,192.0.2.50\n",
        {"dry_run": True},
    )
    job.expires_at = get_utc_now() - timedelta(seconds=1)
    db.commit()
    storage = LocalAuditArtifactStorage(
        ioc_commercial_service.settings.IOC_COMMERCIAL_ARTIFACT_DIRECTORY
    )
    assert storage.read(job.artifact_key)
    result = ioc_commercial_service.cleanup_expired_artifacts(db)
    db.refresh(job)
    assert result["expired_imports"] == 1
    assert job.status == "expired"
    with pytest.raises(FileNotFoundError):
        storage.read(job.artifact_key)


def test_taxii_sync_imports_supported_objects_and_updates_cursor(
    commercial_db, monkeypatch
):
    db, tenant, user = commercial_db
    monkeypatch.setattr(
        ioc_commercial_service, "validate_external_url", lambda url: url
    )
    source = ioc_commercial_service.create_credential(
        db,
        user,
        {
            "provider": "taxii",
            "name": "Demo TAXII",
            "base_url": "https://taxii.example.test/api",
            "credentials": {"token": "test-only-token"},
        },
    )
    config = ioc_commercial_service.create_sync_configuration(
        db,
        user,
        {
            "provider": "taxii",
            "name": "Demo collection",
            "credential_id": source.id,
            "api_root": "https://taxii.example.test/api",
            "collection_id": "collection-1",
        },
    )
    job = ioc_commercial_service.start_sync(db, user, config.id)
    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--00000000-0000-4000-8000-000000000076",
        "pattern": "[domain-name:value = 'taxii.example']",
    }
    monkeypatch.setattr(
        ioc_commercial_service,
        "safe_request",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={"objects": [indicator], "more": False},
            headers={"X-TAXII-Date-Added-Last": "2026-07-30T00:00:00Z"},
            request=httpx.Request("GET", "https://taxii.example.test"),
        ),
    )
    completed = ioc_commercial_service.process_sync(db, job.id, tenant.id)
    assert completed.status == "completed"
    assert completed.counts["imported"] == 1
    assert db.query(IOC).filter_by(
        tenant_id=tenant.id, normalized_value="taxii.example"
    ).count() == 1
    db.refresh(config)
    assert config.safe_cursor["added_after"] == "2026-07-30T00:00:00Z"


def test_destructive_bulk_action_requires_preview_then_confirmation(commercial_db):
    db, tenant, user = commercial_db
    ioc = IOC(
        tenant_id=tenant.id,
        type=IndicatorType.IPV4,
        value="192.0.2.60",
        normalized_value="192.0.2.60",
        display_value="192.0.2.60",
        lifecycle_status="active",
        created_by=user.id,
    )
    db.add(ioc)
    db.commit()
    preview = ioc_commercial_service.create_bulk_job(
        db,
        user,
        {"action": "expire", "ioc_ids": [ioc.id], "options": {"reason": "test"}},
        confirmed=False,
    )
    assert preview.status == "preview"
    with pytest.raises(IOCCommercialError):
        ioc_commercial_service.process_bulk(db, preview.id, tenant.id)
    preview.status = "pending"
    db.commit()
    completed = ioc_commercial_service.process_bulk(db, preview.id, tenant.id)
    db.refresh(ioc)
    assert completed.status == "completed"
    assert completed.results == [{"ioc_id": ioc.id, "status": "completed"}]
    assert ioc.lifecycle_status == "expired"


def test_review_assignment_and_creator_self_approval_guard(commercial_db):
    db, tenant, creator = commercial_db
    reviewer = User(
        tenant_id=tenant.id,
        email="ioc-reviewer@example.test",
        hashed_password="not-used",
        role=UserRole.ANALYST,
    )
    db.add(reviewer)
    db.flush()
    db.add(
        OrganizationMembership(
            tenant_id=tenant.id,
            user_id=reviewer.id,
            role=OrganizationRole.ANALYST,
            is_active=True,
        )
    )
    ioc = IOC(
        tenant_id=tenant.id,
        type=IndicatorType.DOMAIN,
        value="review.example",
        normalized_value="review.example",
        display_value="review.example",
        lifecycle_status="new",
        created_by=creator.id,
    )
    db.add(ioc)
    db.commit()
    assignment = ioc_commercial_service.assign_reviewer(
        db, tenant.id, ioc.id, reviewer.id, creator.id
    )
    assert assignment.reviewer_id == reviewer.id
    with pytest.raises(IOCCommercialError, match="self-approve"):
        ioc_commercial_service.review_decision(
            db, creator, ioc.id, {"action": "approve_activate"}
        )
    approved = ioc_commercial_service.review_decision(
        db,
        reviewer,
        ioc.id,
        {
            "action": "approve_activate",
            "comment": "Validated against internal evidence",
            "confidence_score": 85,
        },
    )
    assert approved.lifecycle_status == "active"
    assert approved.review_status == "approved"
    assert db.query(IOCReviewHistory).filter_by(
        tenant_id=tenant.id, ioc_id=ioc.id
    ).count() == 2


def test_ioc_to_detection_creates_disabled_versioned_draft(commercial_db):
    db, tenant, user = commercial_db
    ioc = IOC(
        tenant_id=tenant.id,
        type=IndicatorType.IPV4,
        value="192.0.2.70",
        normalized_value="192.0.2.70",
        display_value="192.0.2.70",
        content_hash="7" * 64,
        lifecycle_status="active",
        confidence_score=80,
        created_by=user.id,
    )
    db.add(ioc)
    db.commit()
    rule = ioc_commercial_service.generate_detection(
        db, user, ioc.id, {"name": "IOC 192.0.2.70 detection"}
    )
    assert rule.enabled is False
    assert rule.lifecycle_status == "draft"
    version = db.query(DetectionRuleVersion).filter_by(rule_id=rule.id).one()
    assert version.source_metadata["source_id"] == ioc.id
    relationship = db.query(ThreatIntelligenceRelationship).filter_by(
        tenant_id=tenant.id,
        source_type="detection_rule",
        source_id=rule.id,
        target_id=ioc.id,
    ).one()
    assert relationship.relationship_type == "detects"


def test_response_recommendation_is_idempotent_and_blocks_self_approval(
    commercial_db,
):
    db, tenant, requester = commercial_db
    ioc = IOC(
        tenant_id=tenant.id,
        type=IndicatorType.DOMAIN,
        value="block.example",
        normalized_value="block.example",
        display_value="block.example",
        content_hash="8" * 64,
        lifecycle_status="active",
        created_by=requester.id,
    )
    db.add(ioc)
    db.commit()
    first = ioc_commercial_service.create_recommendation(
        db, requester, ioc.id, {"action": "block_domain"}
    )
    second = ioc_commercial_service.create_recommendation(
        db, requester, ioc.id, {"action": "block_domain"}
    )
    assert first.id == second.id
    with pytest.raises(Exception) as exc:
        approval_service.decide(db, requester, first.approval_id, "approve")
    assert getattr(exc.value, "status_code", None) == 403


def test_active_ioc_matching_is_tenant_scoped_and_idempotent(commercial_db):
    db, tenant, user = commercial_db
    active = IOC(
        tenant_id=tenant.id,
        type=IndicatorType.IPV4,
        value="192.0.2.80",
        normalized_value="192.0.2.80",
        display_value="192.0.2.80",
        content_hash="9" * 64,
        lifecycle_status="active",
        created_by=user.id,
    )
    db.add(active)
    db.flush()
    event = SecurityEvent(
        tenant_id=tenant.id,
        source="test",
        event_type="network",
        severity=Severity.MEDIUM,
        raw_event={"source_ip": "192.0.2.80"},
        normalized_event={"network": {"src_ip": "192.0.2.80"}},
    )
    db.add(event)
    db.commit()
    from src.services.ioc_intelligence_service import ioc_intelligence_service

    first = ioc_intelligence_service.match_event(db, event)
    db.commit()
    second = ioc_intelligence_service.match_event(db, event)
    db.commit()
    assert len(first) == 1
    assert second == []
    db.refresh(active)
    assert active.internal_sighting_count == 1
