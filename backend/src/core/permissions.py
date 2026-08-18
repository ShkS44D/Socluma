from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from src.api.deps import get_current_user, get_db
from src.models.sqlalchemy import (
    OrganizationMembership,
    OrganizationRole,
    OrganizationStatus,
    User,
)


class Permission(str, Enum):
    USERS_VIEW = "users.view"
    USERS_CREATE = "users.create"
    USERS_UPDATE = "users.update"
    USERS_DISABLE = "users.disable"
    USERS_DELETE = "users.delete"
    USERS_INVITE = "users.invite"
    ROLES_VIEW = "roles.view"
    ROLES_CREATE = "roles.create"
    ROLES_UPDATE = "roles.update"
    ROLES_DELETE = "roles.delete"
    ROLES_ASSIGN = "roles.assign"
    ORGANIZATION_VIEW = "organization.view"
    ORGANIZATION_UPDATE = "organization.update"
    ORGANIZATION_SECURITY_MANAGE = "organization.security.manage"
    ORGANIZATION_DELETE = "organization.delete"
    ORGANIZATION_DELETE_CANCEL = "organization.delete.cancel"
    ALERTS_VIEW = "alerts.view"
    ALERTS_CREATE = "alerts.create"
    ALERTS_UPDATE = "alerts.update"
    ALERTS_ASSIGN = "alerts.assign"
    ALERTS_CLOSE = "alerts.close"
    ALERTS_BULK_MANAGE = "alerts.bulk_manage"
    INCIDENTS_VIEW = "incidents.view"
    INCIDENTS_CREATE = "incidents.create"
    INCIDENTS_UPDATE = "incidents.update"
    INCIDENTS_ASSIGN = "incidents.assign"
    INCIDENTS_CLOSE = "incidents.close"
    INCIDENTS_DELETE = "incidents.delete"
    DETECTIONS_VIEW = "detections.view"
    DETECTIONS_CREATE = "detections.create"
    DETECTIONS_UPDATE = "detections.update"
    DETECTIONS_ENABLE = "detections.enable"
    DETECTIONS_VALIDATE = "detections.validate"
    DETECTIONS_TEST = "detections.test"
    DETECTIONS_DISABLE = "detections.disable"
    DETECTIONS_RETIRE = "detections.retire"
    DETECTIONS_ROLLBACK = "detections.rollback"
    DETECTIONS_CLONE = "detections.clone"
    DETECTIONS_IMPORT = "detections.import"
    DETECTIONS_EXPORT = "detections.export"
    DETECTIONS_METRICS_VIEW = "detections.metrics.view"
    DETECTIONS_RECOMMENDATIONS_MANAGE = "detections.recommendations.manage"
    DETECTIONS_EXCEPTIONS_VIEW = "detections.exceptions.view"
    DETECTIONS_CONTENT_PACKS_VIEW = "detections.content_packs.view"
    MITRE_COVERAGE_VIEW = "mitre.coverage.view"
    MITRE_COVERAGE_EXPORT = "mitre.coverage.export"
    DETECTIONS_DELETE = "detections.delete"
    DETECTIONS_REVIEW = "detections.review"
    DETECTIONS_APPROVE = "detections.approve"
    DETECTIONS_PUBLISH = "detections.publish"
    DETECTIONS_SIMULATE = "detections.simulate"
    DETECTIONS_EXCEPTIONS_MANAGE = "detections.exceptions.manage"
    DETECTIONS_MAINTENANCE_MANAGE = "detections.maintenance.manage"
    DETECTIONS_ANALYTICS_VIEW = "detections.analytics.view"
    DETECTIONS_CONTENT_PACK_MANAGE = "detections.content_pack.manage"
    SIGMA_VIEW = "sigma.view"
    SIGMA_CREATE = "sigma.create"
    SIGMA_UPDATE = "sigma.update"
    SIGMA_ENABLE = "sigma.enable"
    SIGMA_DELETE = "sigma.delete"
    SIGMA_VALIDATE = "sigma.validate"
    SIGMA_IMPORT = "sigma.import"
    SIGMA_EXPORT = "sigma.export"
    SIGMA_PUBLISH = "sigma.publish"
    PLAYBOOKS_VIEW = "playbooks.view"
    PLAYBOOKS_CREATE = "playbooks.create"
    PLAYBOOKS_UPDATE = "playbooks.update"
    PLAYBOOKS_PUBLISH = "playbooks.publish"
    PLAYBOOKS_EXECUTE = "playbooks.execute"
    PLAYBOOKS_APPROVE = "playbooks.approve"
    SOAR_VIEW = "soar.view"
    SOAR_MANAGE = "soar.manage"
    SOAR_CREDENTIALS_MANAGE = "soar.credentials.manage"
    SOAR_EXECUTE = "soar.execute"
    SOAR_APPROVE = "soar.approve"
    THREAT_INTELLIGENCE_VIEW = "threat_intelligence.view"
    THREAT_INTELLIGENCE_MANAGE = "threat_intelligence.manage"
    IOC_VIEW = "ioc.view"
    IOC_CREATE = "ioc.create"
    IOC_UPDATE = "ioc.update"
    IOC_REVIEW = "ioc.review"
    IOC_ACTIVATE = "ioc.activate"
    IOC_EXPIRE = "ioc.expire"
    IOC_REVOKE = "ioc.revoke"
    IOC_DELETE = "ioc.delete"
    IOC_MERGE = "ioc.merge"
    IOC_BULK_MANAGE = "ioc.bulk_manage"
    IOC_ENRICH = "ioc.enrich"
    IOC_HUNT = "ioc.hunt"
    IOC_SIGHTINGS_VIEW = "ioc.sightings.view"
    IOC_SIGHTINGS_MANAGE = "ioc.sightings.manage"
    IOC_WATCHLISTS_VIEW = "ioc.watchlists.view"
    IOC_WATCHLISTS_MANAGE = "ioc.watchlists.manage"
    IOC_ALLOWLISTS_VIEW = "ioc.allowlists.view"
    IOC_ALLOWLISTS_MANAGE = "ioc.allowlists.manage"
    IOC_RELATIONSHIPS_VIEW = "ioc.relationships.view"
    IOC_RELATIONSHIPS_MANAGE = "ioc.relationships.manage"
    IOC_IMPORT = "ioc.import"
    IOC_EXPORT = "ioc.export"
    IOC_REPORTS_VIEW = "ioc.reports.view"
    IOC_REPORTS_EXPORT = "ioc.reports.export"
    IOC_RESPONSE_RECOMMEND = "ioc.response.recommend"
    IOC_RESPONSE_APPROVE = "ioc.response.approve"
    IOC_REVIEW_ASSIGN = "ioc.review.assign"
    IOC_APPROVE = "ioc.approve"
    IOC_WATCHLIST_POLICIES_MANAGE = "ioc.watchlists.policies.manage"
    IOC_HUNTS_MANAGE = "ioc.hunts.manage"
    IOC_GRAPH_VIEW = "ioc.graph.view"
    IOC_DETECTION_GENERATE = "ioc.detection.generate"
    THREAT_INTELLIGENCE_SOURCES_VIEW = "threat_intelligence.sources.view"
    THREAT_INTELLIGENCE_SOURCES_MANAGE = "threat_intelligence.sources.manage"
    THREAT_INTELLIGENCE_SOURCES_TEST = "threat_intelligence.sources.test"
    THREAT_INTELLIGENCE_SYNC = "threat_intelligence.sync"
    THREAT_INTELLIGENCE_RELIABILITY_MANAGE = "threat_intelligence.reliability.manage"
    STIX_IMPORT = "stix.import"
    STIX_EXPORT = "stix.export"
    TAXII_MANAGE = "taxii.manage"
    TAXII_SYNC = "taxii.sync"
    MISP_MANAGE = "misp.manage"
    MISP_SYNC = "misp.sync"
    TLP_OVERRIDE = "tlp.override"
    AUDIT_VIEW = "audit.view"
    AUDIT_EXPORT = "audit.export"
    AUDIT_INTEGRITY_VERIFY = "audit.integrity.verify"
    AUDIT_RETENTION_MANAGE = "audit.retention.manage"
    AUDIT_LEGAL_HOLD_VIEW = "audit.legal_hold.view"
    AUDIT_LEGAL_HOLD_MANAGE = "audit.legal_hold.manage"
    AUDIT_ARCHIVE_MANAGE = "audit.archive.manage"
    AUDIT_EXPORT_DOWNLOAD = "audit.export.download"
    DATA_PROTECTION_VIEW = "data_protection.view"
    DATA_PROTECTION_MANAGE = "data_protection.manage"
    ENCRYPTION_ROTATION_EXECUTE = "encryption.rotation.execute"
    TRIAGE_AI_USE = "triage_ai.use"
    TRIAGE_AI_MANAGE = "triage_ai.manage"
    COLLECTORS_VIEW = "collectors.view"
    COLLECTORS_MANAGE = "collectors.manage"
    COLLECTORS_REVOKE = "collectors.revoke"
    COLLECTORS_ENROLL = "collectors.enroll"
    COLLECTOR_CREDENTIALS_ROTATE = "collector_credentials.rotate"
    COLLECTOR_POLICIES_VIEW = "collector_policies.view"
    COLLECTOR_POLICIES_MANAGE = "collector_policies.manage"
    COLLECTOR_GROUPS_MANAGE = "collector_groups.manage"
    COLLECTOR_UPDATES_MANAGE = "collector_updates.manage"
    TELEMETRY_VIEW = "telemetry.view"
    TELEMETRY_INGEST = "telemetry.ingest"
    TELEMETRY_IMPORT = "telemetry.import"
    TELEMETRY_REPLAY = "telemetry.replay"
    DEAD_LETTER_VIEW = "dead_letter.view"
    DEAD_LETTER_MANAGE = "dead_letter.manage"
    DATA_SOURCES_VIEW = "data_sources.view"
    DATA_SOURCES_MANAGE = "data_sources.manage"
    INGESTION_METRICS_VIEW = "ingestion_metrics.view"
    SEARCH_EVENTS = "search.events"
    SEARCH_ALERTS = "search.alerts"
    SEARCH_INCIDENTS = "search.incidents"
    SEARCH_ENTITIES = "search.entities"
    SEARCH_EXTENDED_RANGE = "search.extended_range"
    SEARCH_HISTORY_VIEW = "search.history.view"
    SEARCH_HISTORY_MANAGE = "search.history.manage"
    SEARCH_SAVED_VIEW = "search.saved.view"
    SEARCH_SAVED_MANAGE = "search.saved.manage"
    SEARCH_SAVED_SHARE = "search.saved.share"
    SEARCH_TEMPLATES_MANAGE = "search.templates.manage"
    SEARCH_SCHEDULE_MANAGE = "search.schedule.manage"
    SEARCH_EXPORT = "search.export"
    INVESTIGATIONS_VIEW = "investigations.view"
    INVESTIGATIONS_CREATE = "investigations.create"
    INVESTIGATIONS_UPDATE = "investigations.update"
    INVESTIGATIONS_COMPLETE = "investigations.complete"
    INVESTIGATIONS_COLLABORATE = "investigations.collaborate"
    INVESTIGATIONS_EXPORT = "investigations.export"
    EVIDENCE_BOOKMARK = "evidence.bookmark"
    EVIDENCE_SNAPSHOT = "evidence.snapshot"
    EVIDENCE_ATTACHMENT_UPLOAD = "evidence.attachment.upload"
    EVIDENCE_ATTACHMENT_DOWNLOAD = "evidence.attachment.download"
    ENTITIES_VIEW = "entities.view"
    ENTITIES_GRAPH_VIEW = "entities.graph.view"
    API_KEYS_VIEW = "api_keys.view"
    API_KEYS_MANAGE = "api_keys.manage"
    SUBSCRIPTIONS_VIEW = "subscriptions.view"
    USAGE_VIEW = "usage.view"
    REPORTS_VIEW = "reports.view"
    REPORTS_EXPORT = "reports.export"
    ASSETS_VIEW = "assets.view"
    ASSETS_MANAGE = "assets.manage"
    NOTIFICATIONS_MANAGE = "notifications.manage"
    SETTINGS_VIEW = "settings.view"
    SETTINGS_MANAGE = "settings.manage"

    # Compatibility aliases for code migrated incrementally in this revision.
    USERS_READ = USERS_VIEW
    USERS_MANAGE = USERS_UPDATE
    ROLES_READ = ROLES_VIEW
    ROLES_MANAGE = ROLES_UPDATE
    ORGANIZATION_READ = ORGANIZATION_VIEW
    ORGANIZATION_MANAGE = ORGANIZATION_UPDATE
    ALERTS_READ = ALERTS_VIEW
    ALERTS_MANAGE = ALERTS_UPDATE
    INCIDENTS_READ = INCIDENTS_VIEW
    INCIDENTS_MANAGE = INCIDENTS_UPDATE
    DETECTIONS_READ = DETECTIONS_VIEW
    DETECTIONS_MANAGE = DETECTIONS_UPDATE
    SIGMA_READ = SIGMA_VIEW
    SIGMA_MANAGE = SIGMA_UPDATE
    PLAYBOOKS_READ = PLAYBOOKS_VIEW
    PLAYBOOKS_MANAGE = PLAYBOOKS_UPDATE
    SOAR_READ = SOAR_VIEW
    THREAT_INTEL_READ = THREAT_INTELLIGENCE_VIEW
    THREAT_INTEL_MANAGE = THREAT_INTELLIGENCE_MANAGE
    AUDIT_READ = AUDIT_VIEW
    AI_INVESTIGATE = TRIAGE_AI_USE
    ACCOUNT_DELETE = ORGANIZATION_DELETE


@dataclass(frozen=True)
class PermissionMetadata:
    identifier: str
    category: str
    description: str
    owner_only: bool = False


OWNER_ONLY_PERMISSIONS = frozenset({
    Permission.ORGANIZATION_SECURITY_MANAGE.value,
    Permission.ORGANIZATION_DELETE.value,
    Permission.ORGANIZATION_DELETE_CANCEL.value,
    Permission.ENCRYPTION_ROTATION_EXECUTE.value,
})

PERMISSION_CATALOG = {
    permission.value: PermissionMetadata(
        identifier=permission.value,
        category=permission.value.split(".", 1)[0].replace("_", " ").title(),
        description=permission.value.replace("_", " ").replace(".", ": ").capitalize(),
        owner_only=permission.value in OWNER_ONLY_PERMISSIONS,
    )
    for permission in Permission
}
ALL_PERMISSIONS = frozenset(PERMISSION_CATALOG)


def _select(*values: Permission) -> set[str]:
    return {value.value for value in values}


ROLE_PERMISSIONS = {
    OrganizationRole.OWNER: set(ALL_PERMISSIONS),
    OrganizationRole.ADMINISTRATOR: set(ALL_PERMISSIONS) - OWNER_ONLY_PERMISSIONS - {
        Permission.ROLES_DELETE.value,
        Permission.SOAR_APPROVE.value,
        Permission.AUDIT_RETENTION_MANAGE.value,
        Permission.AUDIT_LEGAL_HOLD_MANAGE.value,
        Permission.AUDIT_ARCHIVE_MANAGE.value,
        Permission.DATA_PROTECTION_MANAGE.value,
        Permission.DETECTIONS_APPROVE.value,
        Permission.DETECTIONS_PUBLISH.value,
        Permission.SIGMA_PUBLISH.value,
        Permission.TLP_OVERRIDE.value,
        Permission.THREAT_INTELLIGENCE_SOURCES_MANAGE.value,
        Permission.THREAT_INTELLIGENCE_RELIABILITY_MANAGE.value,
        Permission.TAXII_MANAGE.value,
        Permission.MISP_MANAGE.value,
        Permission.IOC_RESPONSE_APPROVE.value,
    },
    OrganizationRole.SOC_MANAGER: _select(
        Permission.USERS_VIEW, Permission.USERS_INVITE, Permission.USERS_UPDATE,
        Permission.ROLES_VIEW, Permission.ROLES_ASSIGN,
        Permission.ORGANIZATION_VIEW, Permission.ALERTS_VIEW, Permission.ALERTS_CREATE,
        Permission.ALERTS_UPDATE, Permission.ALERTS_ASSIGN, Permission.ALERTS_CLOSE,
        Permission.ALERTS_BULK_MANAGE, Permission.INCIDENTS_VIEW, Permission.INCIDENTS_CREATE,
        Permission.INCIDENTS_UPDATE, Permission.INCIDENTS_ASSIGN, Permission.INCIDENTS_CLOSE,
        Permission.DETECTIONS_VIEW, Permission.DETECTIONS_CREATE, Permission.DETECTIONS_UPDATE,
        Permission.DETECTIONS_ENABLE, Permission.DETECTIONS_REVIEW, Permission.DETECTIONS_APPROVE,
        Permission.DETECTIONS_PUBLISH, Permission.DETECTIONS_SIMULATE,
        Permission.DETECTIONS_VALIDATE, Permission.DETECTIONS_TEST, Permission.DETECTIONS_DISABLE,
        Permission.DETECTIONS_RETIRE, Permission.DETECTIONS_ROLLBACK, Permission.DETECTIONS_CLONE,
        Permission.DETECTIONS_IMPORT, Permission.DETECTIONS_EXPORT, Permission.DETECTIONS_METRICS_VIEW,
        Permission.DETECTIONS_RECOMMENDATIONS_MANAGE, Permission.DETECTIONS_EXCEPTIONS_VIEW,
        Permission.DETECTIONS_CONTENT_PACKS_VIEW, Permission.MITRE_COVERAGE_VIEW,
        Permission.MITRE_COVERAGE_EXPORT,
        Permission.DETECTIONS_EXCEPTIONS_MANAGE, Permission.DETECTIONS_MAINTENANCE_MANAGE,
        Permission.DETECTIONS_ANALYTICS_VIEW, Permission.DETECTIONS_CONTENT_PACK_MANAGE,
        Permission.SIGMA_VIEW, Permission.SIGMA_CREATE,
        Permission.SIGMA_UPDATE, Permission.SIGMA_ENABLE, Permission.PLAYBOOKS_VIEW,
        Permission.SIGMA_VALIDATE, Permission.SIGMA_IMPORT, Permission.SIGMA_EXPORT,
        Permission.SIGMA_PUBLISH,
        Permission.PLAYBOOKS_CREATE, Permission.PLAYBOOKS_UPDATE, Permission.PLAYBOOKS_PUBLISH,
        Permission.PLAYBOOKS_EXECUTE, Permission.PLAYBOOKS_APPROVE, Permission.SOAR_VIEW,
        Permission.SOAR_EXECUTE, Permission.THREAT_INTELLIGENCE_VIEW,
        Permission.THREAT_INTELLIGENCE_MANAGE, Permission.AUDIT_VIEW,
        Permission.IOC_VIEW, Permission.IOC_CREATE, Permission.IOC_UPDATE, Permission.IOC_REVIEW,
        Permission.IOC_ACTIVATE, Permission.IOC_EXPIRE, Permission.IOC_REVOKE, Permission.IOC_DELETE,
        Permission.IOC_MERGE, Permission.IOC_BULK_MANAGE, Permission.IOC_ENRICH, Permission.IOC_HUNT,
        Permission.IOC_SIGHTINGS_VIEW, Permission.IOC_SIGHTINGS_MANAGE,
        Permission.IOC_WATCHLISTS_VIEW, Permission.IOC_WATCHLISTS_MANAGE,
        Permission.IOC_ALLOWLISTS_VIEW, Permission.IOC_ALLOWLISTS_MANAGE,
        Permission.IOC_RELATIONSHIPS_VIEW, Permission.IOC_RELATIONSHIPS_MANAGE,
        Permission.IOC_IMPORT, Permission.IOC_EXPORT, Permission.IOC_REPORTS_VIEW,
        Permission.IOC_REPORTS_EXPORT, Permission.IOC_RESPONSE_RECOMMEND,
        Permission.IOC_REVIEW_ASSIGN, Permission.IOC_APPROVE,
        Permission.IOC_WATCHLIST_POLICIES_MANAGE, Permission.IOC_HUNTS_MANAGE,
        Permission.IOC_GRAPH_VIEW, Permission.IOC_DETECTION_GENERATE,
        Permission.THREAT_INTELLIGENCE_SOURCES_VIEW, Permission.THREAT_INTELLIGENCE_SOURCES_TEST,
        Permission.THREAT_INTELLIGENCE_SYNC, Permission.TAXII_SYNC, Permission.MISP_SYNC,
        Permission.STIX_IMPORT, Permission.STIX_EXPORT,
        Permission.AUDIT_INTEGRITY_VERIFY, Permission.AUDIT_LEGAL_HOLD_VIEW,
        Permission.TRIAGE_AI_USE, Permission.COLLECTORS_VIEW, Permission.USAGE_VIEW,
        Permission.COLLECTORS_ENROLL, Permission.COLLECTOR_CREDENTIALS_ROTATE,
        Permission.COLLECTOR_POLICIES_VIEW, Permission.COLLECTOR_POLICIES_MANAGE,
        Permission.COLLECTOR_GROUPS_MANAGE, Permission.TELEMETRY_VIEW,
        Permission.TELEMETRY_INGEST, Permission.TELEMETRY_IMPORT, Permission.TELEMETRY_REPLAY,
        Permission.DEAD_LETTER_VIEW, Permission.DEAD_LETTER_MANAGE,
        Permission.DATA_SOURCES_VIEW, Permission.DATA_SOURCES_MANAGE, Permission.INGESTION_METRICS_VIEW,
        Permission.SEARCH_EVENTS, Permission.SEARCH_ALERTS, Permission.SEARCH_INCIDENTS,
        Permission.SEARCH_ENTITIES, Permission.SEARCH_EXTENDED_RANGE,
        Permission.SEARCH_HISTORY_VIEW, Permission.SEARCH_HISTORY_MANAGE,
        Permission.SEARCH_SAVED_VIEW, Permission.SEARCH_SAVED_MANAGE, Permission.SEARCH_SAVED_SHARE,
        Permission.SEARCH_TEMPLATES_MANAGE, Permission.SEARCH_SCHEDULE_MANAGE, Permission.SEARCH_EXPORT,
        Permission.INVESTIGATIONS_VIEW, Permission.INVESTIGATIONS_CREATE, Permission.INVESTIGATIONS_UPDATE,
        Permission.INVESTIGATIONS_COMPLETE, Permission.INVESTIGATIONS_COLLABORATE, Permission.INVESTIGATIONS_EXPORT,
        Permission.EVIDENCE_BOOKMARK, Permission.EVIDENCE_SNAPSHOT,
        Permission.EVIDENCE_ATTACHMENT_UPLOAD, Permission.EVIDENCE_ATTACHMENT_DOWNLOAD,
        Permission.ENTITIES_VIEW, Permission.ENTITIES_GRAPH_VIEW,
        Permission.REPORTS_VIEW, Permission.REPORTS_EXPORT, Permission.ASSETS_VIEW,
        Permission.ASSETS_MANAGE, Permission.SETTINGS_VIEW,
    ),
    OrganizationRole.ANALYST: _select(
        Permission.ORGANIZATION_VIEW, Permission.ALERTS_VIEW, Permission.ALERTS_CREATE,
        Permission.ALERTS_UPDATE, Permission.INCIDENTS_VIEW, Permission.INCIDENTS_CREATE,
        Permission.INCIDENTS_UPDATE, Permission.INCIDENTS_ASSIGN,
        Permission.DETECTIONS_VIEW, Permission.DETECTIONS_CREATE, Permission.DETECTIONS_UPDATE,
        Permission.DETECTIONS_SIMULATE, Permission.DETECTIONS_ANALYTICS_VIEW,
        Permission.DETECTIONS_VALIDATE, Permission.DETECTIONS_TEST,
        Permission.DETECTIONS_METRICS_VIEW, Permission.DETECTIONS_EXCEPTIONS_VIEW,
        Permission.DETECTIONS_CONTENT_PACKS_VIEW, Permission.MITRE_COVERAGE_VIEW,
        Permission.SIGMA_VIEW, Permission.SIGMA_CREATE, Permission.SIGMA_VALIDATE,
        Permission.SIGMA_IMPORT, Permission.SIGMA_EXPORT, Permission.PLAYBOOKS_VIEW,
        Permission.PLAYBOOKS_EXECUTE, Permission.SOAR_VIEW,
        Permission.THREAT_INTELLIGENCE_VIEW, Permission.THREAT_INTELLIGENCE_MANAGE,
        Permission.IOC_VIEW, Permission.IOC_CREATE, Permission.IOC_UPDATE, Permission.IOC_REVIEW,
        Permission.IOC_ACTIVATE, Permission.IOC_EXPIRE, Permission.IOC_REVOKE,
        Permission.IOC_ENRICH, Permission.IOC_HUNT, Permission.IOC_SIGHTINGS_VIEW,
        Permission.IOC_SIGHTINGS_MANAGE, Permission.IOC_WATCHLISTS_VIEW,
        Permission.IOC_WATCHLISTS_MANAGE, Permission.IOC_ALLOWLISTS_VIEW,
        Permission.IOC_RELATIONSHIPS_VIEW, Permission.IOC_IMPORT, Permission.IOC_EXPORT,
        Permission.IOC_REPORTS_VIEW, Permission.IOC_RESPONSE_RECOMMEND,
        Permission.IOC_GRAPH_VIEW, Permission.IOC_DETECTION_GENERATE,
        Permission.THREAT_INTELLIGENCE_SOURCES_VIEW, Permission.THREAT_INTELLIGENCE_SOURCES_TEST,
        Permission.STIX_IMPORT, Permission.STIX_EXPORT,
        Permission.TRIAGE_AI_USE, Permission.COLLECTORS_VIEW, Permission.ASSETS_VIEW,
        Permission.TELEMETRY_VIEW, Permission.TELEMETRY_INGEST,
        Permission.DATA_SOURCES_VIEW, Permission.INGESTION_METRICS_VIEW,
        Permission.SEARCH_EVENTS, Permission.SEARCH_ALERTS, Permission.SEARCH_INCIDENTS,
        Permission.SEARCH_ENTITIES, Permission.SEARCH_HISTORY_VIEW, Permission.SEARCH_HISTORY_MANAGE,
        Permission.SEARCH_SAVED_VIEW, Permission.SEARCH_SAVED_MANAGE,
        Permission.INVESTIGATIONS_VIEW, Permission.INVESTIGATIONS_CREATE, Permission.INVESTIGATIONS_UPDATE,
        Permission.INVESTIGATIONS_COLLABORATE, Permission.EVIDENCE_BOOKMARK,
        Permission.ENTITIES_VIEW, Permission.ENTITIES_GRAPH_VIEW,
        Permission.REPORTS_VIEW, Permission.SETTINGS_VIEW,
    ),
    OrganizationRole.VIEWER: _select(
        Permission.ORGANIZATION_VIEW, Permission.ALERTS_VIEW, Permission.INCIDENTS_VIEW,
        Permission.DETECTIONS_VIEW, Permission.DETECTIONS_ANALYTICS_VIEW,
        Permission.DETECTIONS_METRICS_VIEW, Permission.DETECTIONS_EXCEPTIONS_VIEW,
        Permission.DETECTIONS_CONTENT_PACKS_VIEW, Permission.MITRE_COVERAGE_VIEW,
        Permission.SIGMA_VIEW, Permission.PLAYBOOKS_VIEW,
        Permission.SOAR_VIEW, Permission.THREAT_INTELLIGENCE_VIEW,
        Permission.IOC_VIEW, Permission.IOC_SIGHTINGS_VIEW, Permission.IOC_WATCHLISTS_VIEW,
        Permission.IOC_ALLOWLISTS_VIEW, Permission.IOC_RELATIONSHIPS_VIEW, Permission.IOC_REPORTS_VIEW,
        Permission.IOC_GRAPH_VIEW, Permission.THREAT_INTELLIGENCE_SOURCES_VIEW,
        Permission.COLLECTORS_VIEW, Permission.ASSETS_VIEW, Permission.REPORTS_VIEW,
        Permission.TELEMETRY_VIEW, Permission.DATA_SOURCES_VIEW, Permission.INGESTION_METRICS_VIEW,
        Permission.SEARCH_EVENTS, Permission.SEARCH_ALERTS, Permission.SEARCH_INCIDENTS,
        Permission.SEARCH_ENTITIES, Permission.SEARCH_HISTORY_VIEW, Permission.SEARCH_SAVED_VIEW,
        Permission.INVESTIGATIONS_VIEW, Permission.ENTITIES_VIEW, Permission.ENTITIES_GRAPH_VIEW,
        Permission.SETTINGS_VIEW,
    ),
}

LEGACY_PERMISSION_MAP = {
    "users.read": Permission.USERS_VIEW.value,
    "users.manage": Permission.USERS_UPDATE.value,
    "roles.read": Permission.ROLES_VIEW.value,
    "roles.manage": Permission.ROLES_UPDATE.value,
    "organization.read": Permission.ORGANIZATION_VIEW.value,
    "organization.manage": Permission.ORGANIZATION_UPDATE.value,
    "alerts.read": Permission.ALERTS_VIEW.value,
    "alerts.manage": Permission.ALERTS_UPDATE.value,
    "incidents.read": Permission.INCIDENTS_VIEW.value,
    "incidents.manage": Permission.INCIDENTS_UPDATE.value,
    "detections.read": Permission.DETECTIONS_VIEW.value,
    "detections.manage": Permission.DETECTIONS_UPDATE.value,
    "sigma.read": Permission.SIGMA_VIEW.value,
    "sigma.manage": Permission.SIGMA_UPDATE.value,
    "playbooks.read": Permission.PLAYBOOKS_VIEW.value,
    "playbooks.manage": Permission.PLAYBOOKS_UPDATE.value,
    "soar.read": Permission.SOAR_VIEW.value,
    "threat_intel.read": Permission.THREAT_INTELLIGENCE_VIEW.value,
    "threat_intel.manage": Permission.THREAT_INTELLIGENCE_MANAGE.value,
    "audit.read": Permission.AUDIT_VIEW.value,
    "ai.investigate": Permission.TRIAGE_AI_USE.value,
    "account.delete": Permission.ORGANIZATION_DELETE.value,
}


def active_membership(
    db: Session,
    user: User,
    tenant_id: str | None = None,
    *,
    allow_pending_deletion: bool = False,
) -> OrganizationMembership:
    selected_tenant = tenant_id or user.tenant_id
    membership = db.query(OrganizationMembership).filter(
        OrganizationMembership.user_id == user.id,
        OrganizationMembership.tenant_id == selected_tenant,
    ).first()
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "MEMBERSHIP_REQUIRED", "message": "Active organization membership is required"},
        )
    if not membership.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "MEMBERSHIP_DISABLED", "message": "Organization membership is disabled"},
        )
    allowed_statuses = (
        {OrganizationStatus.ACTIVE, OrganizationStatus.PENDING_DELETION}
        if allow_pending_deletion else
        {OrganizationStatus.ACTIVE}
    )
    if (
        not membership.tenant
        or membership.tenant.status not in allowed_statuses
        or (
            membership.tenant.status == OrganizationStatus.ACTIVE
            and not membership.tenant.is_active
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "ORGANIZATION_DISABLED", "message": "Organization is not active"},
        )
    return membership


def membership_permissions(
    db: Session,
    user: User,
    tenant_id: str | None = None,
    *,
    allow_pending_deletion: bool = False,
) -> set[str]:
    membership = active_membership(
        db, user, tenant_id, allow_pending_deletion=allow_pending_deletion
    )
    if membership.custom_role:
        return {
            LEGACY_PERMISSION_MAP.get(item, item)
            for item in (membership.custom_role.permissions or [])
            if LEGACY_PERMISSION_MAP.get(item, item) in ALL_PERMISSIONS
        }
    return set(ROLE_PERMISSIONS.get(membership.role, set()))


def _deny(db: Session, user: User, request: Request, permissions: set[str]) -> None:
    sensitive = any(
        suffix in permission
        for permission in permissions
        for suffix in (".delete", ".approve", ".manage", ".export", "roles.assign")
    )
    if sensitive:
        from src.services.audit_service import audit_service
        audit_service.record(
            db,
            action="permission_denied",
            user=user,
            tenant_id=user.tenant_id,
            resource_type="permission",
            ip_address=request.client.host if request.client else None,
            request_id=getattr(request.state, "request_id", None),
            status="failure",
            failure_reason="permission_denied",
            details={"required_permissions": sorted(permissions)},
        )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"error_code": "PERMISSION_DENIED", "message": "Permission denied"},
    )


def require_all_permissions(*permissions: Permission | str):
    required = {item.value if isinstance(item, Permission) else item for item in permissions}

    def checker(
        request: Request,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user),
    ) -> User:
        if not required.issubset(membership_permissions(db, current_user)):
            _deny(db, current_user, request, required)
        return current_user
    return checker


def require_any_permission(*permissions: Permission | str):
    required = {item.value if isinstance(item, Permission) else item for item in permissions}

    def checker(
        request: Request,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user),
    ) -> User:
        if not membership_permissions(db, current_user).intersection(required):
            _deny(db, current_user, request, required)
        return current_user
    return checker


def require_permission(permission: Permission | str):
    return require_all_permissions(permission)


def require_tenant_permission(
    permission: Permission | str,
    path_parameter: str = "organization_id",
    *,
    allow_pending_deletion: bool = False,
):
    required = permission.value if isinstance(permission, Permission) else permission

    def checker(
        request: Request,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user),
    ) -> User:
        tenant_id = request.path_params.get(path_parameter)
        if not tenant_id:
            raise HTTPException(
                status_code=400,
                detail={"error_code": "ORGANIZATION_CONTEXT_REQUIRED", "message": "Organization context is required"},
            )
        if tenant_id != current_user.tenant_id:
            if not allow_pending_deletion:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={"error_code": "RESOURCE_ACCESS_DENIED", "message": "Resource is not available"},
                )
            target_membership = active_membership(
                db, current_user, tenant_id, allow_pending_deletion=True
            )
            if target_membership.tenant.status != OrganizationStatus.PENDING_DELETION:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={"error_code": "RESOURCE_ACCESS_DENIED", "message": "Resource is not available"},
                )
        if required not in membership_permissions(
            db,
            current_user,
            tenant_id,
            allow_pending_deletion=allow_pending_deletion,
        ):
            _deny(db, current_user, request, {required})
        return current_user
    return checker
