"""batch38 enterprise indexes

Revision ID: 20260703_1400
Revises: 20260703_1300
Create Date: 2026-07-03 14:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260703_1400"
down_revision: Union[str, None] = "20260703_1300"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _indexes(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table_name not in _tables():
        return set()
    return {index["name"] for index in inspector.get_indexes(table_name)}


def _create_index_if_missing(name: str, table: str, columns: list[str], unique: bool = False) -> None:
    if table in _tables() and name not in _indexes(table):
        op.create_index(name, table, columns, unique=unique)


def _drop_index_if_present(name: str, table: str) -> None:
    if table in _tables() and name in _indexes(table):
        op.drop_index(name, table_name=table)


INDEXES: tuple[tuple[str, str, list[str], bool], ...] = (
    ("ix_log_sources_tenant_status", "log_sources", ["tenant_id", "status"], False),
    ("ix_log_sources_tenant_last_seen", "log_sources", ["tenant_id", "last_seen"], False),
    ("ix_log_sources_tenant_created_at", "log_sources", ["tenant_id", "created_at"], False),
    ("ix_collectors_log_source_id", "collectors", ["log_source_id"], False),
    ("ix_users_tenant_role_active", "users", ["tenant_id", "role", "is_active"], False),
    ("ix_users_tenant_created_at", "users", ["tenant_id", "created_at"], False),
    ("ix_users_locked_until", "users", ["locked_until"], False),
    ("ix_refresh_tokens_user_revoked_expires", "refresh_tokens", ["user_id", "revoked_at", "expires_at"], False),
    ("ix_refresh_tokens_tenant_created_at", "refresh_tokens", ["tenant_id", "created_at"], False),
    ("ix_alert_sources_tenant_name", "alert_sources", ["tenant_id", "name"], False),
    ("ix_alert_sources_tenant_enabled", "alert_sources", ["tenant_id", "enabled"], False),
    ("ix_alerts_source_id", "alerts", ["source_id"], False),
    ("ix_alerts_detection_rule_id", "alerts", ["detection_rule_id"], False),
    ("ix_alerts_tenant_status_created_at", "alerts", ["tenant_id", "status", "created_at"], False),
    ("ix_alerts_tenant_severity_created_at", "alerts", ["tenant_id", "severity", "created_at"], False),
    ("ix_incidents_assigned_to", "incidents", ["assigned_to"], False),
    ("ix_incidents_tenant_priority", "incidents", ["tenant_id", "priority"], False),
    ("ix_incidents_tenant_updated_at", "incidents", ["tenant_id", "updated_at"], False),
    ("ix_incidents_tenant_status_updated_at", "incidents", ["tenant_id", "status", "updated_at"], False),
    ("ix_incident_alerts_incident_id", "incident_alerts", ["incident_id"], False),
    ("ix_incident_alerts_alert_id", "incident_alerts", ["alert_id"], False),
    ("ix_incident_alerts_incident_alert", "incident_alerts", ["incident_id", "alert_id"], False),
    ("ix_incident_iocs_tenant_incident", "incident_iocs", ["tenant_id", "incident_id"], False),
    ("ix_incident_iocs_tenant_ioc", "incident_iocs", ["tenant_id", "ioc_id"], False),
    ("ix_incident_iocs_unique_link", "incident_iocs", ["tenant_id", "incident_id", "ioc_id"], False),
    ("ix_investigation_notes_incident_created_at", "investigation_notes", ["incident_id", "created_at"], False),
    ("ix_investigation_notes_user_created_at", "investigation_notes", ["user_id", "created_at"], False),
    ("ix_incident_evidence_incident_created_at", "incident_evidence", ["incident_id", "created_at"], False),
    ("ix_incident_evidence_user_created_at", "incident_evidence", ["user_id", "created_at"], False),
    ("ix_feedback_tenant_incident", "feedback", ["tenant_id", "incident_id"], False),
    ("ix_feedback_user_created_at", "feedback", ["user_id", "created_at"], False),
    ("ix_feedback_tenant_classification", "feedback", ["tenant_id", "classification"], False),
    ("ix_threat_intel_cache_indicator_type_source", "threat_intel_cache", ["indicator", "indicator_type", "source"], False),
    ("ix_threat_intel_cache_expires_at", "threat_intel_cache", ["expires_at"], False),
    ("ix_threat_intel_tenant_indicator", "threat_intel", ["tenant_id", "indicator"], False),
    ("ix_threat_intel_incident_id", "threat_intel", ["incident_id"], False),
    ("ix_threat_intel_tenant_created_at", "threat_intel", ["tenant_id", "created_at"], False),
    ("ix_iocs_tenant_type_value", "iocs", ["tenant_id", "type", "value"], False),
    ("ix_iocs_tenant_active_created_at", "iocs", ["tenant_id", "is_active", "created_at"], False),
    ("ix_iocs_created_by", "iocs", ["created_by"], False),
    ("ix_ioc_enrichments_ioc_provider_created_at", "ioc_enrichments", ["ioc_id", "provider", "created_at"], False),
    ("ix_detection_rules_tenant_enabled", "detection_rules", ["tenant_id", "enabled"], False),
    ("ix_detection_rules_tenant_event_type", "detection_rules", ["tenant_id", "event_type"], False),
    ("ix_detection_rules_created_by", "detection_rules", ["created_by"], False),
    ("ix_incident_comments_tenant_incident_created_at", "incident_comments", ["tenant_id", "incident_id", "created_at"], False),
    ("ix_incident_comments_user_created_at", "incident_comments", ["user_id", "created_at"], False),
    ("ix_notifications_user_read_created_at", "notifications", ["user_id", "is_read", "created_at"], False),
    ("ix_notifications_tenant_created_at", "notifications", ["tenant_id", "created_at"], False),
    ("ix_security_events_tenant_timestamp", "security_events", ["tenant_id", "timestamp"], False),
    ("ix_security_events_tenant_processed_created_at", "security_events", ["tenant_id", "processed", "created_at"], False),
    ("ix_assets_tenant_hostname", "assets", ["tenant_id", "hostname"], False),
    ("ix_assets_tenant_ip_address", "assets", ["tenant_id", "ip_address"], False),
    ("ix_assets_tenant_criticality", "assets", ["tenant_id", "criticality"], False),
    ("ix_assets_tenant_last_seen", "assets", ["tenant_id", "last_seen"], False),
    ("ix_response_actions_tenant_incident_created_at", "response_actions", ["tenant_id", "incident_id", "created_at"], False),
    ("ix_response_actions_status", "response_actions", ["status"], False),
    ("ix_response_actions_executed_by", "response_actions", ["executed_by"], False),
    ("ix_detection_matches_tenant_rule_created_at", "detection_matches", ["tenant_id", "rule_id", "created_at"], False),
    ("ix_detection_matches_tenant_event", "detection_matches", ["tenant_id", "event_id"], False),
    ("ix_playbooks_tenant_status", "playbooks", ["tenant_id", "status"], False),
    ("ix_playbooks_created_by", "playbooks", ["created_by"], False),
    ("ix_playbook_steps_playbook_order", "playbook_steps", ["playbook_id", "order"], False),
    ("ix_playbook_executions_tenant_status_created_at", "playbook_executions", ["tenant_id", "status", "created_at"], False),
    ("ix_playbook_executions_incident_id", "playbook_executions", ["incident_id"], False),
    ("ix_playbook_executions_playbook_id", "playbook_executions", ["playbook_id"], False),
    ("ix_playbook_executions_triggered_by", "playbook_executions", ["triggered_by"], False),
    ("ix_mitre_technique_impacts_technique_id", "mitre_technique_impacts", ["technique_id"], False),
    ("ix_audit_logs_tenant_action_created_at", "audit_logs", ["tenant_id", "action", "created_at"], False),
    ("ix_audit_logs_resource", "audit_logs", ["resource_type", "resource_id"], False),
)


def upgrade() -> None:
    for name, table, columns, unique in INDEXES:
        _create_index_if_missing(name, table, columns, unique=unique)


def downgrade() -> None:
    for name, table, _columns, _unique in reversed(INDEXES):
        _drop_index_if_present(name, table)
