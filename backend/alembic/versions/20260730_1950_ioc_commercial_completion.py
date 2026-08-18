"""IOC commercial completion and demo readiness.

Revision ID: 20260730_1950
Revises: 20260730_1900
"""
from alembic import op
import sqlalchemy as sa


revision = "20260730_1950"
down_revision = "20260730_1900"
branch_labels = None
depends_on = None


def _identity_columns():
    return (
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
    )


def _create_table_if_missing(name: str, *columns, **kwargs) -> None:
    if not sa.inspect(op.get_bind()).has_table(name):
        op.create_table(name, *columns, **kwargs)


def _create_index_if_missing(name: str, table: str, columns: list[str]) -> None:
    existing = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes(table)}
    if name not in existing:
        op.create_index(name, table, columns)


def upgrade() -> None:
    _create_table_if_missing(
        "threat_source_credentials",
        *_identity_columns(),
        sa.Column("provider", sa.String(30), nullable=False),
        sa.Column("name", sa.String(150), nullable=False),
        sa.Column("base_url", sa.String(2048)),
        sa.Column("encrypted_credentials", sa.Text(), nullable=False),
        sa.Column("encryption_key_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("credential_fingerprint", sa.String(64), nullable=False),
        sa.Column("safe_metadata", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="active"),
        sa.Column("tls_verify", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_tested_at", sa.DateTime(timezone=True)),
        sa.Column("last_successful_use_at", sa.DateTime(timezone=True)),
        sa.Column("last_rotated_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("updated_by", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "provider", "name", name="uq_threat_source_tenant_provider_name"),
    )
    _create_index_if_missing("ix_threat_source_tenant_provider_status", "threat_source_credentials", ["tenant_id", "provider", "status"])

    _create_table_if_missing(
        "threat_sync_configurations",
        *_identity_columns(),
        sa.Column("credential_id", sa.String(36), sa.ForeignKey("threat_source_credentials.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(20), nullable=False),
        sa.Column("name", sa.String(150), nullable=False),
        sa.Column("api_root", sa.String(2048)),
        sa.Column("collection_id", sa.String(255)),
        sa.Column("settings", sa.JSON(), nullable=False),
        sa.Column("safe_cursor", sa.JSON(), nullable=False),
        sa.Column("cursor_updated_at", sa.DateTime(timezone=True)),
        sa.Column("schedule_seconds", sa.Integer()),
        sa.Column("next_run_at", sa.DateTime(timezone=True)),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "provider", "name", name="uq_threat_sync_tenant_provider_name"),
    )
    _create_index_if_missing("ix_threat_sync_tenant_provider_enabled", "threat_sync_configurations", ["tenant_id", "provider", "enabled"])
    _create_index_if_missing("ix_threat_sync_cursor", "threat_sync_configurations", ["tenant_id", "provider", "cursor_updated_at"])

    _create_table_if_missing(
        "threat_sync_jobs",
        *_identity_columns(),
        sa.Column("configuration_id", sa.String(36), sa.ForeignKey("threat_sync_configurations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(20), nullable=False),
        sa.Column("direction", sa.String(20), nullable=False, server_default="pull"),
        sa.Column("status", sa.String(30), nullable=False, server_default="pending"),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("counts", sa.JSON(), nullable=False),
        sa.Column("failure_code", sa.String(80)),
        sa.Column("failure_details", sa.JSON(), nullable=False),
        sa.Column("cancellation_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("requested_by", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    _create_index_if_missing("ix_threat_sync_jobs_tenant_status", "threat_sync_jobs", ["tenant_id", "status", "created_at"])
    _create_index_if_missing("ix_threat_sync_jobs_configuration", "threat_sync_jobs", ["tenant_id", "configuration_id", "created_at"])

    _create_table_if_missing(
        "ioc_import_jobs",
        *_identity_columns(),
        sa.Column("format", sa.String(20), nullable=False),
        sa.Column("original_filename", sa.String(255), nullable=False),
        sa.Column("artifact_key", sa.String(1024), nullable=False),
        sa.Column("artifact_checksum", sa.String(64), nullable=False),
        sa.Column("encrypted_artifact", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("status", sa.String(30), nullable=False, server_default="uploaded"),
        sa.Column("dry_run", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("options", sa.JSON(), nullable=False),
        sa.Column("counts", sa.JSON(), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cancellation_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("error_code", sa.String(80)),
        sa.Column("requested_by", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    _create_index_if_missing("ix_ioc_import_jobs_tenant_status", "ioc_import_jobs", ["tenant_id", "status", "created_at"])
    _create_index_if_missing("ix_ioc_import_jobs_expires", "ioc_import_jobs", ["expires_at"])

    _create_table_if_missing(
        "ioc_import_row_results",
        *_identity_columns(),
        sa.Column("job_id", sa.String(36), sa.ForeignKey("ioc_import_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("row_number", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("ioc_id", sa.String(36), sa.ForeignKey("iocs.id", ondelete="SET NULL")),
        sa.Column("error_code", sa.String(80)),
        sa.Column("safe_details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("job_id", "row_number", name="uq_ioc_import_row"),
    )
    _create_index_if_missing("ix_ioc_import_rows_tenant_job_status", "ioc_import_row_results", ["tenant_id", "job_id", "status"])

    _create_table_if_missing(
        "ioc_bulk_action_jobs",
        *_identity_columns(),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="pending"),
        sa.Column("preview", sa.JSON(), nullable=False),
        sa.Column("request", sa.JSON(), nullable=False),
        sa.Column("results", sa.JSON(), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cancellation_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("requested_by", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    _create_index_if_missing("ix_ioc_bulk_jobs_tenant_status", "ioc_bulk_action_jobs", ["tenant_id", "status", "created_at"])

    _create_table_if_missing(
        "ioc_review_assignments",
        *_identity_columns(),
        sa.Column("ioc_id", sa.String(36), sa.ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("reviewer_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("assigned_by", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("status", sa.String(30), nullable=False, server_default="assigned"),
        sa.Column("due_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    _create_index_if_missing("ix_ioc_review_tenant_reviewer_status", "ioc_review_assignments", ["tenant_id", "reviewer_id", "status"])
    _create_index_if_missing("ix_ioc_review_tenant_due", "ioc_review_assignments", ["tenant_id", "due_at"])

    _create_table_if_missing(
        "ioc_review_history",
        *_identity_columns(),
        sa.Column("ioc_id", sa.String(36), sa.ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("assignment_id", sa.String(36), sa.ForeignKey("ioc_review_assignments.id", ondelete="SET NULL")),
        sa.Column("actor_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("comment", sa.Text()),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("before_values", sa.JSON(), nullable=False),
        sa.Column("after_values", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    _create_index_if_missing("ix_ioc_review_history_tenant_ioc", "ioc_review_history", ["tenant_id", "ioc_id", "created_at"])

    _create_table_if_missing(
        "ioc_response_recommendations",
        *_identity_columns(),
        sa.Column("ioc_id", sa.String(36), sa.ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("target_connector_type", sa.String(80)),
        sa.Column("safe_context", sa.JSON(), nullable=False),
        sa.Column("request_fingerprint", sa.String(64), nullable=False),
        sa.Column("requester_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("approval_id", sa.String(36), sa.ForeignKey("sensitive_action_approvals.id", ondelete="SET NULL")),
        sa.Column("status", sa.String(30), nullable=False, server_default="pending_approval"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "request_fingerprint", name="uq_ioc_response_fingerprint"),
    )
    _create_index_if_missing("ix_ioc_response_tenant_status", "ioc_response_recommendations", ["tenant_id", "status", "expires_at"])

    _create_table_if_missing(
        "ioc_notification_states",
        *_identity_columns(),
        sa.Column("ioc_id", sa.String(36), sa.ForeignKey("iocs.id", ondelete="CASCADE")),
        sa.Column("watchlist_id", sa.String(36), sa.ForeignKey("ioc_watchlists.id", ondelete="CASCADE")),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("deduplication_key", sa.String(64), nullable=False),
        sa.Column("delivery_status", sa.String(30), nullable=False, server_default="pending"),
        sa.Column("recipient_scope", sa.JSON(), nullable=False),
        sa.Column("cooldown_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_delivered_at", sa.DateTime(timezone=True)),
        sa.Column("delivery_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("tenant_id", "deduplication_key", name="uq_ioc_notification_dedup"),
    )
    _create_index_if_missing("ix_ioc_notification_tenant_cooldown", "ioc_notification_states", ["tenant_id", "cooldown_until"])

    _create_table_if_missing(
        "ioc_report_jobs",
        *_identity_columns(),
        sa.Column("report_type", sa.String(80), nullable=False),
        sa.Column("format", sa.String(20), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="pending"),
        sa.Column("filters", sa.JSON(), nullable=False),
        sa.Column("artifact_key", sa.String(1024)),
        sa.Column("checksum", sa.String(64)),
        sa.Column("manifest", sa.JSON(), nullable=False),
        sa.Column("error_code", sa.String(80)),
        sa.Column("requested_by", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    _create_index_if_missing("ix_ioc_report_tenant_status", "ioc_report_jobs", ["tenant_id", "status", "created_at"])
    _create_index_if_missing("ix_ioc_report_expires", "ioc_report_jobs", ["expires_at"])


def downgrade() -> None:
    for table in (
        "ioc_report_jobs",
        "ioc_notification_states",
        "ioc_response_recommendations",
        "ioc_review_history",
        "ioc_review_assignments",
        "ioc_bulk_action_jobs",
        "ioc_import_row_results",
        "ioc_import_jobs",
        "threat_sync_jobs",
        "threat_sync_configurations",
        "threat_source_credentials",
    ):
        op.drop_table(table)
