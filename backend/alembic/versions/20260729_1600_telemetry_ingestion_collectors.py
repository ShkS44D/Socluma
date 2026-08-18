"""Telemetry ingestion, collector enrollment, health, and durable processing.

Revision ID: 20260729_1600
Revises: 20260729_1500
"""
from alembic import op
import sqlalchemy as sa

revision = "20260729_1600"
down_revision = "20260729_1500"
branch_labels = None
depends_on = None


def _create_table_if_missing(name: str, *columns, **kwargs) -> None:
    """Support databases where an older ORM startup created newer tables."""
    if not sa.inspect(op.get_bind()).has_table(name):
        op.create_table(name, *columns, **kwargs)


def upgrade() -> None:
    _create_table_if_missing(
        "collector_policies",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(150), nullable=False), sa.Column("description", sa.Text()), sa.Column("active_version", sa.Integer()),
        sa.Column("created_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("tenant_id", "name", name="uq_collector_policies_tenant_name"),
    )
    _create_table_if_missing(
        "collector_groups",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(120), nullable=False), sa.Column("normalized_name", sa.String(120), nullable=False),
        sa.Column("description", sa.Text()), sa.Column("policy_id", sa.String(36), sa.ForeignKey("collector_policies.id", ondelete="SET NULL")),
        sa.Column("platform_filter", sa.String(50)), sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("tenant_id", "normalized_name", name="uq_collector_groups_tenant_name"),
    )
    _create_table_if_missing(
        "collector_policy_versions",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("policy_id", sa.String(36), sa.ForeignKey("collector_policies.id", ondelete="CASCADE"), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False), sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("configuration", sa.JSON(), nullable=False), sa.Column("checksum", sa.String(64), nullable=False),
        sa.Column("created_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("policy_id", "version", name="uq_collector_policy_version"),
    )
    collector_columns = [
        sa.Column("credential_expires_at", sa.DateTime(timezone=True)), sa.Column("credential_rotated_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)), sa.Column("revoked_reason", sa.String(255)),
        sa.Column("group_id", sa.String(36), sa.ForeignKey("collector_groups.id", name="fk_collectors_group_id", ondelete="SET NULL")),
        sa.Column("policy_version_id", sa.String(36), sa.ForeignKey("collector_policy_versions.id", name="fk_collectors_policy_version_id", ondelete="SET NULL")),
        sa.Column("platform", sa.String(50)), sa.Column("os_version", sa.String(150)), sa.Column("collector_version", sa.String(50)),
        sa.Column("architecture", sa.String(50)), sa.Column("health_status", sa.String(30), nullable=False, server_default="offline"),
        sa.Column("last_ingestion_at", sa.DateTime(timezone=True)), sa.Column("last_failed_ingestion_at", sa.DateTime(timezone=True)),
        sa.Column("last_authenticated_at", sa.DateTime(timezone=True)), sa.Column("queue_depth", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("spool_size_bytes", sa.BigInteger(), nullable=False, server_default="0"), sa.Column("dropped_event_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("events_collected", sa.BigInteger(), nullable=False, server_default="0"), sa.Column("events_submitted", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("events_accepted", sa.BigInteger(), nullable=False, server_default="0"), sa.Column("events_rejected", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("retry_count", sa.BigInteger(), nullable=False, server_default="0"), sa.Column("cpu_percent", sa.Float()), sa.Column("memory_percent", sa.Float()),
        sa.Column("disk_percent", sa.Float()), sa.Column("applied_policy_version", sa.Integer()), sa.Column("checkpoint_status", sa.String(30)),
        sa.Column("uptime_seconds", sa.BigInteger()), sa.Column("service_status", sa.String(30)),
    ]
    existing_collector_columns = {
        column["name"] for column in sa.inspect(op.get_bind()).get_columns("collectors")
    }
    with op.batch_alter_table("collectors") as batch:
        for column in collector_columns:
            if column.name not in existing_collector_columns:
                batch.add_column(column)
    _create_table_if_missing(
        "data_sources",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector_id", sa.String(36), sa.ForeignKey("collectors.id", ondelete="SET NULL")), sa.Column("source_key", sa.String(150), nullable=False),
        sa.Column("name", sa.String(255), nullable=False), sa.Column("source_type", sa.String(50), nullable=False), sa.Column("vendor", sa.String(100)),
        sa.Column("product", sa.String(100)), sa.Column("parser_name", sa.String(100), nullable=False, server_default="json"),
        sa.Column("transport", sa.String(30), nullable=False, server_default="https"), sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("minimum_quality_score", sa.Integer(), nullable=False, server_default="0"), sa.Column("last_event_at", sa.DateTime(timezone=True)),
        sa.Column("last_received_at", sa.DateTime(timezone=True)), sa.Column("last_successful_parse_at", sa.DateTime(timezone=True)),
        sa.Column("last_failure_at", sa.DateTime(timezone=True)), sa.Column("accepted_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("rejected_count", sa.BigInteger(), nullable=False, server_default="0"), sa.Column("duplicate_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("quality_score_total", sa.BigInteger(), nullable=False, server_default="0"), sa.Column("events_per_minute", sa.Float(), nullable=False, server_default="0"),
        sa.Column("ingestion_lag_seconds", sa.Float()), sa.Column("health_status", sa.String(30), nullable=False, server_default="unknown"),
        sa.Column("retention_class", sa.String(50), nullable=False, server_default="telemetry"), sa.Column("safe_config", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("tenant_id", "source_key", name="uq_data_sources_tenant_key"),
    )
    _create_table_if_missing(
        "ingestion_batches",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector_id", sa.String(36), sa.ForeignKey("collectors.id", ondelete="SET NULL")), sa.Column("actor_key", sa.String(100), nullable=False),
        sa.Column("batch_key", sa.String(100), nullable=False), sa.Column("request_fingerprint", sa.String(64), nullable=False),
        sa.Column("state", sa.String(30), nullable=False, server_default="accepted"), sa.Column("submitted_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("accepted_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("duplicate_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rejected_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("receipt", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("tenant_id", "actor_key", "batch_key", name="uq_ingestion_batch_actor_key"),
    )
    event_columns = [
        sa.Column("collector_id", sa.String(36), sa.ForeignKey("collectors.id", name="fk_security_events_collector_id", ondelete="SET NULL")),
        sa.Column("data_source_id", sa.String(36), sa.ForeignKey("data_sources.id", name="fk_security_events_data_source_id", ondelete="SET NULL")),
        sa.Column("batch_id", sa.String(36), sa.ForeignKey("ingestion_batches.id", name="fk_security_events_batch_id", ondelete="SET NULL")),
        sa.Column("source_event_id", sa.String(255)), sa.Column("idempotency_key", sa.String(255)), sa.Column("content_fingerprint", sa.String(64)),
        sa.Column("source_type", sa.String(80)), sa.Column("vendor", sa.String(100)), sa.Column("product", sa.String(100)),
        sa.Column("parser_name", sa.String(100)), sa.Column("parser_version", sa.String(30)),
        sa.Column("schema_version", sa.String(30), nullable=False, server_default="1.0"), sa.Column("event_category", sa.String(100)),
        sa.Column("event_class", sa.String(100)), sa.Column("original_offset", sa.String(10)),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("processed_at", sa.DateTime(timezone=True)),
        sa.Column("processing_status", sa.String(30), nullable=False, server_default="accepted"),
        sa.Column("data_quality_score", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("data_quality_reasons", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("normalization_warnings", sa.JSON(), nullable=False, server_default="[]"),
    ]
    security_inspector = sa.inspect(op.get_bind())
    existing_event_columns = {
        column["name"] for column in security_inspector.get_columns("security_events")
    }
    existing_event_constraints = {
        constraint["name"]
        for constraint in security_inspector.get_unique_constraints("security_events")
        if constraint.get("name")
    }
    with op.batch_alter_table("security_events") as batch:
        for column in event_columns:
            if column.name not in existing_event_columns:
                batch.add_column(column)
        if "uq_security_event_source_event" not in existing_event_constraints:
            batch.create_unique_constraint("uq_security_event_source_event", ["tenant_id", "data_source_id", "source_event_id"])
        if "uq_security_event_idempotency" not in existing_event_constraints:
            batch.create_unique_constraint("uq_security_event_idempotency", ["tenant_id", "data_source_id", "idempotency_key"])
        if "uq_security_event_fingerprint" not in existing_event_constraints:
            batch.create_unique_constraint("uq_security_event_fingerprint", ["tenant_id", "data_source_id", "content_fingerprint"])
    _create_table_if_missing(
        "collector_enrollment_tokens",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(255), nullable=False, unique=True), sa.Column("name", sa.String(150), nullable=False),
        sa.Column("platform", sa.String(50)), sa.Column("group_id", sa.String(36), sa.ForeignKey("collector_groups.id", ondelete="SET NULL")),
        sa.Column("max_uses", sa.Integer(), nullable=False, server_default="1"), sa.Column("used_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    _create_table_if_missing(
        "collector_credentials",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector_id", sa.String(36), sa.ForeignKey("collectors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(255), nullable=False), sa.Column("lookup_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("scopes", sa.JSON(), nullable=False, server_default="[]"), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("overlap_until", sa.DateTime(timezone=True)), sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    _create_table_if_missing(
        "collector_heartbeats",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector_id", sa.String(36), sa.ForeignKey("collectors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("health_status", sa.String(30), nullable=False), sa.Column("safe_metrics", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    _create_table_if_missing(
        "collector_checkpoints",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector_id", sa.String(36), sa.ForeignKey("collectors.id", ondelete="CASCADE"), nullable=False), sa.Column("source_key", sa.String(200), nullable=False),
        sa.Column("checkpoint_version", sa.Integer(), nullable=False, server_default="1"), sa.Column("safe_state", sa.JSON(), nullable=False),
        sa.Column("last_acknowledged_batch", sa.String(36)), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("collector_id", "source_key", name="uq_collector_checkpoint_source"),
    )
    _create_table_if_missing(
        "telemetry_failures",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector_id", sa.String(36), sa.ForeignKey("collectors.id", ondelete="SET NULL")),
        sa.Column("data_source_id", sa.String(36), sa.ForeignKey("data_sources.id", ondelete="SET NULL")),
        sa.Column("event_id", sa.String(36), sa.ForeignKey("security_events.id", ondelete="SET NULL")),
        sa.Column("batch_id", sa.String(36), sa.ForeignKey("ingestion_batches.id", ondelete="SET NULL")),
        sa.Column("stage", sa.String(50), nullable=False), sa.Column("error_code", sa.String(80), nullable=False), sa.Column("safe_error", sa.Text(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False, server_default="{}"), sa.Column("state", sa.String(30), nullable=False, server_default="retry"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"), sa.Column("next_retry_at", sa.DateTime(timezone=True)),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True)), sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    _create_table_if_missing(
        "ingestion_replay_nonces",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector_id", sa.String(36), sa.ForeignKey("collectors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("nonce", sa.String(100), nullable=False), sa.Column("request_fingerprint", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("collector_id", "nonce", name="uq_ingestion_replay_nonce"),
    )
    _create_table_if_missing(
        "telemetry_import_jobs",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False), sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("format", sa.String(20), nullable=False), sa.Column("state", sa.String(30), nullable=False, server_default="queued"),
        sa.Column("submitted_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("accepted_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duplicate_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("rejected_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("safe_error", sa.Text()), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("completed_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    for table in ("telemetry_import_jobs", "ingestion_replay_nonces", "telemetry_failures", "collector_checkpoints", "collector_heartbeats", "collector_credentials", "collector_enrollment_tokens"):
        op.drop_table(table)
    with op.batch_alter_table("security_events") as batch:
        for name in ("uq_security_event_fingerprint", "uq_security_event_idempotency", "uq_security_event_source_event"):
            batch.drop_constraint(name, type_="unique")
        for name in ("normalization_warnings", "data_quality_reasons", "data_quality_score", "processing_status", "processed_at", "received_at", "original_offset", "event_class", "event_category", "schema_version", "parser_version", "parser_name", "product", "vendor", "source_type", "content_fingerprint", "idempotency_key", "source_event_id", "batch_id", "data_source_id", "collector_id"):
            batch.drop_column(name)
    op.drop_table("ingestion_batches")
    op.drop_table("data_sources")
    with op.batch_alter_table("collectors") as batch:
        for name in ("service_status", "uptime_seconds", "checkpoint_status", "applied_policy_version", "disk_percent", "memory_percent", "cpu_percent", "retry_count", "events_rejected", "events_accepted", "events_submitted", "events_collected", "dropped_event_count", "spool_size_bytes", "queue_depth", "last_authenticated_at", "last_failed_ingestion_at", "last_ingestion_at", "health_status", "architecture", "collector_version", "os_version", "platform", "policy_version_id", "group_id", "revoked_reason", "revoked_at", "credential_rotated_at", "credential_expires_at"):
            batch.drop_column(name)
    op.drop_table("collector_policy_versions")
    op.drop_table("collector_groups")
    op.drop_table("collector_policies")
