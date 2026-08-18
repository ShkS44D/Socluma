"""Audit integrity, retention, legal holds, exports, and encryption versions.

Revision ID: 20260729_1500
Revises: 20260729_1400
"""
from __future__ import annotations

import hashlib

from alembic import op
import sqlalchemy as sa


revision = "20260729_1500"
down_revision = "20260729_1400"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("mfa_secret_key_version", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("mfa_pending_secret_key_version", sa.Integer(), nullable=True))
    bind.execute(sa.text(
        "UPDATE users SET mfa_secret_key_version = 1 WHERE mfa_secret_encrypted IS NOT NULL"
    ))
    bind.execute(sa.text(
        "UPDATE users SET mfa_pending_secret_key_version = 1 WHERE mfa_pending_secret_encrypted IS NOT NULL"
    ))

    with op.batch_alter_table("connector_credentials") as batch:
        batch.add_column(sa.Column("encryption_key_version", sa.Integer(), nullable=False, server_default="1"))

    columns = (
        sa.Column("actor_membership_id", sa.String(36), nullable=True),
        sa.Column("actor_session_id", sa.String(36), nullable=True),
        sa.Column("actor_type", sa.String(32), nullable=False, server_default="user"),
        sa.Column("category", sa.String(50), nullable=False, server_default="system"),
        sa.Column("severity", sa.String(20), nullable=False, server_default="info"),
        sa.Column("parent_resource_type", sa.String(100), nullable=True),
        sa.Column("parent_resource_id", sa.String(36), nullable=True),
        sa.Column("correlation_id", sa.String(128), nullable=True),
        sa.Column("approval_request_id", sa.String(36), nullable=True),
        sa.Column("before_values", sa.JSON(), nullable=True),
        sa.Column("after_values", sa.JSON(), nullable=True),
        sa.Column("event_source", sa.String(50), nullable=False, server_default="application"),
        sa.Column("retention_class", sa.String(50), nullable=False, server_default="administrative"),
        sa.Column("data_classification", sa.String(20), nullable=False, server_default="confidential"),
        sa.Column("sequence_number", sa.BigInteger(), nullable=True),
        sa.Column("previous_event_hash", sa.String(64), nullable=True),
        sa.Column("event_hash", sa.String(64), nullable=True),
        sa.Column("hash_algorithm_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("integrity_key_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
    )
    with op.batch_alter_table("audit_logs") as batch:
        for column in columns:
            batch.add_column(column)

    # Legacy rows use a deterministic, unkeyed compatibility chain. New rows use
    # HMAC-SHA256. No runtime integrity or encryption key is needed by migration.
    tenant_rows = bind.execute(sa.text(
        "SELECT DISTINCT tenant_id FROM audit_logs WHERE tenant_id IS NOT NULL ORDER BY tenant_id"
    )).scalars().all()
    chain_states: list[dict[str, object]] = []
    for tenant_id in tenant_rows:
        previous = None
        sequence = 0
        rows = bind.execute(sa.text(
            "SELECT id FROM audit_logs WHERE tenant_id = :tenant_id "
            "ORDER BY created_at ASC, id ASC"
        ), {"tenant_id": tenant_id}).mappings().all()
        for row in rows:
            sequence += 1
            material = f"{previous or ''}|{row['id']}|{tenant_id}|{sequence}"
            event_hash = hashlib.sha256(material.encode()).hexdigest()
            bind.execute(sa.text(
                "UPDATE audit_logs SET sequence_number=:sequence, previous_event_hash=:previous, "
                "event_hash=:event_hash, hash_algorithm_version=0 WHERE id=:id"
            ), {"sequence": sequence, "previous": previous, "event_hash": event_hash, "id": row["id"]})
            previous = event_hash
        chain_states.append({"tenant_id": tenant_id, "last_sequence": sequence, "last_event_hash": previous})

    with op.batch_alter_table("audit_logs") as batch:
        batch.create_foreign_key("fk_audit_actor_membership", "organization_memberships", ["actor_membership_id"], ["id"], ondelete="SET NULL")
        batch.create_foreign_key("fk_audit_actor_session", "auth_sessions", ["actor_session_id"], ["id"], ondelete="SET NULL")
        batch.create_unique_constraint("uq_audit_logs_tenant_sequence", ["tenant_id", "sequence_number"])
        batch.create_unique_constraint("uq_audit_logs_tenant_idempotency", ["tenant_id", "idempotency_key"])
    for name, fields in (
        ("ix_audit_logs_tenant_category_result", ["tenant_id", "category", "status"]),
        ("ix_audit_logs_tenant_actor_created", ["tenant_id", "actor_type", "user_id", "created_at"]),
        ("ix_audit_logs_retention_class", ["retention_class"]),
        ("ix_audit_logs_sequence", ["tenant_id", "sequence_number"]),
        ("ix_audit_logs_correlation_id", ["correlation_id"]),
    ):
        op.create_index(name, "audit_logs", fields)

    op.create_table(
        "audit_chain_states",
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("last_sequence", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_event_hash", sa.String(64), nullable=True),
        sa.Column("first_retained_sequence", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("first_retained_previous_hash", sa.String(64), nullable=True),
        sa.Column("key_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    for state in chain_states:
        bind.execute(sa.text(
            "INSERT INTO audit_chain_states "
            "(tenant_id,last_sequence,last_event_hash,first_retained_sequence,key_version) "
            "VALUES (:tenant_id,:last_sequence,:last_event_hash,1,1)"
        ), state)

    op.create_table(
        "audit_retention_policies",
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("default_retention_days", sa.Integer(), nullable=False, server_default="365"),
        sa.Column("security_retention_days", sa.Integer(), nullable=False, server_default="730"),
        sa.Column("administrative_retention_days", sa.Integer(), nullable=False, server_default="365"),
        sa.Column("authentication_retention_days", sa.Integer(), nullable=False, server_default="365"),
        sa.Column("export_retention_days", sa.Integer(), nullable=False, server_default="365"),
        sa.Column("archive_before_purge", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("archive_retention_days", sa.Integer(), nullable=False, server_default="2555"),
        sa.Column("updated_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "audit_legal_holds",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(150), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("created_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("released_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("start_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("end_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("category_filters", sa.JSON(), nullable=False),
        sa.Column("resource_filters", sa.JSON(), nullable=False),
        sa.Column("safe_metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_audit_legal_holds_tenant_id", "audit_legal_holds", ["tenant_id"])
    op.create_index("ix_audit_legal_holds_tenant_status", "audit_legal_holds", ["tenant_id", "status"])
    op.create_index("ix_audit_legal_holds_dates", "audit_legal_holds", ["start_at", "end_at"])

    op.create_table(
        "audit_archive_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("requested_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("date_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("date_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("records_considered", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_archived", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_purged", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_held", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("artifact_key", sa.String(255), nullable=True),
        sa.Column("manifest_checksum", sa.String(64), nullable=True),
        sa.Column("error_code", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_audit_archive_jobs_tenant_status", "audit_archive_jobs", ["tenant_id", "status"])
    op.create_index("ix_audit_archive_jobs_created", "audit_archive_jobs", ["created_at"])

    op.create_table(
        "audit_export_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("requested_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("format", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("filters", sa.JSON(), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("artifact_key", sa.String(255), nullable=True),
        sa.Column("checksum", sa.String(64), nullable=True),
        sa.Column("download_token_hash", sa.String(64), nullable=True),
        sa.Column("error_code", sa.String(100), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_audit_export_jobs_tenant_status", "audit_export_jobs", ["tenant_id", "status"])
    op.create_index("ix_audit_export_jobs_expiration", "audit_export_jobs", ["expires_at"])


def downgrade() -> None:
    op.drop_table("audit_export_jobs")
    op.drop_table("audit_archive_jobs")
    op.drop_table("audit_legal_holds")
    op.drop_table("audit_retention_policies")
    op.drop_table("audit_chain_states")
    for name in (
        "ix_audit_logs_correlation_id", "ix_audit_logs_sequence", "ix_audit_logs_retention_class",
        "ix_audit_logs_tenant_actor_created", "ix_audit_logs_tenant_category_result",
    ):
        op.drop_index(name, table_name="audit_logs")
    with op.batch_alter_table("audit_logs") as batch:
        batch.drop_constraint("uq_audit_logs_tenant_idempotency", type_="unique")
        batch.drop_constraint("uq_audit_logs_tenant_sequence", type_="unique")
        batch.drop_constraint("fk_audit_actor_session", type_="foreignkey")
        batch.drop_constraint("fk_audit_actor_membership", type_="foreignkey")
        for column in reversed((
            "actor_membership_id", "actor_session_id", "actor_type", "category", "severity",
            "parent_resource_type", "parent_resource_id", "correlation_id", "approval_request_id",
            "before_values", "after_values", "event_source", "retention_class", "data_classification",
            "sequence_number", "previous_event_hash", "event_hash", "hash_algorithm_version",
            "integrity_key_version", "idempotency_key",
        )):
            batch.drop_column(column)
    with op.batch_alter_table("connector_credentials") as batch:
        batch.drop_column("encryption_key_version")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("mfa_pending_secret_key_version")
        batch.drop_column("mfa_secret_key_version")
