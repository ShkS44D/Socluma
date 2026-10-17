"""Foundation integrity, deletion lifecycle, and daily usage aggregates.

Revision ID: 20260729_1200
Revises: 20260727_1200
"""
from alembic import op
import sqlalchemy as sa


revision = "20260729_1200"
down_revision = "20260727_1200"
branch_labels = None
depends_on = None


def _column_names(inspector, table: str) -> set[str]:
    return {column["name"] for column in inspector.get_columns(table)}


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tenant_columns = _column_names(inspector, "tenants")
    additions = [
        column
        for column in (
            sa.Column("deletion_requested_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("scheduled_purge_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("deletion_requested_by_id", sa.String(36), nullable=True),
        )
        if column.name not in tenant_columns
    ]
    if additions:
        with op.batch_alter_table("tenants") as batch:
            for column in additions:
                batch.add_column(column)

    inspector = sa.inspect(bind)
    tenant_fks = {
        tuple(fk.get("constrained_columns") or []): fk
        for fk in inspector.get_foreign_keys("tenants")
    }
    if ("deletion_requested_by_id",) not in tenant_fks:
        with op.batch_alter_table("tenants") as batch:
            batch.create_foreign_key(
                "fk_tenants_deletion_requester",
                "users",
                ["deletion_requested_by_id"],
                ["id"],
                ondelete="SET NULL",
            )

    inspector = sa.inspect(bind)
    tenant_indexes = {index["name"] for index in inspector.get_indexes("tenants")}
    if "ix_tenants_scheduled_purge_at" not in tenant_indexes:
        op.create_index("ix_tenants_scheduled_purge_at", "tenants", ["scheduled_purge_at"])
    if "ix_tenants_deletion_requested_by_id" not in tenant_indexes:
        op.create_index("ix_tenants_deletion_requested_by_id", "tenants", ["deletion_requested_by_id"])

    usage_columns = _column_names(inspector, "organization_usage")
    usage_additions = [
        column
        for column in (
            sa.Column("incident_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("playbook_execution_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("triage_ai_request_count", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("snapshot_date", sa.Date(), nullable=True),
        )
        if column.name not in usage_columns
    ]
    if usage_additions:
        with op.batch_alter_table("organization_usage") as batch:
            for column in usage_additions:
                batch.add_column(column)

    inspector = sa.inspect(bind)
    usage_indexes = {index["name"] for index in inspector.get_indexes("organization_usage")}
    if "ix_org_usage_snapshot_date" not in usage_indexes:
        op.create_index("ix_org_usage_snapshot_date", "organization_usage", ["snapshot_date"])
    usage_uniques = {
        tuple(item.get("column_names") or [])
        for item in inspector.get_unique_constraints("organization_usage")
    }
    usage_indexes = inspector.get_indexes("organization_usage")
    has_unique_index = any(
        index.get("unique") and tuple(index.get("column_names") or []) == ("tenant_id", "snapshot_date")
        for index in usage_indexes
    )
    if ("tenant_id", "snapshot_date") not in usage_uniques and not has_unique_index:
        with op.batch_alter_table("organization_usage") as batch:
            batch.create_unique_constraint(
                "uq_org_usage_tenant_snapshot_date",
                ["tenant_id", "snapshot_date"],
            )


def downgrade():
    with op.batch_alter_table("organization_usage") as batch:
        batch.drop_constraint("uq_org_usage_tenant_snapshot_date", type_="unique")
    op.drop_index("ix_org_usage_snapshot_date", table_name="organization_usage")
    with op.batch_alter_table("organization_usage") as batch:
        batch.drop_column("snapshot_date")
        batch.drop_column("triage_ai_request_count")
        batch.drop_column("playbook_execution_count")
        batch.drop_column("incident_count")

    op.drop_index("ix_tenants_deletion_requested_by_id", table_name="tenants")
    op.drop_index("ix_tenants_scheduled_purge_at", table_name="tenants")
    with op.batch_alter_table("tenants") as batch:
        batch.drop_constraint("fk_tenants_deletion_requester", type_="foreignkey")
        batch.drop_column("deletion_requested_by_id")
        batch.drop_column("deleted_at")
        batch.drop_column("scheduled_purge_at")
        batch.drop_column("deletion_requested_at")
    # PostgreSQL enum values are intentionally retained; removing a used enum
    # value is destructive and unsafe for a routine rollback.
