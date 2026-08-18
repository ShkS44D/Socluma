"""Deletion PIN, granular RBAC, and complete audit metadata.

Revision ID: 20260727_1200
Revises: 20260725_1200
"""
from alembic import op
import sqlalchemy as sa

revision = "20260727_1200"
down_revision = "20260725_1200"
branch_labels = None
depends_on = None


def upgrade():
    # Some development installations historically ran ORM metadata creation
    # before Alembic. Be repair-safe when those databases already contain part
    # of this additive schema, while keeping fresh installations deterministic.
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    tenant_columns = {column["name"] for column in inspector.get_columns("tenants")}
    missing_tenant_columns = [
        column for column in (
            sa.Column("deletion_pin_hash", sa.String(255), nullable=True),
            sa.Column("deletion_pin_failed_attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("deletion_pin_locked_until", sa.DateTime(timezone=True), nullable=True),
        ) if column.name not in tenant_columns
    ]
    if missing_tenant_columns:
        with op.batch_alter_table("tenants") as batch:
            for column in missing_tenant_columns:
                batch.add_column(column)

    if "organization_custom_roles" not in inspector.get_table_names():
        op.create_table(
            "organization_custom_roles",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("name", sa.String(100), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("permissions", sa.JSON(), nullable=False),
            sa.Column("is_system", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.UniqueConstraint("tenant_id", "name", name="uq_org_custom_roles_tenant_name"),
        )
    inspector = sa.inspect(bind)
    role_indexes = {index["name"] for index in inspector.get_indexes("organization_custom_roles")}
    if "ix_org_custom_roles_tenant" not in role_indexes:
        op.create_index("ix_org_custom_roles_tenant", "organization_custom_roles", ["tenant_id"])

    membership_columns = {column["name"] for column in inspector.get_columns("organization_memberships")}
    if "custom_role_id" not in membership_columns:
        with op.batch_alter_table("organization_memberships") as batch:
            batch.add_column(sa.Column("custom_role_id", sa.String(36), nullable=True))
    inspector = sa.inspect(bind)
    membership_fks = {fk.get("name") for fk in inspector.get_foreign_keys("organization_memberships")}
    if "fk_membership_custom_role" not in membership_fks:
        with op.batch_alter_table("organization_memberships") as batch:
            batch.create_foreign_key(
                "fk_membership_custom_role", "organization_custom_roles", ["custom_role_id"], ["id"]
            )

    audit_columns = {column["name"] for column in inspector.get_columns("audit_logs")}
    missing_audit_columns = [
        column for column in (
            sa.Column("actor_role", sa.String(100), nullable=True),
            sa.Column("status", sa.String(32), nullable=False, server_default="success"),
            sa.Column("user_agent", sa.String(512), nullable=True),
            sa.Column("request_id", sa.String(128), nullable=True),
            sa.Column("failure_reason", sa.String(255), nullable=True),
        ) if column.name not in audit_columns
    ]
    if missing_audit_columns:
        with op.batch_alter_table("audit_logs") as batch:
            for column in missing_audit_columns:
                batch.add_column(column)


def downgrade():
    with op.batch_alter_table("audit_logs") as batch:
        for name in ("failure_reason", "request_id", "user_agent", "status", "actor_role"):
            batch.drop_column(name)
    with op.batch_alter_table("organization_memberships") as batch:
        batch.drop_constraint("fk_membership_custom_role", type_="foreignkey")
        batch.drop_column("custom_role_id")
    op.drop_index("ix_org_custom_roles_tenant", table_name="organization_custom_roles")
    op.drop_table("organization_custom_roles")
    with op.batch_alter_table("tenants") as batch:
        batch.drop_column("deletion_pin_locked_until")
        batch.drop_column("deletion_pin_failed_attempts")
        batch.drop_column("deletion_pin_hash")
