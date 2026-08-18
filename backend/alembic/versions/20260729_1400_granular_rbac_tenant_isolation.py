"""Granular RBAC, scoped API keys, and sensitive-action approvals.

Revision ID: 20260729_1400
Revises: 20260729_1300
"""
from alembic import op
import sqlalchemy as sa


revision = "20260729_1400"
down_revision = "20260729_1300"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("tenants") as batch:
        batch.add_column(sa.Column("sensitive_action_approval_mode", sa.String(20), nullable=False, server_default="none"))
        batch.add_column(sa.Column("permission_revision", sa.Integer(), nullable=False, server_default="1"))

    with op.batch_alter_table("organization_custom_roles") as batch:
        batch.add_column(sa.Column("normalized_name", sa.String(100), nullable=True))
        batch.add_column(sa.Column("is_protected", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("permission_revision", sa.Integer(), nullable=False, server_default="1"))
    # Backfill deterministically without making a previously valid database
    # unmigratable when role names differ only by case or surrounding spaces.
    connection = op.get_bind()
    rows = connection.execute(
        sa.text("SELECT id, tenant_id, name FROM organization_custom_roles ORDER BY tenant_id, id")
    ).mappings()
    used: dict[str, set[str]] = {}
    for row in rows:
        base = " ".join((row["name"] or "").strip().lower().split()) or "custom-role"
        normalized = base[:100]
        tenant_names = used.setdefault(row["tenant_id"], set())
        if normalized in tenant_names:
            suffix = f"-{row['id'][:8].lower()}"
            normalized = f"{base[:100 - len(suffix)]}{suffix}"
        tenant_names.add(normalized)
        connection.execute(
            sa.text(
                "UPDATE organization_custom_roles "
                "SET normalized_name = :normalized_name WHERE id = :role_id"
            ),
            {"normalized_name": normalized, "role_id": row["id"]},
        )
    op.create_index(
        "ix_org_custom_roles_tenant_normalized_name",
        "organization_custom_roles",
        ["tenant_id", "normalized_name"],
        unique=True,
    )

    op.create_table(
        "organization_api_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_by_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("key_prefix", sa.String(24), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(100), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("tenant_id", "name", name="uq_organization_api_keys_tenant_name"),
        sa.UniqueConstraint("key_hash", name="uq_organization_api_keys_hash"),
    )
    for name, columns in (
        ("ix_organization_api_keys_tenant_id", ["tenant_id"]),
        ("ix_organization_api_keys_created_by_id", ["created_by_id"]),
        ("ix_organization_api_keys_key_prefix", ["key_prefix"]),
        ("ix_organization_api_keys_expires", ["expires_at"]),
        ("ix_organization_api_keys_tenant_revoked", ["tenant_id", "revoked_at"]),
    ):
        op.create_index(name, "organization_api_keys", columns)

    op.create_table(
        "sensitive_action_approvals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("requester_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action_type", sa.String(100), nullable=False),
        sa.Column("target_resource_type", sa.String(100), nullable=False),
        sa.Column("target_resource_id", sa.String(36), nullable=False),
        sa.Column("request_fingerprint", sa.String(64), nullable=False),
        sa.Column("required_approvals", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("safe_metadata", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("tenant_id", "request_fingerprint", name="uq_sensitive_approval_fingerprint"),
    )
    for name, columns in (
        ("ix_sensitive_approvals_tenant_id", ["tenant_id"]),
        ("ix_sensitive_approvals_requester_id", ["requester_id"]),
        ("ix_sensitive_approvals_action_type", ["action_type"]),
        ("ix_sensitive_approvals_tenant_status", ["tenant_id", "status"]),
        ("ix_sensitive_approvals_expires", ["expires_at"]),
        ("ix_sensitive_approvals_target", ["tenant_id", "action_type", "target_resource_id"]),
    ):
        op.create_index(name, "sensitive_action_approvals", columns)

    op.create_table(
        "sensitive_action_approval_decisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "approval_id", sa.String(36),
            sa.ForeignKey("sensitive_action_approvals.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("approver_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("approval_id", "approver_id", name="uq_sensitive_approval_approver"),
    )
    op.create_index("ix_sensitive_approval_decisions_approval_id", "sensitive_action_approval_decisions", ["approval_id"])
    op.create_index("ix_sensitive_approval_decisions_approver_id", "sensitive_action_approval_decisions", ["approver_id"])
    op.create_index(
        "ix_sensitive_approval_decisions_approval",
        "sensitive_action_approval_decisions",
        ["approval_id", "created_at"],
    )


def downgrade():
    op.drop_table("sensitive_action_approval_decisions")
    op.drop_table("sensitive_action_approvals")
    op.drop_table("organization_api_keys")
    op.drop_index("ix_org_custom_roles_tenant_normalized_name", table_name="organization_custom_roles")
    with op.batch_alter_table("organization_custom_roles") as batch:
        batch.drop_column("permission_revision")
        batch.drop_column("is_protected")
        batch.drop_column("normalized_name")
    with op.batch_alter_table("tenants") as batch:
        batch.drop_column("permission_revision")
        batch.drop_column("sensitive_action_approval_mode")
