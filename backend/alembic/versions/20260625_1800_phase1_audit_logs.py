"""Add audit logs

Revision ID: 202606251800
Revises: e20d4558ca11
Create Date: 2026-06-25 18:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "202606251800"
down_revision: Union[str, None] = "e20d4558ca11"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())
    created_at_default = (
        sa.text("CURRENT_TIMESTAMP")
        if bind.dialect.name == "sqlite"
        else sa.text("now()")
    )

    if "audit_logs" not in existing_tables:
        op.create_table(
            "audit_logs",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=True),
            sa.Column("user_id", sa.String(length=36), nullable=True),
            sa.Column("action", sa.String(length=100), nullable=False),
            sa.Column("resource_type", sa.String(length=100), nullable=True),
            sa.Column("resource_id", sa.String(length=36), nullable=True),
            sa.Column("ip_address", sa.String(length=64), nullable=True),
            sa.Column("details", sa.JSON(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=created_at_default,
                nullable=True,
            ),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        existing_indexes: set[str] = set()
    else:
        existing_indexes = {index["name"] for index in inspector.get_indexes("audit_logs")}

    index_specs = (
        (op.f("ix_audit_logs_action"), ["action"]),
        (op.f("ix_audit_logs_created_at"), ["created_at"]),
        (op.f("ix_audit_logs_tenant_id"), ["tenant_id"]),
        (op.f("ix_audit_logs_user_id"), ["user_id"]),
    )
    for index_name, columns in index_specs:
        if index_name not in existing_indexes:
            op.create_index(index_name, "audit_logs", columns, unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())
    if "audit_logs" not in existing_tables:
        return

    existing_indexes = {index["name"] for index in inspector.get_indexes("audit_logs")}
    for index_name in (
        op.f("ix_audit_logs_user_id"),
        op.f("ix_audit_logs_tenant_id"),
        op.f("ix_audit_logs_created_at"),
        op.f("ix_audit_logs_action"),
    ):
        if index_name in existing_indexes:
            op.drop_index(index_name, table_name="audit_logs")
    op.drop_table("audit_logs")
