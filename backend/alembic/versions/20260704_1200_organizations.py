"""organizations and memberships

Revision ID: 20260704_1200
Revises: 20260703_1600
Create Date: 2026-07-04 12:00:00.000000
"""

from __future__ import annotations

import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260704_1200"
down_revision: Union[str, None] = "20260703_1600"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table_name not in _tables():
        return set()
    return {column["name"] for column in inspector.get_columns(table_name)}


def _indexes(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table_name not in _tables():
        return set()
    return {index["name"] for index in inspector.get_indexes(table_name)}


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    if table in _tables() and column.name not in _columns(table):
        with op.batch_alter_table(table) as batch_op:
            batch_op.add_column(column)


def _create_index_if_missing(name: str, table: str, columns: list[str], unique: bool = False) -> None:
    if table in _tables() and name not in _indexes(table):
        op.create_index(name, table, columns, unique=unique)


def upgrade() -> None:
    tenant_columns = {
        "description": sa.Column("description", sa.Text(), nullable=True),
        "logo": sa.Column("logo", sa.String(length=1024), nullable=True),
        "industry": sa.Column("industry", sa.String(length=255), nullable=True),
        "country": sa.Column("country", sa.String(length=100), nullable=True),
        "timezone": sa.Column("timezone", sa.String(length=100), nullable=False, server_default="UTC"),
        "subscription_plan": sa.Column("subscription_plan", sa.String(length=100), nullable=False, server_default="starter"),
        "max_users": sa.Column("max_users", sa.Integer(), nullable=False, server_default="25"),
        "max_collectors": sa.Column("max_collectors", sa.Integer(), nullable=False, server_default="25"),
        "max_storage": sa.Column("max_storage", sa.BigInteger(), nullable=False, server_default="10737418240"),
        "status": sa.Column("status", sa.String(length=64), nullable=False, server_default="ACTIVE"),
    }
    for column in tenant_columns.values():
        _add_column_if_missing("tenants", column)
    _create_index_if_missing("ix_tenants_status_created_at", "tenants", ["status", "created_at"])
    _create_index_if_missing("ix_tenants_subscription_plan", "tenants", ["subscription_plan"])

    if "organization_memberships" not in _tables():
        op.create_table(
            "organization_memberships",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("role", sa.String(length=64), nullable=False, server_default="ANALYST"),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default="1"),
            sa.Column("invited_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    _create_index_if_missing("ix_org_memberships_tenant_role_active", "organization_memberships", ["tenant_id", "role", "is_active"])
    _create_index_if_missing("ix_org_memberships_user_active", "organization_memberships", ["user_id", "is_active"])
    _create_index_if_missing("ix_org_memberships_unique_user_tenant", "organization_memberships", ["user_id", "tenant_id"], unique=True)

    if "organization_invitations" not in _tables():
        op.create_table(
            "organization_invitations",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("role", sa.String(length=64), nullable=False, server_default="ANALYST"),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=64), nullable=False, server_default="PENDING"),
            sa.Column("invited_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("invited_user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    _create_index_if_missing("ix_org_invitations_tenant_status", "organization_invitations", ["tenant_id", "status"])
    _create_index_if_missing("ix_org_invitations_email_status", "organization_invitations", ["email", "status"])
    _create_index_if_missing("ix_org_invitations_token_hash", "organization_invitations", ["token_hash"], unique=True)

    if "organization_usage" not in _tables():
        op.create_table(
            "organization_usage",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("user_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("collector_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("alert_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("playbook_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("soar_execution_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("storage_bytes", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("api_request_count", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("period_start", sa.DateTime(timezone=True), nullable=True),
            sa.Column("period_end", sa.DateTime(timezone=True), nullable=True),
            sa.Column("calculated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    _create_index_if_missing("ix_org_usage_tenant_period", "organization_usage", ["tenant_id", "period_start", "period_end"])
    _backfill_memberships()


def _backfill_memberships() -> None:
    bind = op.get_bind()
    users = bind.execute(sa.text("SELECT id, tenant_id, role FROM users")).fetchall()
    existing = {
        (row[0], row[1])
        for row in bind.execute(sa.text("SELECT user_id, tenant_id FROM organization_memberships")).fetchall()
    }
    for user_id, tenant_id, role in users:
        if (user_id, tenant_id) in existing:
            continue
        org_role = "OWNER" if str(role).lower() == "admin" else ("VIEWER" if str(role).lower() == "viewer" else "ANALYST")
        bind.execute(
            sa.text(
                """
                INSERT INTO organization_memberships (id, tenant_id, user_id, role, is_active)
                VALUES (:id, :tenant_id, :user_id, :role, :is_active)
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "tenant_id": tenant_id,
                "user_id": user_id,
                "role": org_role,
                "is_active": True,
            },
        )


def downgrade() -> None:
    for table in ("organization_usage", "organization_invitations", "organization_memberships"):
        if table in _tables():
            op.drop_table(table)
