"""batch5 soar response action framework

Revision ID: 20260703_1600
Revises: 20260703_1500
Create Date: 2026-07-03 16:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260703_1600"
down_revision: Union[str, None] = "20260703_1500"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _indexes(table_name: str) -> set[str]:
    if table_name not in _tables():
        return set()
    return {index["name"] for index in sa.inspect(op.get_bind()).get_indexes(table_name)}


def _create_index_if_missing(name: str, table: str, columns: list[str], unique: bool = False) -> None:
    if table in _tables() and name not in _indexes(table):
        op.create_index(name, table, columns, unique=unique)


def upgrade() -> None:
    if "action_connectors" not in _tables():
        op.create_table(
            "action_connectors",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("type", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=64), nullable=True, server_default="active"),
            sa.Column("config", sa.JSON(), nullable=False),
            sa.Column("requires_approval", sa.Boolean(), nullable=False, server_default="0"),
            sa.Column("approval_roles", sa.JSON(), nullable=True),
            sa.Column("created_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("updated_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    _create_index_if_missing("ix_action_connectors_tenant_type_status", "action_connectors", ["tenant_id", "type", "status"])
    _create_index_if_missing("ix_action_connectors_tenant_name", "action_connectors", ["tenant_id", "name"])

    if "connector_credentials" not in _tables():
        op.create_table(
            "connector_credentials",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("connector_id", sa.String(length=36), sa.ForeignKey("action_connectors.id"), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("status", sa.String(length=64), nullable=True, server_default="active"),
            sa.Column("encrypted_secret", sa.Text(), nullable=False),
            sa.Column("secret_fingerprint", sa.String(length=64), nullable=False),
            sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("created_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("updated_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    _create_index_if_missing("ix_connector_credentials_tenant_connector_status", "connector_credentials", ["tenant_id", "connector_id", "status"])
    _create_index_if_missing("ix_connector_credentials_tenant_name", "connector_credentials", ["tenant_id", "name"])
    _create_index_if_missing("ix_connector_credentials_secret_fingerprint", "connector_credentials", ["secret_fingerprint"])

    if "connector_action_executions" not in _tables():
        op.create_table(
            "connector_action_executions",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("connector_id", sa.String(length=36), sa.ForeignKey("action_connectors.id"), nullable=False),
            sa.Column("credential_id", sa.String(length=36), sa.ForeignKey("connector_credentials.id"), nullable=True),
            sa.Column("playbook_execution_id", sa.String(length=36), nullable=True),
            sa.Column("playbook_step_id", sa.String(length=36), nullable=True),
            sa.Column("action_name", sa.String(length=255), nullable=False),
            sa.Column("status", sa.String(length=64), nullable=True, server_default="queued"),
            sa.Column("request", sa.JSON(), nullable=True),
            sa.Column("response", sa.JSON(), nullable=True),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("retry_policy", sa.JSON(), nullable=True),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("timeout_seconds", sa.Integer(), nullable=True),
            sa.Column("worker_id", sa.String(length=255), nullable=True),
            sa.Column("correlation_id", sa.String(length=64), nullable=False),
            sa.Column("request_id", sa.String(length=64), nullable=True),
            sa.Column("requested_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("approved_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("duration_ms", sa.Integer(), nullable=True),
            sa.Column("rollback_status", sa.String(length=64), nullable=True),
            sa.Column("rollback_result", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    _create_index_if_missing("ix_connector_action_executions_tenant_status_created", "connector_action_executions", ["tenant_id", "status", "created_at"])
    _create_index_if_missing("ix_connector_action_executions_connector_created", "connector_action_executions", ["connector_id", "created_at"])
    _create_index_if_missing("ix_connector_action_executions_playbook_execution", "connector_action_executions", ["playbook_execution_id"])
    _create_index_if_missing("ix_connector_action_executions_correlation_id", "connector_action_executions", ["correlation_id"])
    _create_index_if_missing("ix_connector_action_executions_request_id", "connector_action_executions", ["request_id"])

    if "soar_action_approvals" not in _tables():
        op.create_table(
            "soar_action_approvals",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("execution_id", sa.String(length=36), sa.ForeignKey("connector_action_executions.id"), nullable=False),
            sa.Column("required_role", sa.String(length=64), nullable=True),
            sa.Column("status", sa.String(length=64), nullable=True, server_default="pending"),
            sa.Column("requested_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("decided_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("decision_comment", sa.Text(), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        )
    _create_index_if_missing("ix_soar_action_approvals_execution_status", "soar_action_approvals", ["execution_id", "status"])
    _create_index_if_missing("ix_soar_action_approvals_tenant_status", "soar_action_approvals", ["tenant_id", "status"])

    if "connector_action_logs" not in _tables():
        op.create_table(
            "connector_action_logs",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("execution_id", sa.String(length=36), sa.ForeignKey("connector_action_executions.id"), nullable=False),
            sa.Column("level", sa.String(length=20), nullable=False, server_default="info"),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column("data", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    _create_index_if_missing("ix_connector_action_logs_execution_created", "connector_action_logs", ["execution_id", "created_at"])
    _create_index_if_missing("ix_connector_action_logs_tenant_created", "connector_action_logs", ["tenant_id", "created_at"])


def downgrade() -> None:
    for table in (
        "connector_action_logs",
        "soar_action_approvals",
        "connector_action_executions",
        "connector_credentials",
        "action_connectors",
    ):
        if table in _tables():
            op.drop_table(table)
