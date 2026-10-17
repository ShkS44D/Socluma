"""playbook engine

Revision ID: 20260703_1500
Revises: 20260703_1400
Create Date: 2026-07-03 15:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260703_1500"
down_revision: Union[str, None] = "20260703_1400"
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


def _create_index_if_missing(name: str, table: str, columns: list[str], unique: bool = False) -> None:
    if table in _tables() and name not in _indexes(table):
        op.create_index(name, table, columns, unique=unique)


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    if table in _tables() and column.name not in _columns(table):
        with op.batch_alter_table(table) as batch_op:
            batch_op.add_column(column)


def _add_postgres_enum_values(enum_name: str, values: list[str]) -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for value in values:
        op.execute(sa.text(f"ALTER TYPE {enum_name} ADD VALUE IF NOT EXISTS :value").bindparams(value=value))


def upgrade() -> None:
    _add_postgres_enum_values("playbookstatus", ["TESTING", "DISABLED"])
    _add_postgres_enum_values("playbookexecutionstatus", ["PAUSED"])
    _add_postgres_enum_values(
        "playbooksteptype",
        [
            "DELAY",
            "AI_ANALYSIS",
            "THREAT_INTEL_LOOKUP",
            "HTTP_REQUEST",
            "WEBHOOK",
            "PYTHON_SCRIPT",
            "CREATE_INCIDENT",
            "UPDATE_INCIDENT",
            "CLOSE_INCIDENT",
            "TAG_ALERT",
            "ASSIGN_ANALYST",
            "CREATE_TASK",
            "BRANCH",
            "END",
        ],
    )
    _add_column_if_missing("playbooks", sa.Column("trigger_type", sa.String(length=64), nullable=True, server_default="manual_run"))
    _add_column_if_missing("playbooks", sa.Column("active_version_id", sa.String(length=36), nullable=True))
    if "playbooks" in _tables():
        op.execute("UPDATE playbooks SET status = 'DRAFT' WHERE status IS NULL")
        op.execute("UPDATE playbooks SET trigger_type = 'manual_run' WHERE trigger_type IS NULL")
    _create_index_if_missing("ix_playbooks_tenant_trigger_status", "playbooks", ["tenant_id", "trigger_type", "status"])

    if "playbook_executions" in _tables() and "incident_id" in _columns("playbook_executions"):
        with op.batch_alter_table("playbook_executions") as batch_op:
            batch_op.alter_column("incident_id", existing_type=sa.String(length=36), nullable=True)

    if "playbook_versions" not in _tables():
        op.create_table(
            "playbook_versions",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("playbook_id", sa.String(length=36), sa.ForeignKey("playbooks.id"), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("version_number", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(length=64), nullable=True, server_default="draft"),
            sa.Column("definition", sa.JSON(), nullable=False),
            sa.Column("changelog", sa.Text(), nullable=True),
            sa.Column("created_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("published_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    _create_index_if_missing("ix_playbook_versions_playbook_version", "playbook_versions", ["playbook_id", "version_number"], unique=True)
    _create_index_if_missing("ix_playbook_versions_tenant_status", "playbook_versions", ["tenant_id", "status"])
    if "playbook_versions" in _tables():
        op.execute("UPDATE playbook_versions SET status = 'draft' WHERE status IS NULL")

    for name, column in (
        ("alert_id", sa.Column("alert_id", sa.String(length=36), nullable=True)),
        ("version_id", sa.Column("version_id", sa.String(length=36), nullable=True)),
        ("trigger_type", sa.Column("trigger_type", sa.String(length=64), nullable=True, server_default="manual_run")),
        ("current_step_key", sa.Column("current_step_key", sa.String(length=255), nullable=True)),
        ("context", sa.Column("context", sa.JSON(), nullable=True)),
        ("paused_at", sa.Column("paused_at", sa.DateTime(timezone=True), nullable=True)),
        ("cancelled_at", sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True)),
    ):
        _add_column_if_missing("playbook_executions", column)
    if "playbook_executions" in _tables():
        op.execute("UPDATE playbook_executions SET trigger_type = 'manual_run' WHERE trigger_type IS NULL")
    _create_index_if_missing("ix_playbook_executions_version_id", "playbook_executions", ["version_id"])

    if "playbook_execution_steps" not in _tables():
        op.create_table(
            "playbook_execution_steps",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("execution_id", sa.String(length=36), sa.ForeignKey("playbook_executions.id"), nullable=False),
            sa.Column("playbook_id", sa.String(length=36), sa.ForeignKey("playbooks.id"), nullable=True),
            sa.Column("version_id", sa.String(length=36), sa.ForeignKey("playbook_versions.id"), nullable=True),
            sa.Column("step_key", sa.String(length=255), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("type", sa.String(length=64), nullable=False),
            sa.Column("order", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("status", sa.String(length=64), nullable=True, server_default="pending"),
            sa.Column("config", sa.JSON(), nullable=True),
            sa.Column("result", sa.JSON(), nullable=True),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("timeout_seconds", sa.Integer(), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("execution_time_ms", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    _create_index_if_missing("ix_playbook_execution_steps_execution_order", "playbook_execution_steps", ["execution_id", "order"])
    _create_index_if_missing("ix_playbook_execution_steps_status", "playbook_execution_steps", ["status"])

    if "playbook_approvals" not in _tables():
        op.create_table(
            "playbook_approvals",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("execution_id", sa.String(length=36), sa.ForeignKey("playbook_executions.id"), nullable=False),
            sa.Column("execution_step_id", sa.String(length=36), sa.ForeignKey("playbook_execution_steps.id"), nullable=True),
            sa.Column("requested_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("approved_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("status", sa.String(length=64), nullable=True, server_default="pending"),
            sa.Column("message", sa.Text(), nullable=True),
            sa.Column("decision_comment", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        )
    _create_index_if_missing("ix_playbook_approvals_execution_status", "playbook_approvals", ["execution_id", "status"])
    _create_index_if_missing("ix_playbook_approvals_tenant_status", "playbook_approvals", ["tenant_id", "status"])

    if "playbook_run_logs" not in _tables():
        op.create_table(
            "playbook_run_logs",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("execution_id", sa.String(length=36), sa.ForeignKey("playbook_executions.id"), nullable=False),
            sa.Column("execution_step_id", sa.String(length=36), sa.ForeignKey("playbook_execution_steps.id"), nullable=True),
            sa.Column("level", sa.String(length=20), nullable=False, server_default="info"),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column("data", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    _create_index_if_missing("ix_playbook_run_logs_execution_created_at", "playbook_run_logs", ["execution_id", "created_at"])
    _create_index_if_missing("ix_playbook_run_logs_tenant_created_at", "playbook_run_logs", ["tenant_id", "created_at"])

    if "playbook_variables" not in _tables():
        op.create_table(
            "playbook_variables",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("playbook_id", sa.String(length=36), sa.ForeignKey("playbooks.id"), nullable=True),
            sa.Column("key", sa.String(length=255), nullable=False),
            sa.Column("value", sa.JSON(), nullable=False),
            sa.Column("scope", sa.String(length=50), nullable=False, server_default="tenant"),
            sa.Column("is_secret", sa.Boolean(), nullable=False, server_default="0"),
            sa.Column("created_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("updated_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    _create_index_if_missing("ix_playbook_variables_tenant_scope_key", "playbook_variables", ["tenant_id", "scope", "key"])
    _create_index_if_missing("ix_playbook_variables_playbook_key", "playbook_variables", ["playbook_id", "key"])


def downgrade() -> None:
    for table in ("playbook_variables", "playbook_run_logs", "playbook_approvals", "playbook_execution_steps", "playbook_versions"):
        if table in _tables():
            op.drop_table(table)
