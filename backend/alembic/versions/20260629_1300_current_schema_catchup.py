"""current schema catchup

Revision ID: 20260629_1300
Revises: 20260629_1200
Create Date: 2026-06-29 13:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260629_1300"
down_revision: Union[str, None] = "20260629_1200"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _created_at_default() -> sa.TextClause:
    bind = op.get_bind()
    return sa.text("CURRENT_TIMESTAMP") if bind.dialect.name == "sqlite" else sa.text("now()")


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table_name not in set(inspector.get_table_names()):
        return set()
    return {column["name"] for column in inspector.get_columns(table_name)}


def _indexes(table_name: str) -> list[dict]:
    inspector = sa.inspect(op.get_bind())
    if table_name not in set(inspector.get_table_names()):
        return []
    return inspector.get_indexes(table_name)


def _add_columns(table_name: str, column_specs: list[tuple[str, sa.Column]]) -> None:
    existing_columns = _columns(table_name)
    if not existing_columns:
        return
    with op.batch_alter_table(table_name) as batch_op:
        for column_name, column in column_specs:
            if column_name not in existing_columns:
                batch_op.add_column(column)


def upgrade() -> None:
    bind = op.get_bind()
    existing_tables = _tables()
    created_at_default = _created_at_default()

    if bind.dialect.name == "postgresql":
        op.execute("ALTER TYPE eventtype ADD VALUE IF NOT EXISTS 'USER_CREATION'")

    _add_columns(
        "incidents",
        [
            ("why_suspicious", sa.Column("why_suspicious", sa.Text(), nullable=True)),
            ("ai_analyzed_at", sa.Column("ai_analyzed_at", sa.DateTime(timezone=True), nullable=True)),
        ],
    )
    _add_columns(
        "detection_rules",
        [
            ("rule_type", sa.Column("rule_type", sa.Enum("CUSTOM", "SIGMA", name="ruletype"), nullable=True, server_default="CUSTOM")),
            ("rule_content", sa.Column("rule_content", sa.JSON(), nullable=True)),
            ("event_type", sa.Column("event_type", sa.Enum("LOGIN", "LOGOUT", "FILE", "NETWORK", "PROCESS", "ALERT", "USER_CREATION", name="eventtype"), nullable=True)),
            ("condition", sa.Column("condition", sa.JSON(), nullable=True)),
            ("mitre_technique_id", sa.Column("mitre_technique_id", sa.String(length=50), nullable=True)),
        ],
    )
    _add_columns(
        "alerts",
        [
            ("detection_rule_id", sa.Column("detection_rule_id", sa.String(length=36), nullable=True)),
            ("event_id", sa.Column("event_id", sa.String(length=36), nullable=True)),
            ("matched_condition", sa.Column("matched_condition", sa.Text(), nullable=True)),
            ("why_matched", sa.Column("why_matched", sa.Text(), nullable=True)),
        ],
    )
    _add_columns(
        "detection_matches",
        [("alert_id", sa.Column("alert_id", sa.String(length=36), nullable=True))],
    )

    if "incident_iocs" not in existing_tables:
        op.create_table(
            "incident_iocs",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("incident_id", sa.String(length=36), nullable=False),
            sa.Column("ioc_id", sa.String(length=36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=created_at_default, nullable=True),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["ioc_id"], ["iocs.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )

    if "log_sources" not in existing_tables:
        op.create_table(
            "log_sources",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("type", sa.Enum("WINDOWS_EDR", "LINUX_AUDIT", "FIREWALL", "CLOUDTRAIL", "APPLICATION_LOG", "CUSTOM", name="logsourcetype"), nullable=True, server_default="CUSTOM"),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("status", sa.Enum("ACTIVE", "INACTIVE", "ERROR", name="logsourcestatus"), nullable=True, server_default="INACTIVE"),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=created_at_default, nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=created_at_default, nullable=True),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    existing_tables = _tables()
    if "collectors" not in existing_tables:
        op.create_table(
            "collectors",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("log_source_id", sa.String(length=36), nullable=True),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("type", sa.String(length=100), nullable=False),
            sa.Column("hostname", sa.String(length=255), nullable=True),
            sa.Column("token", sa.String(length=255), nullable=False),
            sa.Column("status", sa.Enum("ONLINE", "OFFLINE", "ERROR", name="collectorstatus"), nullable=True, server_default="OFFLINE"),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=created_at_default, nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=created_at_default, nullable=True),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
            sa.ForeignKeyConstraint(["log_source_id"], ["log_sources.id"]),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("token"),
        )

    if "playbooks" not in existing_tables:
        op.create_table(
            "playbooks",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("status", sa.Enum("DRAFT", "ACTIVE", "ARCHIVED", name="playbookstatus"), nullable=True, server_default="DRAFT"),
            sa.Column("trigger_conditions", sa.JSON(), nullable=True),
            sa.Column("created_by", sa.String(length=36), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=created_at_default, nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=created_at_default, nullable=True),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
            sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    existing_tables = _tables()
    if "playbook_steps" not in existing_tables:
        op.create_table(
            "playbook_steps",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("playbook_id", sa.String(length=36), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("type", sa.Enum("ACTION", "CONDITION", "APPROVAL", "NOTIFICATION", name="playbooksteptype"), nullable=False),
            sa.Column("order", sa.Integer(), nullable=False),
            sa.Column("config", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=created_at_default, nullable=True),
            sa.ForeignKeyConstraint(["playbook_id"], ["playbooks.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    if "playbook_executions" not in existing_tables:
        op.create_table(
            "playbook_executions",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("incident_id", sa.String(length=36), nullable=False),
            sa.Column("playbook_id", sa.String(length=36), nullable=True),
            sa.Column("status", sa.Enum("PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED", "AWAITING_APPROVAL", name="playbookexecutionstatus"), nullable=True, server_default="PENDING"),
            sa.Column("triggered_by", sa.String(length=36), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("result", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=created_at_default, nullable=True),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
            sa.ForeignKeyConstraint(["playbook_id"], ["playbooks.id"]),
            sa.ForeignKeyConstraint(["triggered_by"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    mitre_technique_indexes = _indexes("mitre_techniques")
    has_unique_technique_id = any(
        index.get("unique") and index.get("column_names") == ["technique_id"]
        for index in mitre_technique_indexes
    )
    if not has_unique_technique_id:
        op.create_index(
            "ux_mitre_techniques_technique_id",
            "mitre_techniques",
            ["technique_id"],
            unique=True,
        )

    if "mitre_technique_impacts" not in existing_tables:
        op.create_table(
            "mitre_technique_impacts",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("technique_id", sa.String(length=50), nullable=False),
            sa.Column("impact_score", sa.Integer(), nullable=False, server_default="10"),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=created_at_default, nullable=True),
            sa.ForeignKeyConstraint(["technique_id"], ["mitre_techniques.technique_id"]),
            sa.PrimaryKeyConstraint("id"),
        )


def downgrade() -> None:
    existing_tables = _tables()
    for table_name in (
        "mitre_technique_impacts",
        "playbook_executions",
        "playbook_steps",
        "playbooks",
        "collectors",
        "log_sources",
        "incident_iocs",
    ):
        if table_name in existing_tables:
            op.drop_table(table_name)

    mitre_technique_indexes = _indexes("mitre_techniques")
    if any(index.get("name") == "ux_mitre_techniques_technique_id" for index in mitre_technique_indexes):
        op.drop_index("ux_mitre_techniques_technique_id", table_name="mitre_techniques")

    for table_name, column_names in (
        ("detection_matches", ("alert_id",)),
        ("alerts", ("why_matched", "matched_condition", "event_id", "detection_rule_id")),
        ("detection_rules", ("mitre_technique_id", "condition", "event_type", "rule_content", "rule_type")),
        ("incidents", ("ai_analyzed_at", "why_suspicious")),
    ):
        existing_columns = _columns(table_name)
        if not existing_columns:
            continue
        with op.batch_alter_table(table_name) as batch_op:
            for column_name in column_names:
                if column_name in existing_columns:
                    batch_op.drop_column(column_name)
