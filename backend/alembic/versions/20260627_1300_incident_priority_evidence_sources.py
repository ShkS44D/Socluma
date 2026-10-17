"""Incident priority, evidence, and source management

Revision ID: 202606271300
Revises: 202606271200
Create Date: 2026-06-27 13:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "202606271300"
down_revision: Union[str, None] = "202606271200"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


incident_priority_enum = postgresql.ENUM("P1", "P2", "P3", "P4", name="incidentpriority")
evidence_type_enum = postgresql.ENUM("IP", "DOMAIN", "HASH", "FILE", "URL", name="evidencetype")


def _incident_priority_column_type(bind):
    if bind.dialect.name == "postgresql":
        return postgresql.ENUM("P1", "P2", "P3", "P4", name="incidentpriority", create_type=False)
    return sa.Enum("P1", "P2", "P3", "P4", name="incidentpriority")


def _evidence_column_type(bind):
    if bind.dialect.name == "postgresql":
        return postgresql.ENUM("IP", "DOMAIN", "HASH", "FILE", "URL", name="evidencetype", create_type=False)
    return sa.Enum("IP", "DOMAIN", "HASH", "FILE", "URL", name="evidencetype")


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if bind.dialect.name == "postgresql":
        incident_priority_enum.create(bind, checkfirst=True)
        evidence_type_enum.create(bind, checkfirst=True)
    
    incident_columns = {column["name"] for column in inspector.get_columns("incidents")}
    with op.batch_alter_table("incidents") as batch_op:
        if "priority" not in incident_columns:
            batch_op.add_column(sa.Column("priority", _incident_priority_column_type(bind), nullable=True, server_default="P3"))
        if "due_date" not in incident_columns:
            batch_op.add_column(sa.Column("due_date", sa.DateTime(timezone=True), nullable=True))
        if "escalation_level" not in incident_columns:
            batch_op.add_column(sa.Column("escalation_level", sa.Integer(), nullable=False, server_default="0"))
    
    table_names = inspector.get_table_names()
    if "incident_evidence" not in table_names:
        op.create_table(
            "incident_evidence",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("incident_id", sa.String(length=36), nullable=False),
            sa.Column("user_id", sa.String(length=36), nullable=False),
            sa.Column("type", _evidence_column_type(bind), nullable=False),
            sa.Column("value", sa.String(length=1024), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=True),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        with op.batch_alter_table("incident_evidence", schema=None) as batch_op:
            batch_op.create_index("ix_incident_evidence_incident_id", ["incident_id"], unique=False)
            batch_op.create_index("ix_incident_evidence_user_id", ["user_id"], unique=False)
    
    source_columns = {column["name"] for column in inspector.get_columns("alert_sources")}
    with op.batch_alter_table("alert_sources") as batch_op:
        if "api_key_hash" not in source_columns:
            batch_op.add_column(sa.Column("api_key_hash", sa.String(length=256), nullable=True))
        if "enabled" not in source_columns:
            batch_op.add_column(sa.Column("enabled", sa.Boolean(), nullable=True, server_default="1"))
        if "config" not in source_columns:
            batch_op.add_column(sa.Column("config", sa.JSON(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    
    with op.batch_alter_table("alert_sources") as batch_op:
        source_columns = {column["name"] for column in inspector.get_columns("alert_sources")}
        if "api_key_hash" in source_columns:
            batch_op.drop_column("api_key_hash")
        if "enabled" in source_columns:
            batch_op.drop_column("enabled")
        if "config" in source_columns:
            batch_op.drop_column("config")
    
    table_names = inspector.get_table_names()
    if "incident_evidence" in table_names:
        with op.batch_alter_table("incident_evidence", schema=None) as batch_op:
            batch_op.drop_index("ix_incident_evidence_user_id")
            batch_op.drop_index("ix_incident_evidence_incident_id")
        op.drop_table("incident_evidence")
    
    with op.batch_alter_table("incidents") as batch_op:
        incident_columns = {column["name"] for column in inspector.get_columns("incidents")}
        if "priority" in incident_columns:
            batch_op.drop_column("priority")
        if "due_date" in incident_columns:
            batch_op.drop_column("due_date")
        if "escalation_level" in incident_columns:
            batch_op.drop_column("escalation_level")

    if bind.dialect.name == "postgresql":
        evidence_type_enum.drop(bind, checkfirst=True)
        incident_priority_enum.drop(bind, checkfirst=True)
