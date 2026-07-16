"""Phase 6: Detection matches and event processing

Revision ID: 202606271700
Revises: 202606271600
Create Date: 2026-06-27 17:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "202606271700"
down_revision: Union[str, None] = "202606271500"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


rule_type_enum = postgresql.ENUM("CUSTOM", "SIGMA", name="ruletype")


def _rule_type_column_type(bind):
    if bind.dialect.name == "postgresql":
        return postgresql.ENUM("CUSTOM", "SIGMA", name="ruletype", create_type=False)
    return sa.Enum("CUSTOM", "SIGMA", name="ruletype")


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table_name not in _tables():
        return set()
    return {column["name"] for column in inspector.get_columns(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        rule_type_enum.create(bind, checkfirst=True)

    # First add columns to detection_rules table
    detection_rule_columns = _columns("detection_rules")
    if "type" not in detection_rule_columns:
        op.add_column("detection_rules", sa.Column("type", _rule_type_column_type(bind), nullable=True, server_default="CUSTOM"))
    if "sigma_rule" not in detection_rule_columns:
        op.add_column("detection_rules", sa.Column("sigma_rule", sa.Text(), nullable=True))
    
    # Now create detection_matches table
    if "detection_matches" not in _tables():
        op.create_table(
            "detection_matches",
            sa.Column("id", sa.String(36), nullable=False),
            sa.Column("tenant_id", sa.String(36), nullable=False),
            sa.Column("event_id", sa.String(36), nullable=False),
            sa.Column("rule_id", sa.String(36), nullable=False),
            sa.Column("matched", sa.Boolean(), nullable=False, server_default="1"),
            sa.Column("severity", sa.Enum("LOW", "MEDIUM", "HIGH", "CRITICAL", name="severity"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=True),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_detection_matches_tenant_id_tenants"),
            sa.ForeignKeyConstraint(["event_id"], ["security_events.id"], name="fk_detection_matches_event_id_security_events"),
            sa.ForeignKeyConstraint(["rule_id"], ["detection_rules.id"], name="fk_detection_matches_rule_id_detection_rules"),
            sa.PrimaryKeyConstraint("id"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    op.drop_table("detection_matches")
    op.drop_column("detection_rules", "sigma_rule")
    op.drop_column("detection_rules", "type")
    if bind.dialect.name == "postgresql":
        rule_type_enum.drop(bind, checkfirst=True)
