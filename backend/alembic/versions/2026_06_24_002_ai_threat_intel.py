"""Add AI and threat intelligence storage

Revision ID: 20260624002
Revises: 20260624001
Create Date: 2026-06-24 00:30:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260624002"
down_revision: Union[str, None] = "20260624001"
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


def upgrade() -> None:
    bind = op.get_bind()
    created_at_default = (
        sa.text("CURRENT_TIMESTAMP")
        if bind.dialect.name == "sqlite"
        else sa.text("now()")
    )
    if "attack_technique" not in _columns("incidents"):
        op.add_column("incidents", sa.Column("attack_technique", sa.JSON(), nullable=True))

    if "threat_intel" not in _tables():
        op.create_table(
            "threat_intel",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("incident_id", sa.String(length=36), nullable=True),
            sa.Column("indicator", sa.String(length=255), nullable=False),
            sa.Column("type", sa.Enum("IP", "DOMAIN", "URL", "HASH", name="indicatortype"), nullable=False),
            sa.Column("source", sa.String(length=100), nullable=False),
            sa.Column("result", sa.JSON(), nullable=False),
            sa.Column("risk_impact", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=created_at_default, nullable=True),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
    if "ix_threat_intel_indicator" not in _indexes("threat_intel"):
        op.create_index(op.f("ix_threat_intel_indicator"), "threat_intel", ["indicator"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_threat_intel_indicator"), table_name="threat_intel")
    op.drop_table("threat_intel")
    op.drop_column("incidents", "attack_technique")
