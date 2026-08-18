"""Persist indicator types by stable enum value on every database.

Revision ID: 20260801_2000
Revises: 20260730_1950
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260801_2000"
down_revision = "20260730_1950"
branch_labels = None
depends_on = None


LEGACY_VALUES = ("ip", "domain", "url", "hash")
COLUMNS = (
    ("threat_intel_cache", "indicator_type"),
    ("threat_intel", "type"),
    ("iocs", "type"),
)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # New PostgreSQL enum labels must be committed before UPDATE can use them.
        with op.get_context().autocommit_block():
            for value in LEGACY_VALUES:
                op.execute(sa.text(f"ALTER TYPE indicatortype ADD VALUE IF NOT EXISTS '{value}'"))

    for table, column in COLUMNS:
        if bind.dialect.name == "postgresql":
            op.execute(sa.text(
                f"UPDATE {table} SET {column}=lower({column}::text)::indicatortype "
                f"WHERE {column}::text IN ('IP','DOMAIN','URL','HASH')"
            ))
        else:
            op.execute(sa.text(
                f"UPDATE {table} SET {column}=lower({column}) "
                f"WHERE {column} IN ('IP','DOMAIN','URL','HASH')"
            ))


def downgrade() -> None:
    bind = op.get_bind()
    for table, column in COLUMNS:
        if bind.dialect.name == "postgresql":
            op.execute(sa.text(
                f"UPDATE {table} SET {column}=upper({column}::text)::indicatortype "
                f"WHERE {column}::text IN ('ip','domain','url','hash')"
            ))
        else:
            op.execute(sa.text(
                f"UPDATE {table} SET {column}=upper({column}) "
                f"WHERE {column} IN ('ip','domain','url','hash')"
            ))
