"""label recorded and legacy incident provenance

Revision ID: 20260715_1600
Revises: 20260715_1500
Create Date: 2026-07-15 16:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260715_1600"
down_revision: Union[str, None] = "20260715_1500"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns() -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns("incidents")}


def upgrade() -> None:
    if "provenance_status" not in _columns():
        with op.batch_alter_table("incidents") as batch:
            batch.add_column(
                sa.Column(
                    "provenance_status",
                    sa.String(length=32),
                    nullable=False,
                    server_default="legacy_derived",
                )
            )
            batch.alter_column("creation_source", server_default="manual")

    evidence_columns = {
        column["name"]: column
        for column in sa.inspect(op.get_bind()).get_columns("incident_evidence")
    }
    user_id = evidence_columns.get("user_id")
    if user_id and not user_id.get("nullable", True):
        with op.batch_alter_table("incident_evidence") as batch:
            batch.alter_column(
                "user_id",
                existing_type=sa.String(length=36),
                nullable=True,
            )


def downgrade() -> None:
    if "provenance_status" in _columns():
        with op.batch_alter_table("incidents") as batch:
            batch.alter_column("creation_source", server_default="detection_engine")
            batch.drop_column("provenance_status")
