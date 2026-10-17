"""incident workflow fields

Revision ID: 202606271200
Revises: 202606251800
Create Date: 2026-06-27 12:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "202606271200"
down_revision: Union[str, None] = "202606251800"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    created_at_default = (
        sa.text("CURRENT_TIMESTAMP")
        if bind.dialect.name == "sqlite"
        else sa.text("now()")
    )

    incident_columns = {column["name"] for column in inspector.get_columns("incidents")}
    with op.batch_alter_table("incidents") as batch_op:
        if "assigned_to" not in incident_columns:
            batch_op.add_column(sa.Column("assigned_to", sa.String(length=36), nullable=True))
            batch_op.create_foreign_key(
                "fk_incidents_assigned_to_users",
                "users",
                ["assigned_to"],
                ["id"],
            )
        if "assigned_at" not in incident_columns:
            batch_op.add_column(sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=True))

    existing_incident_indexes = {index["name"] for index in inspector.get_indexes("incidents")}
    assigned_index_name = op.f("ix_incidents_assigned_to")
    if assigned_index_name not in existing_incident_indexes:
        op.create_index(assigned_index_name, "incidents", ["assigned_to"], unique=False)

    note_columns = {column["name"] for column in inspector.get_columns("investigation_notes")}
    if "updated_at" not in note_columns:
        with op.batch_alter_table("investigation_notes") as batch_op:
            batch_op.add_column(
                sa.Column(
                    "updated_at",
                    sa.DateTime(timezone=True),
                    nullable=True,
                    server_default=created_at_default,
                )
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    note_columns = {column["name"] for column in inspector.get_columns("investigation_notes")}
    if "updated_at" in note_columns:
        with op.batch_alter_table("investigation_notes") as batch_op:
            batch_op.drop_column("updated_at")

    incident_columns = {column["name"] for column in inspector.get_columns("incidents")}
    existing_incident_indexes = {index["name"] for index in inspector.get_indexes("incidents")}
    assigned_index_name = op.f("ix_incidents_assigned_to")
    if assigned_index_name in existing_incident_indexes:
        op.drop_index(assigned_index_name, table_name="incidents")

    with op.batch_alter_table("incidents") as batch_op:
        if "assigned_to" in incident_columns:
            try:
                batch_op.drop_constraint("fk_incidents_assigned_to_users", type_="foreignkey")
            except Exception:
                pass
            batch_op.drop_column("assigned_to")
        if "assigned_at" in incident_columns:
            batch_op.drop_column("assigned_at")
