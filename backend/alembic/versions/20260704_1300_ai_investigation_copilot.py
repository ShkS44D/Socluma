"""ai investigation copilot

Revision ID: 20260704_1300
Revises: 20260704_1200
Create Date: 2026-07-04 13:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260704_1300"
down_revision: Union[str, None] = "20260704_1200"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _indexes(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table_name not in _tables():
        return set()
    return {index["name"] for index in inspector.get_indexes(table_name)}


def _create_index_if_missing(name: str, table: str, columns: list[str], unique: bool = False) -> None:
    if table in _tables() and name not in _indexes(table):
        op.create_index(name, table, columns, unique=unique)


def upgrade() -> None:
    if "ai_investigation_artifacts" not in _tables():
        op.create_table(
            "ai_investigation_artifacts",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("incident_id", sa.String(length=36), sa.ForeignKey("incidents.id"), nullable=True),
            sa.Column("alert_id", sa.String(length=36), sa.ForeignKey("alerts.id"), nullable=True),
            sa.Column("ioc_id", sa.String(length=36), sa.ForeignKey("iocs.id"), nullable=True),
            sa.Column("artifact_type", sa.String(length=64), nullable=False),
            sa.Column("prompt_hash", sa.String(length=64), nullable=False),
            sa.Column("model", sa.String(length=100), nullable=False),
            sa.Column("content", sa.JSON(), nullable=False),
            sa.Column("confidence_score", sa.Float(), nullable=True),
            sa.Column("created_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    _create_index_if_missing("ix_ai_artifacts_tenant_type_created_at", "ai_investigation_artifacts", ["tenant_id", "artifact_type", "created_at"])
    _create_index_if_missing("ix_ai_artifacts_incident_type_created_at", "ai_investigation_artifacts", ["incident_id", "artifact_type", "created_at"])
    _create_index_if_missing("ix_ai_artifacts_alert_type_created_at", "ai_investigation_artifacts", ["alert_id", "artifact_type", "created_at"])
    _create_index_if_missing("ix_ai_artifacts_ioc_type_created_at", "ai_investigation_artifacts", ["ioc_id", "artifact_type", "created_at"])
    _create_index_if_missing("ix_ai_investigation_artifacts_prompt_hash", "ai_investigation_artifacts", ["prompt_hash"])

    if "ai_investigation_conversations" not in _tables():
        op.create_table(
            "ai_investigation_conversations",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("incident_id", sa.String(length=36), sa.ForeignKey("incidents.id"), nullable=False),
            sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("title", sa.String(length=255), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    _create_index_if_missing("ix_ai_conversations_tenant_incident_created_at", "ai_investigation_conversations", ["tenant_id", "incident_id", "created_at"])

    if "ai_investigation_messages" not in _tables():
        op.create_table(
            "ai_investigation_messages",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("conversation_id", sa.String(length=36), sa.ForeignKey("ai_investigation_conversations.id"), nullable=False),
            sa.Column("role", sa.String(length=20), nullable=False),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column("message_metadata", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    _create_index_if_missing("ix_ai_messages_conversation_created_at", "ai_investigation_messages", ["conversation_id", "created_at"])
    _create_index_if_missing("ix_ai_messages_tenant_created_at", "ai_investigation_messages", ["tenant_id", "created_at"])


def downgrade() -> None:
    for table in ("ai_investigation_messages", "ai_investigation_conversations", "ai_investigation_artifacts"):
        if table in _tables():
            op.drop_table(table)
