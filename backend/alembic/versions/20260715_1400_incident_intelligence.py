"""incident intelligence provenance and evidence

Revision ID: 20260715_1400
Revises: 20260704_1300
Create Date: 2026-07-15 14:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260715_1400"
down_revision: Union[str, None] = "20260704_1300"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table_name: str) -> set[str]:
    if table_name not in _tables():
        return set()
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def _indexes(table_name: str) -> set[str]:
    if table_name not in _tables():
        return set()
    return {index["name"] for index in sa.inspect(op.get_bind()).get_indexes(table_name)}


def _add_columns(table_name: str, columns: list[sa.Column]) -> None:
    existing = _columns(table_name)
    with op.batch_alter_table(table_name) as batch:
        for column in columns:
            if column.name not in existing:
                batch.add_column(column)


def _create_index(name: str, table: str, columns: list[str]) -> None:
    if table in _tables() and name not in _indexes(table):
        op.create_index(name, table, columns, unique=False)


def upgrade() -> None:
    _add_columns(
        "incidents",
        [
            sa.Column("creation_source", sa.String(length=64), nullable=False, server_default="detection_engine"),
            sa.Column("creation_reason", sa.Text(), nullable=True),
            sa.Column("primary_alert_id", sa.String(length=36), nullable=True),
            sa.Column("correlation_rule_id", sa.String(length=36), nullable=True),
            sa.Column("correlation_rule_name", sa.String(length=255), nullable=True),
            sa.Column("correlation_key", sa.String(length=255), nullable=True),
            sa.Column("correlation_score", sa.Float(), nullable=True),
            sa.Column("correlation_window_start", sa.DateTime(timezone=True), nullable=True),
            sa.Column("correlation_window_end", sa.DateTime(timezone=True), nullable=True),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("risk_score_breakdown", sa.JSON(), nullable=True),
            sa.Column("severity_reason", sa.Text(), nullable=True),
            sa.Column("attack_summary", sa.Text(), nullable=True),
            sa.Column("status_reason", sa.Text(), nullable=True),
        ],
    )
    _create_index("ix_incidents_tenant_first_seen", "incidents", ["tenant_id", "first_seen_at"])
    _create_index("ix_incidents_tenant_last_seen", "incidents", ["tenant_id", "last_seen_at"])
    _create_index("ix_incidents_primary_alert", "incidents", ["primary_alert_id"])

    _add_columns(
        "incident_alerts",
        [
            sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("attachment_reason", sa.Text(), nullable=True),
            sa.Column("sequence_order", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("risk_contribution", sa.Float(), nullable=True),
            sa.Column("matching_entities", sa.JSON(), nullable=True),
            sa.Column("matching_indicators", sa.JSON(), nullable=True),
            sa.Column("time_delta_seconds", sa.Float(), nullable=True),
        ],
    )
    _create_index("ix_incident_alerts_incident_sequence", "incident_alerts", ["incident_id", "sequence_order"])
    _create_index("ix_incident_alerts_incident_primary", "incident_alerts", ["incident_id", "is_primary"])

    if "incident_entities" not in _tables():
        op.create_table(
            "incident_entities",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("incident_id", sa.String(length=36), sa.ForeignKey("incidents.id"), nullable=False),
            sa.Column("entity_type", sa.String(length=40), nullable=False),
            sa.Column("value", sa.String(length=2048), nullable=False),
            sa.Column("normalized_value", sa.String(length=2048), nullable=False),
            sa.Column("role", sa.String(length=80), nullable=True),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("source_event_id", sa.String(length=36), sa.ForeignKey("security_events.id"), nullable=True),
            sa.Column("source_alert_id", sa.String(length=36), sa.ForeignKey("alerts.id"), nullable=True),
            sa.Column("confidence", sa.Float(), nullable=True),
            sa.Column("risk_contribution", sa.Float(), nullable=True),
            sa.Column("entity_metadata", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    _create_index("ix_incident_entities_tenant_incident", "incident_entities", ["tenant_id", "incident_id"])
    _create_index("ix_incident_entities_incident_type", "incident_entities", ["incident_id", "entity_type"])
    _create_index("ix_incident_entities_source_event", "incident_entities", ["source_event_id"])
    _create_index("ix_incident_entities_source_alert", "incident_entities", ["source_alert_id"])

    _add_columns(
        "incident_evidence",
        [
            sa.Column("tenant_id", sa.String(length=36), nullable=True),
            sa.Column("source_event_id", sa.String(length=36), nullable=True),
            sa.Column("source_alert_id", sa.String(length=36), nullable=True),
            sa.Column("source_entity_id", sa.String(length=36), nullable=True),
            sa.Column("confidence", sa.Float(), nullable=True),
            sa.Column("risk_contribution", sa.Float(), nullable=True),
            sa.Column("evidence_metadata", sa.JSON(), nullable=True),
        ],
    )
    op.execute(
        "UPDATE incident_evidence SET tenant_id = "
        "(SELECT incidents.tenant_id FROM incidents WHERE incidents.id = incident_evidence.incident_id) "
        "WHERE tenant_id IS NULL"
    )
    _create_index("ix_incident_evidence_tenant_incident", "incident_evidence", ["tenant_id", "incident_id"])
    _create_index("ix_incident_evidence_source_event", "incident_evidence", ["source_event_id"])
    _create_index("ix_incident_evidence_source_alert", "incident_evidence", ["source_alert_id"])


def downgrade() -> None:
    evidence_columns = {
        "tenant_id", "source_event_id", "source_alert_id", "source_entity_id",
        "confidence", "risk_contribution", "evidence_metadata",
    }
    if "incident_evidence" in _tables():
        with op.batch_alter_table("incident_evidence") as batch:
            for name in evidence_columns & _columns("incident_evidence"):
                batch.drop_column(name)

    if "incident_entities" in _tables():
        op.drop_table("incident_entities")

    link_columns = {
        "is_primary", "attachment_reason", "sequence_order", "risk_contribution",
        "matching_entities", "matching_indicators", "time_delta_seconds",
    }
    if "incident_alerts" in _tables():
        with op.batch_alter_table("incident_alerts") as batch:
            for name in link_columns & _columns("incident_alerts"):
                batch.drop_column(name)

    incident_columns = {
        "creation_source", "creation_reason", "primary_alert_id", "correlation_rule_id",
        "correlation_rule_name", "correlation_key", "correlation_score",
        "correlation_window_start", "correlation_window_end", "first_seen_at",
        "last_seen_at", "risk_score_breakdown", "severity_reason", "attack_summary",
        "status_reason",
    }
    if "incidents" in _tables():
        with op.batch_alter_table("incidents") as batch:
            for name in incident_columns & _columns("incidents"):
                batch.drop_column(name)
