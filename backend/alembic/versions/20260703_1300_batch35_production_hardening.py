"""batch35 production hardening

Revision ID: 20260703_1300
Revises: 20260703_1200
Create Date: 2026-07-03 13:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260703_1300"
down_revision: Union[str, None] = "20260703_1200"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table_name not in set(inspector.get_table_names()):
        return set()
    return {column["name"] for column in inspector.get_columns(table_name)}


def _indexes(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table_name not in set(inspector.get_table_names()):
        return set()
    return {index["name"] for index in inspector.get_indexes(table_name)}


def _create_index_if_missing(name: str, table: str, columns: list[str], unique: bool = False) -> None:
    if table in _tables() and name not in _indexes(table):
        op.create_index(name, table, columns, unique=unique)


def upgrade() -> None:
    if "collectors" in _tables() and "token_lookup_hash" not in _columns("collectors"):
        with op.batch_alter_table("collectors") as batch_op:
            batch_op.add_column(sa.Column("token_lookup_hash", sa.String(length=64), nullable=True))
        _create_index_if_missing("ix_collectors_token_lookup_hash", "collectors", ["token_lookup_hash"], unique=True)

    _create_index_if_missing("ix_alerts_tenant_created_at", "alerts", ["tenant_id", "created_at"])
    _create_index_if_missing("ix_alerts_tenant_severity", "alerts", ["tenant_id", "severity"])
    _create_index_if_missing("ix_alerts_tenant_status", "alerts", ["tenant_id", "status"])
    _create_index_if_missing("ix_alerts_incident_id", "alerts", ["incident_id"])
    _create_index_if_missing("ix_alerts_event_id", "alerts", ["event_id"])
    _create_index_if_missing("ix_incidents_tenant_created_at", "incidents", ["tenant_id", "created_at"])
    _create_index_if_missing("ix_incidents_tenant_severity", "incidents", ["tenant_id", "severity"])
    _create_index_if_missing("ix_incidents_tenant_status", "incidents", ["tenant_id", "status"])
    _create_index_if_missing("ix_security_events_tenant_created_at", "security_events", ["tenant_id", "created_at"])
    _create_index_if_missing("ix_security_events_tenant_severity", "security_events", ["tenant_id", "severity"])
    _create_index_if_missing("ix_security_events_tenant_event_type", "security_events", ["tenant_id", "event_type"])
    _create_index_if_missing("ix_collectors_tenant_status", "collectors", ["tenant_id", "status"])
    _create_index_if_missing("ix_collectors_tenant_last_seen", "collectors", ["tenant_id", "last_seen"])
    _create_index_if_missing("ix_detection_matches_event_id", "detection_matches", ["event_id"])
    _create_index_if_missing("ix_detection_matches_alert_id", "detection_matches", ["alert_id"])


def downgrade() -> None:
    for name, table in (
        ("ix_detection_matches_alert_id", "detection_matches"),
        ("ix_detection_matches_event_id", "detection_matches"),
        ("ix_collectors_tenant_last_seen", "collectors"),
        ("ix_collectors_tenant_status", "collectors"),
        ("ix_security_events_tenant_event_type", "security_events"),
        ("ix_security_events_tenant_severity", "security_events"),
        ("ix_security_events_tenant_created_at", "security_events"),
        ("ix_incidents_tenant_status", "incidents"),
        ("ix_incidents_tenant_severity", "incidents"),
        ("ix_incidents_tenant_created_at", "incidents"),
        ("ix_alerts_event_id", "alerts"),
        ("ix_alerts_incident_id", "alerts"),
        ("ix_alerts_tenant_status", "alerts"),
        ("ix_alerts_tenant_severity", "alerts"),
        ("ix_alerts_tenant_created_at", "alerts"),
        ("ix_collectors_token_lookup_hash", "collectors"),
    ):
        if table in _tables() and name in _indexes(table):
            op.drop_index(name, table_name=table)

    if "collectors" in _tables() and "token_lookup_hash" in _columns("collectors"):
        with op.batch_alter_table("collectors") as batch_op:
            batch_op.drop_column("token_lookup_hash")
