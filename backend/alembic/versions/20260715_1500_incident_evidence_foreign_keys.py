"""enforce incident evidence lineage foreign keys

Revision ID: 20260715_1500
Revises: 20260715_1400
Create Date: 2026-07-15 15:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260715_1500"
down_revision: Union[str, None] = "20260715_1400"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


LINEAGE_FOREIGN_KEYS = (
    ("fk_incident_evidence_tenant_id_tenants", "tenants", ["tenant_id"], ["id"]),
    ("fk_incident_evidence_source_event_id_security_events", "security_events", ["source_event_id"], ["id"]),
    ("fk_incident_evidence_source_alert_id_alerts", "alerts", ["source_alert_id"], ["id"]),
    ("fk_incident_evidence_source_entity_id_incident_entities", "incident_entities", ["source_entity_id"], ["id"]),
)


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "incident_evidence" not in inspector.get_table_names():
        return
    existing_columns = {
        tuple(item.get("constrained_columns") or [])
        for item in inspector.get_foreign_keys("incident_evidence")
    }
    with op.batch_alter_table("incident_evidence") as batch:
        for name, referent, local_columns, remote_columns in LINEAGE_FOREIGN_KEYS:
            if tuple(local_columns) not in existing_columns:
                batch.create_foreign_key(name, referent, local_columns, remote_columns)


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "incident_evidence" not in inspector.get_table_names():
        return
    existing_names = {
        item.get("name")
        for item in inspector.get_foreign_keys("incident_evidence")
        if item.get("name")
    }
    with op.batch_alter_table("incident_evidence") as batch:
        for name, _, _, _ in LINEAGE_FOREIGN_KEYS:
            if name in existing_names:
                batch.drop_constraint(name, type_="foreignkey")
