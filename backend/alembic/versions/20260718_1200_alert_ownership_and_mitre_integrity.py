"""enforce alert ownership and enrich incident MITRE mappings

Revision ID: 20260718_1200
Revises: 20260717_1200
"""

from __future__ import annotations

import uuid

from alembic import op
import sqlalchemy as sa


revision = "20260718_1200"
down_revision = "20260717_1200"
branch_labels = None
depends_on = None


def _preflight_and_reconcile_unambiguous_ownership(bind) -> None:
    alerts = sa.table(
        "alerts",
        sa.column("id", sa.String),
        sa.column("tenant_id", sa.String),
        sa.column("incident_id", sa.String),
    )
    links = sa.table(
        "incident_alerts",
        sa.column("id", sa.String),
        sa.column("incident_id", sa.String),
        sa.column("alert_id", sa.String),
        sa.column("correlation_score", sa.Float),
        sa.column("correlation_reason", sa.Text),
        sa.column("is_primary", sa.Boolean),
        sa.column("sequence_order", sa.Integer),
    )
    incidents = sa.table(
        "incidents",
        sa.column("id", sa.String),
        sa.column("tenant_id", sa.String),
    )

    duplicate_owners = bind.execute(
        sa.select(links.c.alert_id, sa.func.count(sa.distinct(links.c.incident_id)).label("owner_count"))
        .group_by(links.c.alert_id)
        .having(sa.func.count(sa.distinct(links.c.incident_id)) > 1)
    ).mappings().all()
    if duplicate_owners:
        sample = ", ".join(row["alert_id"] for row in duplicate_owners[:5])
        raise RuntimeError(
            "Cannot enforce one-alert/one-incident ownership: alerts linked to multiple incidents: " + sample
        )

    disagreements = bind.execute(
        sa.select(alerts.c.id)
        .join(links, links.c.alert_id == alerts.c.id)
        .where(alerts.c.incident_id.is_not(None), alerts.c.incident_id != links.c.incident_id)
    ).scalars().all()
    if disagreements:
        raise RuntimeError(
            "Cannot enforce alert ownership because alerts.incident_id disagrees with incident_alerts: "
            + ", ".join(disagreements[:5])
        )

    tenant_conflicts = bind.execute(
        sa.select(alerts.c.id)
        .join(links, links.c.alert_id == alerts.c.id)
        .join(incidents, incidents.c.id == links.c.incident_id)
        .where(alerts.c.tenant_id != incidents.c.tenant_id)
    ).scalars().all()
    if tenant_conflicts:
        raise RuntimeError(
            "Cannot enforce alert ownership because linked alerts and incidents cross tenant scope: "
            + ", ".join(tenant_conflicts[:5])
        )

    linked_incidents = incidents.alias("linked_incidents")
    missing_link_owners = bind.execute(
        sa.select(links.c.alert_id)
        .outerjoin(linked_incidents, linked_incidents.c.id == links.c.incident_id)
        .where(linked_incidents.c.id.is_(None))
    ).scalars().all()
    direct_incidents = incidents.alias("direct_incidents")
    missing_direct_owners = bind.execute(
        sa.select(alerts.c.id)
        .outerjoin(direct_incidents, direct_incidents.c.id == alerts.c.incident_id)
        .where(alerts.c.incident_id.is_not(None), direct_incidents.c.id.is_(None))
    ).scalars().all()
    missing_owners = list(dict.fromkeys([*missing_link_owners, *missing_direct_owners]))
    if missing_owners:
        raise RuntimeError(
            "Cannot enforce alert ownership because an owned incident is missing: "
            + ", ".join(missing_owners[:5])
        )

    # These two historical shapes have only one possible owner. Reconcile them
    # explicitly without deleting, moving, or inventing source evidence.
    link_only = bind.execute(
        sa.select(alerts.c.id, links.c.incident_id)
        .join(links, links.c.alert_id == alerts.c.id)
        .where(alerts.c.incident_id.is_(None))
    ).mappings().all()
    for row in link_only:
        bind.execute(alerts.update().where(alerts.c.id == row["id"]).values(incident_id=row["incident_id"]))

    direct_only = bind.execute(
        sa.select(alerts.c.id, alerts.c.incident_id)
        .outerjoin(links, links.c.alert_id == alerts.c.id)
        .where(alerts.c.incident_id.is_not(None), links.c.alert_id.is_(None))
    ).mappings().all()
    for row in direct_only:
        bind.execute(links.insert().values(
            id=str(uuid.uuid4()),
            incident_id=row["incident_id"],
            alert_id=row["id"],
            correlation_score=0,
            correlation_reason="Historical direct ownership backfilled during integrity migration",
            is_primary=False,
            sequence_order=0,
        ))


def upgrade() -> None:
    bind = op.get_bind()
    _preflight_and_reconcile_unambiguous_ownership(bind)
    inspector = sa.inspect(bind)

    incident_alert_indexes = {item["name"] for item in inspector.get_indexes("incident_alerts")}
    incident_alert_constraints = {item["name"] for item in inspector.get_unique_constraints("incident_alerts")}
    if "uq_incident_alerts_alert_id" not in incident_alert_indexes | incident_alert_constraints:
        op.create_index("uq_incident_alerts_alert_id", "incident_alerts", ["alert_id"], unique=True)

    alert_indexes = {item["name"] for item in inspector.get_indexes("alerts")}
    if "ix_alerts_correlation_candidates" not in alert_indexes:
        op.create_index(
            "ix_alerts_correlation_candidates",
            "alerts",
            ["tenant_id", "incident_id", "status", "created_at"],
        )
    if "ix_alerts_tenant_event_id" not in alert_indexes:
        op.create_index("ix_alerts_tenant_event_id", "alerts", ["tenant_id", "event_id"])

    mapping_columns = {item["name"] for item in inspector.get_columns("incident_mitre_mappings")}
    with op.batch_alter_table("incident_mitre_mappings") as batch:
        if "parent_technique_id" not in mapping_columns:
            batch.add_column(sa.Column("parent_technique_id", sa.String(50), nullable=False, server_default=""))
        if "parent_technique_name" not in mapping_columns:
            batch.add_column(sa.Column("parent_technique_name", sa.String(255), nullable=False, server_default=""))
        if "mapping_source" not in mapping_columns:
            batch.add_column(sa.Column("mapping_source", sa.String(32), nullable=False, server_default="correlated"))

    mappings = sa.table(
        "incident_mitre_mappings",
        sa.column("id", sa.String),
        sa.column("technique_id", sa.String),
        sa.column("technique_name", sa.String),
        sa.column("sub_technique_id", sa.String),
        sa.column("source_alert_ids", sa.JSON),
        sa.column("parent_technique_id", sa.String),
        sa.column("parent_technique_name", sa.String),
        sa.column("mapping_source", sa.String),
    )
    techniques = sa.table(
        "mitre_techniques",
        sa.column("technique_id", sa.String),
        sa.column("name", sa.String),
    )
    technique_names = dict(bind.execute(sa.select(techniques.c.technique_id, techniques.c.name)).all())
    for row in bind.execute(sa.select(mappings)).mappings():
        full_id = str(row["sub_technique_id"] or row["technique_id"])
        parent_id = full_id.split(".", 1)[0]
        parent_name = technique_names.get(parent_id) or (
            row["technique_name"] if full_id == parent_id else parent_id
        )
        source_ids = row["source_alert_ids"] if isinstance(row["source_alert_ids"], list) else []
        bind.execute(mappings.update().where(mappings.c.id == row["id"]).values(
            parent_technique_id=parent_id,
            parent_technique_name=parent_name,
            mapping_source="correlated" if source_ids else "legacy-derived",
        ))


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    incident_alert_indexes = {item["name"] for item in inspector.get_indexes("incident_alerts")}
    if "uq_incident_alerts_alert_id" in incident_alert_indexes:
        op.drop_index("uq_incident_alerts_alert_id", table_name="incident_alerts")
    alert_indexes = {item["name"] for item in inspector.get_indexes("alerts")}
    if "ix_alerts_tenant_event_id" in alert_indexes:
        op.drop_index("ix_alerts_tenant_event_id", table_name="alerts")
    if "ix_alerts_correlation_candidates" in alert_indexes:
        op.drop_index("ix_alerts_correlation_candidates", table_name="alerts")
    mapping_columns = {item["name"] for item in inspector.get_columns("incident_mitre_mappings")}
    with op.batch_alter_table("incident_mitre_mappings") as batch:
        for name in ("mapping_source", "parent_technique_name", "parent_technique_id"):
            if name in mapping_columns:
                batch.drop_column(name)
