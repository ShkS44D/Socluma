"""correlation-driven incidents and MITRE mappings

Revision ID: 20260717_1200
Revises: 20260715_1600
"""

from alembic import op
import sqlalchemy as sa

revision = "20260717_1200"
down_revision = "20260715_1600"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "incident_mitre_mappings" not in inspector.get_table_names():
        op.create_table(
            "incident_mitre_mappings",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("tactic", sa.String(100), nullable=False),
            sa.Column("technique_id", sa.String(50), nullable=False),
            sa.Column("technique_name", sa.String(255), nullable=False),
            sa.Column("sub_technique_id", sa.String(50), nullable=True),
            sa.Column("sub_technique_name", sa.String(255), nullable=True),
            sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
            sa.Column("confidence_reasons", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("supporting_evidence", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("source_alert_ids", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("stage_order", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.UniqueConstraint("incident_id", "technique_id", name="uq_incident_mitre_mapping"),
        )
        op.create_index("ix_incident_mitre_tenant_tactic", "incident_mitre_mappings", ["tenant_id", "tactic"])
        op.create_index("ix_incident_mitre_tenant_technique", "incident_mitre_mappings", ["tenant_id", "technique_id"])

    incident_alert_indexes = {idx["name"] for idx in inspector.get_indexes("incident_alerts")}
    if "uq_incident_alerts_incident_alert" not in incident_alert_indexes:
        op.create_index(
            "uq_incident_alerts_incident_alert",
            "incident_alerts",
            ["incident_id", "alert_id"],
            unique=True,
        )

    # Existing incidents remain readable. Their legacy JSON mapping is copied
    # only when it has a technique ID; no alert linkage is fabricated.
    bind = op.get_bind()
    incidents = sa.table(
        "incidents",
        sa.column("id", sa.String), sa.column("tenant_id", sa.String),
        sa.column("attack_technique", sa.JSON), sa.column("first_seen_at", sa.DateTime),
        sa.column("last_seen_at", sa.DateTime),
    )
    mappings = sa.table(
        "incident_mitre_mappings",
        sa.column("id", sa.String), sa.column("tenant_id", sa.String), sa.column("incident_id", sa.String),
        sa.column("tactic", sa.String), sa.column("technique_id", sa.String), sa.column("technique_name", sa.String),
        sa.column("confidence", sa.Float), sa.column("confidence_reasons", sa.JSON),
        sa.column("supporting_evidence", sa.JSON), sa.column("source_alert_ids", sa.JSON),
        sa.column("stage_order", sa.Integer), sa.column("first_seen_at", sa.DateTime), sa.column("last_seen_at", sa.DateTime),
    )
    import uuid
    for row in bind.execute(sa.select(incidents)).mappings():
        value = row["attack_technique"] or {}
        if isinstance(value, dict) and value.get("technique_id"):
            bind.execute(mappings.insert().values(
                id=str(uuid.uuid4()), tenant_id=row["tenant_id"], incident_id=row["id"],
                tactic=str(value.get("tactic") or "Unknown"), technique_id=str(value["technique_id"]),
                technique_name=str(value.get("technique_name") or value["technique_id"]), confidence=float(value.get("confidence") or 0),
                confidence_reasons=["Migrated from historical incident metadata."], supporting_evidence=[], source_alert_ids=[],
                stage_order=0, first_seen_at=row["first_seen_at"], last_seen_at=row["last_seen_at"],
            ))


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    incident_alert_indexes = {idx["name"] for idx in inspector.get_indexes("incident_alerts")}
    if "uq_incident_alerts_incident_alert" in incident_alert_indexes:
        op.drop_index("uq_incident_alerts_incident_alert", table_name="incident_alerts")
    op.drop_table("incident_mitre_mappings")
