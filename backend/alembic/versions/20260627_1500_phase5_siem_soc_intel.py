"""Phase 5: SIEM Integration & Advanced SOC Intelligence

Revision ID: 202606271500
Revises: 202606271400
Create Date: 2026-06-27 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "202606271500"
down_revision: Union[str, None] = "202606271400"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    if "security_events" not in _tables():
        op.create_table(
            "security_events",
            sa.Column("id", sa.String(36), nullable=False),
            sa.Column("tenant_id", sa.String(36), nullable=False),
            sa.Column("source", sa.String(255), nullable=False),
            sa.Column("event_type", sa.Enum("LOGIN", "LOGOUT", "FILE", "NETWORK", "PROCESS", "ALERT", "USER_CREATION", name="eventtype"), nullable=False),
            sa.Column("raw_event", sa.JSON(), nullable=False),
            sa.Column("normalized_event", sa.JSON(), nullable=False),
            sa.Column("severity", sa.Enum("LOW", "MEDIUM", "HIGH", "CRITICAL", name="severity"), nullable=True, server_default="MEDIUM"),
            sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
            sa.Column("processed", sa.Boolean(), nullable=True, server_default="0"),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=True),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_security_events_tenant_id_tenants"),
            sa.PrimaryKeyConstraint("id"),
        )
    if "assets" not in _tables():
        op.create_table(
            "assets",
            sa.Column("id", sa.String(36), nullable=False),
            sa.Column("tenant_id", sa.String(36), nullable=False),
            sa.Column("hostname", sa.String(255), nullable=False),
            sa.Column("ip_address", sa.String(50), nullable=True),
            sa.Column("operating_system", sa.String(255), nullable=True),
            sa.Column("owner", sa.String(255), nullable=True),
            sa.Column("criticality", sa.Enum("LOW", "MEDIUM", "HIGH", "CRITICAL", name="assetcriticality"), nullable=True, server_default="MEDIUM"),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=True),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_assets_tenant_id_tenants"),
            sa.PrimaryKeyConstraint("id"),
        )
    if "mitre_techniques" not in _tables():
        op.create_table(
            "mitre_techniques",
            sa.Column("id", sa.String(36), nullable=False),
            sa.Column("technique_id", sa.String(50), nullable=False, index=True),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("tactic", sa.Enum(
                "Reconnaissance",
                "Resource Development",
                "Initial Access",
                "Execution",
                "Persistence",
                "Privilege Escalation",
                "Defense Evasion",
                "Credential Access",
                "Discovery",
                "Lateral Movement",
                "Collection",
                "Command and Control",
                "Exfiltration",
                "Impact",
                name="mitretactic"
            ), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
    if "response_actions" not in _tables():
        op.create_table(
            "response_actions",
            sa.Column("id", sa.String(36), nullable=False),
            sa.Column("tenant_id", sa.String(36), nullable=False),
            sa.Column("incident_id", sa.String(36), nullable=False),
            sa.Column("action_type", sa.Enum("isolate_host", "block_ip", "close_incident", "escalate_incident", name="actiontype"), nullable=False),
            sa.Column("status", sa.Enum("pending", "running", "completed", "failed", name="actionstatus"), nullable=True, server_default="pending"),
            sa.Column("executed_by", sa.String(36), nullable=True),
            sa.Column("details", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=True),
            sa.ForeignKeyConstraint(["executed_by"], ["users.id"], name="fk_response_actions_executed_by_users"),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], name="fk_response_actions_incident_id_incidents"),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_response_actions_tenant_id_tenants"),
            sa.PrimaryKeyConstraint("id"),
        )


def downgrade() -> None:
    op.drop_table("response_actions")
    op.drop_table("mitre_techniques")
    op.drop_table("assets")
    op.drop_table("security_events")
    op.execute("DROP TYPE IF EXISTS actionstatus")
    op.execute("DROP TYPE IF EXISTS actiontype")
    op.execute("DROP TYPE IF EXISTS mitretactic")
    op.execute("DROP TYPE IF EXISTS assetcriticality")
    op.execute("DROP TYPE IF EXISTS eventtype")
