"""Phase 4: IOC, Detection Rules, Comments, Notifications

Revision ID: 202606271400
Revises: 202606271300
Create Date: 2026-06-27 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "202606271400"
down_revision: Union[str, None] = "202606271300"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    if "iocs" not in _tables():
        op.create_table(
            "iocs",
            sa.Column("id", sa.String(36), nullable=False),
            sa.Column("tenant_id", sa.String(36), nullable=False),
            sa.Column("type", sa.Enum("IP", "DOMAIN", "URL", "HASH", name="indicatortype"), nullable=False),
            sa.Column("value", sa.String(1024), nullable=False, index=True),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("source", sa.String(255), nullable=True),
            sa.Column("severity", sa.Enum("LOW", "MEDIUM", "HIGH", "CRITICAL", name="severity"), nullable=True, server_default="MEDIUM"),
            sa.Column("is_active", sa.Boolean(), nullable=True, server_default="1"),
            sa.Column("created_by", sa.String(36), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=True),
            sa.ForeignKeyConstraint(["created_by"], ["users.id"], name="fk_iocs_created_by_users"),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_iocs_tenant_id_tenants"),
            sa.PrimaryKeyConstraint("id"),
        )
    if "detection_rules" not in _tables():
        op.create_table(
            "detection_rules",
            sa.Column("id", sa.String(36), nullable=False),
            sa.Column("tenant_id", sa.String(36), nullable=False),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("severity", sa.Enum("LOW", "MEDIUM", "HIGH", "CRITICAL", name="severity"), nullable=True, server_default="MEDIUM"),
            sa.Column("query", sa.Text(), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=True, server_default="1"),
            sa.Column("created_by", sa.String(36), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=True),
            sa.ForeignKeyConstraint(["created_by"], ["users.id"], name="fk_detection_rules_created_by_users"),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_detection_rules_tenant_id_tenants"),
            sa.PrimaryKeyConstraint("id"),
        )
    if "incident_comments" not in _tables():
        op.create_table(
            "incident_comments",
            sa.Column("id", sa.String(36), nullable=False),
            sa.Column("tenant_id", sa.String(36), nullable=False),
            sa.Column("incident_id", sa.String(36), nullable=False),
            sa.Column("user_id", sa.String(36), nullable=False),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=True),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], name="fk_incident_comments_incident_id_incidents"),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_incident_comments_tenant_id_tenants"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], name="fk_incident_comments_user_id_users"),
            sa.PrimaryKeyConstraint("id"),
        )
    if "notifications" not in _tables():
        op.create_table(
            "notifications",
            sa.Column("id", sa.String(36), nullable=False),
            sa.Column("tenant_id", sa.String(36), nullable=False),
            sa.Column("user_id", sa.String(36), nullable=False),
            sa.Column("title", sa.String(255), nullable=False),
            sa.Column("message", sa.Text(), nullable=True),
            sa.Column("type", sa.Enum("INFO", "WARNING", "ERROR", "ALERT", name="notificationtype"), nullable=True, server_default="INFO"),
            sa.Column("is_read", sa.Boolean(), nullable=True, server_default="0", index=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=True),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_notifications_tenant_id_tenants"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], name="fk_notifications_user_id_users"),
            sa.PrimaryKeyConstraint("id"),
        )


def downgrade() -> None:
    op.drop_table("notifications")
    op.drop_table("incident_comments")
    op.drop_table("detection_rules")
    op.drop_table("iocs")
    op.execute("DROP TYPE IF EXISTS notificationtype")
