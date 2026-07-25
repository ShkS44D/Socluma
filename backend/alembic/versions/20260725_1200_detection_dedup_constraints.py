"""enforce one detection and alert per tenant event rule

Revision ID: 20260725_1200
Revises: 20260721_1200
"""

from alembic import op
import sqlalchemy as sa

revision = "20260725_1200"
down_revision = "20260721_1200"
branch_labels = None
depends_on = None


def _reject_duplicates(bind, table_name: str) -> None:
    table = sa.table(
        table_name,
        sa.column("id", sa.String),
        sa.column("tenant_id", sa.String),
        sa.column("event_id", sa.String),
        sa.column("rule_id" if table_name == "detection_matches" else "detection_rule_id", sa.String),
    )
    rule_column = table.c.rule_id if table_name == "detection_matches" else table.c.detection_rule_id
    duplicates = bind.execute(
        sa.select(table.c.tenant_id, table.c.event_id, rule_column, sa.func.count())
        .where(table.c.event_id.is_not(None), rule_column.is_not(None))
        .group_by(table.c.tenant_id, table.c.event_id, rule_column)
        .having(sa.func.count() > 1)
    ).all()
    if duplicates:
        raise RuntimeError(
            f"Cannot add detection deduplication constraint: {table_name} contains "
            f"{len(duplicates)} duplicate tenant/event/rule group(s)"
        )


def upgrade() -> None:
    bind = op.get_bind()
    _reject_duplicates(bind, "detection_matches")
    _reject_duplicates(bind, "alerts")
    with op.batch_alter_table("detection_matches") as batch:
        batch.create_unique_constraint(
            "uq_detection_matches_tenant_event_rule", ["tenant_id", "event_id", "rule_id"]
        )
    with op.batch_alter_table("alerts") as batch:
        batch.create_unique_constraint(
            "uq_alerts_tenant_event_rule", ["tenant_id", "event_id", "detection_rule_id"]
        )


def downgrade() -> None:
    with op.batch_alter_table("alerts") as batch:
        batch.drop_constraint("uq_alerts_tenant_event_rule", type_="unique")
    with op.batch_alter_table("detection_matches") as batch:
        batch.drop_constraint("uq_detection_matches_tenant_event_rule", type_="unique")
