"""add authoritative MITRE ATT&CK catalog metadata

Revision ID: 20260721_1200
Revises: 20260718_1200
"""

from alembic import op
import sqlalchemy as sa

revision = "20260721_1200"
down_revision = "20260718_1200"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("mitre_techniques") as batch:
        batch.add_column(sa.Column("tactic_id", sa.String(64), nullable=True))
        batch.add_column(sa.Column("tactic_order", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("tactics", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))
        batch.add_column(sa.Column("parent_technique_id", sa.String(50), nullable=True))
        batch.add_column(sa.Column("parent_technique_name", sa.String(255), nullable=True))
        batch.add_column(sa.Column("sub_technique_id", sa.String(50), nullable=True))
        batch.add_column(sa.Column("sub_technique_name", sa.String(255), nullable=True))
        batch.add_column(sa.Column("is_subtechnique", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("is_deprecated", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("catalog_version", sa.String(32), nullable=True))
        batch.add_column(sa.Column("catalog_source", sa.String(255), nullable=True))
        batch.add_column(sa.Column("external_url", sa.String(1024), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("mitre_techniques") as batch:
        for name in ("external_url", "catalog_source", "catalog_version", "is_deprecated", "is_revoked", "is_subtechnique",
                     "sub_technique_name", "sub_technique_id", "parent_technique_name", "parent_technique_id", "tactics",
                     "tactic_order", "tactic_id"):
            batch.drop_column(name)
