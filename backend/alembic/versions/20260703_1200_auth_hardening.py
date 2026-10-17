"""auth hardening

Revision ID: 20260703_1200
Revises: 20260629_1300
Create Date: 2026-07-03 12:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260703_1200"
down_revision: Union[str, None] = "20260629_1300"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _created_at_default() -> sa.TextClause:
    bind = op.get_bind()
    return sa.text("CURRENT_TIMESTAMP") if bind.dialect.name == "sqlite" else sa.text("now()")


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table_name not in set(inspector.get_table_names()):
        return set()
    return {column["name"] for column in inspector.get_columns(table_name)}


def upgrade() -> None:
    detection_rule_columns = _columns("detection_rules")
    if detection_rule_columns:
        with op.batch_alter_table("detection_rules") as batch_op:
            if "query" in detection_rule_columns:
                batch_op.alter_column("query", existing_type=sa.Text(), nullable=True)
            if "sigma_rule" in detection_rule_columns:
                batch_op.alter_column("sigma_rule", existing_type=sa.Text(), nullable=True)

    user_columns = _columns("users")
    if user_columns:
        with op.batch_alter_table("users") as batch_op:
            if "failed_login_attempts" not in user_columns:
                batch_op.add_column(sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"))
            if "locked_until" not in user_columns:
                batch_op.add_column(sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))
            if "last_failed_login_at" not in user_columns:
                batch_op.add_column(sa.Column("last_failed_login_at", sa.DateTime(timezone=True), nullable=True))
            if "last_login_at" not in user_columns:
                batch_op.add_column(sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
            if "password_changed_at" not in user_columns:
                batch_op.add_column(sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True))

    if "refresh_tokens" not in _tables():
        op.create_table(
            "refresh_tokens",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("user_id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("jti", sa.String(length=64), nullable=False),
            sa.Column("family_id", sa.String(length=36), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("replaced_by_token_id", sa.String(length=36), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=_created_at_default(), nullable=True),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("user_agent", sa.String(length=512), nullable=True),
            sa.Column("ip_address", sa.String(length=64), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
            sa.ForeignKeyConstraint(["replaced_by_token_id"], ["refresh_tokens.id"]),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("token_hash"),
            sa.UniqueConstraint("jti"),
        )
        op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
        op.create_index("ix_refresh_tokens_tenant_id", "refresh_tokens", ["tenant_id"])
        op.create_index("ix_refresh_tokens_token_hash", "refresh_tokens", ["token_hash"], unique=True)
        op.create_index("ix_refresh_tokens_jti", "refresh_tokens", ["jti"], unique=True)
        op.create_index("ix_refresh_tokens_family_id", "refresh_tokens", ["family_id"])
        op.create_index("ix_refresh_tokens_expires_at", "refresh_tokens", ["expires_at"])


def downgrade() -> None:
    if "refresh_tokens" in _tables():
        op.drop_index("ix_refresh_tokens_expires_at", table_name="refresh_tokens")
        op.drop_index("ix_refresh_tokens_family_id", table_name="refresh_tokens")
        op.drop_index("ix_refresh_tokens_jti", table_name="refresh_tokens")
        op.drop_index("ix_refresh_tokens_token_hash", table_name="refresh_tokens")
        op.drop_index("ix_refresh_tokens_tenant_id", table_name="refresh_tokens")
        op.drop_index("ix_refresh_tokens_user_id", table_name="refresh_tokens")
        op.drop_table("refresh_tokens")

    user_columns = _columns("users")
    if user_columns:
        with op.batch_alter_table("users") as batch_op:
            for column_name in (
                "password_changed_at",
                "last_login_at",
                "last_failed_login_at",
                "locked_until",
                "failed_login_attempts",
            ):
                if column_name in user_columns:
                    batch_op.drop_column(column_name)
