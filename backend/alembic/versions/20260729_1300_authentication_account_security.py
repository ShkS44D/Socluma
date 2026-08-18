"""Authentication MFA, recovery, sessions, and security history.

Revision ID: 20260729_1300
Revises: 20260729_1200
"""
from alembic import op
import sqlalchemy as sa


revision = "20260729_1300"
down_revision = "20260729_1200"
branch_labels = None
depends_on = None


def upgrade():
    user_columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("users")}
    with op.batch_alter_table("users") as batch:
        for column in (
            sa.Column("mfa_secret_encrypted", sa.Text(), nullable=True),
            sa.Column("mfa_pending_secret_encrypted", sa.Text(), nullable=True),
            sa.Column("mfa_pending_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("mfa_enabled_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("mfa_last_totp_step", sa.BigInteger(), nullable=True),
            sa.Column("mfa_failed_attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("mfa_locked_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("email_verification_exempt", sa.Boolean(), nullable=False, server_default=sa.false()),
        ):
            if column.name not in user_columns:
                batch.add_column(column)
    # Existing accounts remain usable; newly registered accounts use the ORM
    # default (not exempt) and follow environment verification policy.
    op.execute(sa.text("UPDATE users SET email_verification_exempt = :value").bindparams(value=True))

    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("family_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column("device_label", sa.String(255), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(100), nullable=True),
        sa.UniqueConstraint("family_id", name="uq_auth_sessions_family_id"),
    )
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])
    op.create_index("ix_auth_sessions_tenant_id", "auth_sessions", ["tenant_id"])
    op.create_index("ix_auth_sessions_expires_at", "auth_sessions", ["expires_at"])
    op.create_index("ix_auth_sessions_ip_address", "auth_sessions", ["ip_address"])
    op.create_index("ix_auth_sessions_user_revoked_expires", "auth_sessions", ["user_id", "revoked_at", "expires_at"])
    op.create_index("ix_auth_sessions_tenant_created", "auth_sessions", ["tenant_id", "created_at"])

    refresh_columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("refresh_tokens")}
    with op.batch_alter_table("refresh_tokens") as batch:
        if "session_id" not in refresh_columns:
            batch.add_column(sa.Column("session_id", sa.String(36), nullable=True))
        if "revocation_reason" not in refresh_columns:
            batch.add_column(sa.Column("revocation_reason", sa.String(100), nullable=True))
    with op.batch_alter_table("refresh_tokens") as batch:
        batch.create_foreign_key("fk_refresh_tokens_session", "auth_sessions", ["session_id"], ["id"], ondelete="CASCADE")
    op.create_index("ix_refresh_tokens_session_id", "refresh_tokens", ["session_id"])

    op.create_table(
        "auth_challenges",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("jti", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("jti", name="uq_auth_challenges_jti"),
    )
    op.create_index("ix_auth_challenges_user_id", "auth_challenges", ["user_id"])
    op.create_index("ix_auth_challenges_user_expires", "auth_challenges", ["user_id", "expires_at"])

    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("code_hash", name="uq_mfa_recovery_code_hash"),
    )
    op.create_index("ix_mfa_recovery_codes_user_id", "mfa_recovery_codes", ["user_id"])
    op.create_index("ix_mfa_recovery_codes_user_used", "mfa_recovery_codes", ["user_id", "used_at"])

    op.create_table(
        "auth_one_time_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requested_ip", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("token_hash", name="uq_auth_one_time_token_hash"),
    )
    op.create_index("ix_auth_one_time_tokens_user_id", "auth_one_time_tokens", ["user_id"])
    op.create_index("ix_auth_one_time_tokens_purpose", "auth_one_time_tokens", ["purpose"])
    op.create_index("ix_auth_one_time_tokens_expires", "auth_one_time_tokens", ["expires_at"])
    op.create_index("ix_auth_one_time_tokens_user_purpose_created", "auth_one_time_tokens", ["user_id", "purpose", "created_at"])

    op.create_table(
        "auth_security_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("result", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False, server_default="informational"),
        sa.Column("reason_code", sa.String(100), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column("device_label", sa.String(255), nullable=True),
        sa.Column("request_id", sa.String(128), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    for name, columns in (
        ("ix_auth_security_events_user_id", ["user_id"]),
        ("ix_auth_security_events_tenant_id", ["tenant_id"]),
        ("ix_auth_security_events_event_type", ["event_type"]),
        ("ix_auth_security_events_ip_address", ["ip_address"]),
        ("ix_auth_security_events_created_at", ["created_at"]),
        ("ix_auth_security_events_user_created", ["user_id", "created_at"]),
        ("ix_auth_security_events_tenant_created", ["tenant_id", "created_at"]),
        ("ix_auth_security_events_user_severity", ["user_id", "severity"]),
    ):
        op.create_index(name, "auth_security_events", columns)

    op.create_table(
        "known_auth_devices",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fingerprint_hash", sa.String(64), nullable=False),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column("device_label", sa.String(255), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("user_id", "fingerprint_hash", name="uq_known_auth_device_user_fingerprint"),
    )
    op.create_index("ix_known_auth_devices_user_id", "known_auth_devices", ["user_id"])
    op.create_index("ix_known_auth_devices_user_last_seen", "known_auth_devices", ["user_id", "last_seen_at"])


def downgrade():
    op.drop_table("known_auth_devices")
    op.drop_table("auth_security_events")
    op.drop_table("auth_one_time_tokens")
    op.drop_table("mfa_recovery_codes")
    op.drop_table("auth_challenges")
    op.drop_index("ix_refresh_tokens_session_id", table_name="refresh_tokens")
    with op.batch_alter_table("refresh_tokens") as batch:
        batch.drop_constraint("fk_refresh_tokens_session", type_="foreignkey")
        batch.drop_column("revocation_reason")
        batch.drop_column("session_id")
    op.drop_table("auth_sessions")
    with op.batch_alter_table("users") as batch:
        for name in (
            "email_verification_exempt",
            "email_verified_at",
            "mfa_locked_until",
            "mfa_failed_attempts",
            "mfa_last_totp_step",
            "mfa_enabled_at",
            "mfa_pending_expires_at",
            "mfa_pending_secret_encrypted",
            "mfa_secret_encrypted",
        ):
            batch.drop_column(name)
