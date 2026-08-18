"""IOC intelligence and threat intelligence polish.

Revision ID: 20260730_1900
Revises: 20260729_1800
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit, urlunsplit

from alembic import op
import sqlalchemy as sa

revision = "20260730_1900"
down_revision = "20260729_1800"
branch_labels = None
depends_on = None

NEW_TABLES = (
    "ioc_score_history",
    "ioc_sightings",
    "ioc_watchlists",
    "ioc_watchlist_members",
    "ioc_list_entries",
    "ioc_hunt_jobs",
    "threat_intelligence_relationships",
)

IOC_COLUMNS = (
    sa.Column("original_value", sa.String(2048)),
    sa.Column("normalized_value", sa.String(2048)),
    sa.Column("display_value", sa.String(2048)),
    sa.Column("source_reliability", sa.Integer(), nullable=False, server_default="50"),
    sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
    sa.Column("risk_reasons", sa.JSON(), nullable=False, server_default="[]"),
    sa.Column("risk_score_version", sa.String(30), nullable=False, server_default="1.0"),
    sa.Column("lifecycle_status", sa.String(30), nullable=False, server_default="new"),
    sa.Column("review_status", sa.String(30), nullable=False, server_default="pending"),
    sa.Column("reviewed_by", sa.String(36), sa.ForeignKey("users.id", name="fk_iocs_reviewed_by_users", ondelete="SET NULL")),
    sa.Column("first_seen", sa.DateTime(timezone=True)),
    sa.Column("last_seen", sa.DateTime(timezone=True)),
    sa.Column("valid_from", sa.DateTime(timezone=True)),
    sa.Column("valid_until", sa.DateTime(timezone=True)),
    sa.Column("revoked_at", sa.DateTime(timezone=True)),
    sa.Column("expired_at", sa.DateTime(timezone=True)),
    sa.Column("tlp", sa.String(30), nullable=False, server_default="TLP:AMBER"),
    sa.Column("source_references", sa.JSON(), nullable=False, server_default="[]"),
    sa.Column("stix_id", sa.String(255)),
    sa.Column("external_source_ids", sa.JSON(), nullable=False, server_default="{}"),
    sa.Column("internal_sighting_count", sa.Integer(), nullable=False, server_default="0"),
    sa.Column("first_internal_sighting", sa.DateTime(timezone=True)),
    sa.Column("last_internal_sighting", sa.DateTime(timezone=True)),
    sa.Column("enrichment_status", sa.String(30), nullable=False, server_default="pending"),
    sa.Column("last_enriched_at", sa.DateTime(timezone=True)),
    sa.Column("next_enrichment_at", sa.DateTime(timezone=True)),
    sa.Column("false_positive", sa.Boolean(), nullable=False, server_default=sa.false()),
    sa.Column("allowlisted", sa.Boolean(), nullable=False, server_default=sa.false()),
    sa.Column("classification", sa.String(50)),
    sa.Column("content_hash", sa.String(64)),
    sa.Column("merged_from_ids", sa.JSON(), nullable=False, server_default="[]"),
)

ENRICHMENT_COLUMNS = (
    sa.Column("provider_verdict", sa.String(50)),
    sa.Column("confidence", sa.Integer()),
    sa.Column("categories", sa.JSON(), nullable=False, server_default="[]"),
    sa.Column("detection_counts", sa.JSON(), nullable=False, server_default="{}"),
    sa.Column("provider_first_seen", sa.DateTime(timezone=True)),
    sa.Column("provider_last_seen", sa.DateTime(timezone=True)),
    sa.Column("provider_references", sa.JSON(), nullable=False, server_default="[]"),
    sa.Column("expires_at", sa.DateTime(timezone=True)),
    sa.Column("raw_response_hash", sa.String(64)),
    sa.Column("safe_result", sa.JSON(), nullable=False, server_default="{}"),
    sa.Column("failure_code", sa.String(80)),
    sa.Column("retryable", sa.Boolean(), nullable=False, server_default=sa.false()),
    sa.Column("response_version", sa.String(30), nullable=False, server_default="1.0"),
)

ENUM_VALUES = (
    "ipv4", "ipv6", "cidr", "email", "md5", "sha1", "sha256", "sha512",
    "file_name", "file_path", "registry_key", "mutex", "user_agent",
    "certificate_fingerprint", "ja3", "ja4", "cryptocurrency_address",
)


def _legacy_normalize(kind: str, value: str) -> tuple[str, str]:
    value = value.strip().replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    value = value.replace("hxxps://", "https://").replace("hxxp://", "http://")
    if kind == "ip":
        address = ipaddress.ip_address(value)
        return ("ipv4" if address.version == 4 else "ipv6", address.compressed.lower())
    if kind == "domain":
        return kind, value.rstrip(".").lower().encode("idna").decode("ascii")
    if kind == "url":
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower().encode("idna").decode("ascii")
        netloc = host if not parsed.port else f"{host}:{parsed.port}"
        return kind, urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))
    if kind == "hash":
        compact = value.replace(":", "").lower()
        return {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}.get(len(compact), "hash"), compact
    return kind, value


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for value in ENUM_VALUES:
            op.execute(sa.text(f"ALTER TYPE indicatortype ADD VALUE IF NOT EXISTS '{value}'"))

    ioc_inspector = sa.inspect(bind)
    existing_ioc_columns = {
        column["name"] for column in ioc_inspector.get_columns("iocs")
    }
    with op.batch_alter_table("iocs") as batch:
        for column in IOC_COLUMNS:
            if column.name not in existing_ioc_columns:
                batch.add_column(column)
    existing_enrichment_columns = {
        column["name"] for column in sa.inspect(bind).get_columns("ioc_enrichments")
    }
    with op.batch_alter_table("ioc_enrichments") as batch:
        for column in ENRICHMENT_COLUMNS:
            if column.name not in existing_enrichment_columns:
                batch.add_column(column)

    metadata = sa.MetaData()
    iocs = sa.Table("iocs", metadata, autoload_with=bind)
    rows = bind.execute(sa.select(iocs.c.id, iocs.c.tenant_id, iocs.c.type, iocs.c.value, iocs.c.is_active)).mappings().all()
    seen: dict[tuple[str, str, str], str] = {}
    import hashlib
    for row in rows:
        raw_type = row["type"].value if hasattr(row["type"], "value") else str(row["type"])
        try:
            normalized_type, canonical = _legacy_normalize(raw_type, row["value"])
        except (ValueError, UnicodeError):
            normalized_type, canonical = raw_type, row["value"].strip()
        key = (row["tenant_id"], normalized_type, canonical)
        content_hash = hashlib.sha256(f"{normalized_type}\0{canonical}".encode()).hexdigest()
        if key in seen:
            survivor = seen[key]
            # Preserve incident provenance and enrichment history before removing the duplicate.
            bind.execute(sa.text(
                "DELETE FROM incident_iocs WHERE ioc_id=:duplicate AND EXISTS "
                "(SELECT 1 FROM incident_iocs keep WHERE keep.ioc_id=:survivor "
                "AND keep.tenant_id=incident_iocs.tenant_id AND keep.incident_id=incident_iocs.incident_id)"
            ), {"duplicate": row["id"], "survivor": survivor})
            bind.execute(sa.text("UPDATE incident_iocs SET ioc_id=:survivor WHERE ioc_id=:duplicate"),
                         {"duplicate": row["id"], "survivor": survivor})
            bind.execute(sa.text("UPDATE ioc_enrichments SET ioc_id=:survivor WHERE ioc_id=:duplicate"),
                         {"duplicate": row["id"], "survivor": survivor})
            bind.execute(sa.delete(iocs).where(iocs.c.id == row["id"]))
            continue
        seen[key] = row["id"]
        bind.execute(
            sa.update(iocs).where(iocs.c.id == row["id"]).values(
                type=normalized_type,
                original_value=row["value"],
                normalized_value=canonical,
                display_value=canonical,
                content_hash=content_hash,
                lifecycle_status="active" if row["is_active"] else "monitoring",
            )
        )

    ioc_inspector = sa.inspect(bind)
    existing_ioc_constraints = {
        constraint["name"]
        for constraint in ioc_inspector.get_unique_constraints("iocs")
        if constraint.get("name")
    }
    existing_ioc_indexes = {
        index["name"] for index in ioc_inspector.get_indexes("iocs")
    }
    with op.batch_alter_table("iocs") as batch:
        if "uq_iocs_tenant_type_normalized" not in existing_ioc_constraints:
            batch.create_unique_constraint("uq_iocs_tenant_type_normalized", ["tenant_id", "type", "normalized_value"])
        index_specs = (
            ("ix_iocs_tenant_lifecycle_risk", ["tenant_id", "lifecycle_status", "risk_score"]),
            ("ix_iocs_tenant_expiration", ["tenant_id", "valid_until"]),
            ("ix_iocs_tenant_sightings", ["tenant_id", "last_internal_sighting"]),
            ("ix_iocs_content_hash", ["content_hash"]),
        )
        for name, columns in index_specs:
            if name not in existing_ioc_indexes:
                batch.create_index(name, columns)

    from src.models.sqlalchemy import Base
    for name in NEW_TABLES:
        Base.metadata.tables[name].create(bind=bind, checkfirst=True)


def downgrade() -> None:
    for name in reversed(NEW_TABLES):
        op.drop_table(name)
    with op.batch_alter_table("ioc_enrichments") as batch:
        for column in reversed(ENRICHMENT_COLUMNS):
            batch.drop_column(column.name)
    with op.batch_alter_table("iocs") as batch:
        batch.drop_index("ix_iocs_content_hash")
        batch.drop_index("ix_iocs_tenant_sightings")
        batch.drop_index("ix_iocs_tenant_expiration")
        batch.drop_index("ix_iocs_tenant_lifecycle_risk")
        batch.drop_constraint("uq_iocs_tenant_type_normalized", type_="unique")
        for column in reversed(IOC_COLUMNS):
            batch.drop_column(column.name)
