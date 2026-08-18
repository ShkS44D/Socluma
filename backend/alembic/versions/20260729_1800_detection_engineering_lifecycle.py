"""Detection engineering lifecycle and immutable rule provenance.

Revision ID: 20260729_1800
Revises: 20260729_1700
"""
from alembic import op
import sqlalchemy as sa

revision = "20260729_1800"
down_revision = "20260729_1700"
branch_labels = None
depends_on = None

NEW_TABLES = (
    "detection_rule_versions", "detection_rule_test_cases", "detection_rule_test_results",
    "detection_simulation_jobs", "detection_exceptions", "detection_suppression_policies",
    "detection_maintenance_windows", "detection_rule_health_snapshots",
    "detection_execution_state", "detection_recommendations", "detection_content_packs",
)


def upgrade() -> None:
    bind = op.get_bind()
    rule_columns = (
        sa.Column("lifecycle_status", sa.String(30), nullable=False, server_default="draft"),
        sa.Column("detection_kind", sa.String(30), nullable=False, server_default="event_match"),
        sa.Column("sigma_rule_id", sa.String(100)),
        sa.Column("current_version_id", sa.String(36)),
        sa.Column("production_version_id", sa.String(36)),
        sa.Column(
            "owner_id",
            sa.String(36),
            sa.ForeignKey("users.id", name="fk_detection_rules_owner_id_users", ondelete="SET NULL"),
        ),
        sa.Column("team", sa.String(120)), sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("risk_contribution", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("mitre_mappings", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("data_source_requirements", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("alert_policy", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("protected", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True)), sa.Column("last_tested_at", sa.DateTime(timezone=True)),
        sa.Column("retired_at", sa.DateTime(timezone=True)),
    )
    rule_inspector = sa.inspect(bind)
    existing_rule_columns = {
        column["name"] for column in rule_inspector.get_columns("detection_rules")
    }
    existing_rule_constraints = {
        constraint["name"]
        for constraint in rule_inspector.get_unique_constraints("detection_rules")
        if constraint.get("name")
    }
    with op.batch_alter_table("detection_rules") as batch:
        for column in rule_columns:
            if column.name not in existing_rule_columns:
                batch.add_column(column)
        if "uq_detection_rules_tenant_sigma_id" not in existing_rule_constraints:
            batch.create_unique_constraint(
                "uq_detection_rules_tenant_sigma_id", ["tenant_id", "sigma_rule_id"]
            )

    from src.models.sqlalchemy import Base
    for name in NEW_TABLES:
        Base.metadata.tables[name].create(bind=bind, checkfirst=True)

    match_columns = (
        sa.Column(
            "rule_version_id",
            sa.String(36),
            sa.ForeignKey(
                "detection_rule_versions.id",
                name="fk_detection_matches_rule_version_id",
                ondelete="SET NULL",
            ),
        ),
        sa.Column("rule_content_hash", sa.String(64)), sa.Column("detection_type", sa.String(30), nullable=False, server_default="event_match"),
        sa.Column("triggered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("window_start", sa.DateTime(timezone=True)), sa.Column("window_end", sa.DateTime(timezone=True)),
        sa.Column("group_key", sa.String(512)), sa.Column("contributing_event_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("matched_conditions", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("aggregate_values", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("exceptions_evaluated", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("suppression_result", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("risk_contribution", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("mitre_mappings", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("data_source_provenance", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("processing_version", sa.String(30), nullable=False, server_default="1.0"),
        sa.Column("explanation", sa.JSON(), nullable=False, server_default="{}"),
    )
    existing_match_columns = {
        column["name"] for column in sa.inspect(bind).get_columns("detection_matches")
    }
    with op.batch_alter_table("detection_matches") as batch:
        for column in match_columns:
            if column.name not in existing_match_columns:
                batch.add_column(column)

    index_specs = (
        ("detection_rules", "ix_detection_rules_tenant_lifecycle", ["tenant_id", "lifecycle_status"]),
        ("detection_rules", "ix_detection_rules_tenant_owner", ["tenant_id", "owner_id"]),
        ("detection_rules", "ix_detection_rules_tenant_production", ["tenant_id", "production_version_id"]),
        ("detection_matches", "ix_detection_matches_tenant_version", ["tenant_id", "rule_version_id", "created_at"]),
    )
    indexes_by_table = {
        table: {index["name"] for index in sa.inspect(bind).get_indexes(table)}
        for table in {spec[0] for spec in index_specs}
    }
    for table, name, columns in index_specs:
        if name not in indexes_by_table[table]:
            op.create_index(name, table, columns)

    rows = bind.execute(sa.text(
        "SELECT id, tenant_id, created_by, rule_content, sigma_rule, query, enabled, created_at "
        "FROM detection_rules WHERE current_version_id IS NULL"
    )).mappings().all()
    import hashlib, json, uuid
    for row in rows:
        definition = row["rule_content"] or {"kind": "event_match", "legacy_query": row["query"] or ""}
        if isinstance(definition, str):
            try: definition = json.loads(definition)
            except ValueError: definition = {"kind": "event_match", "legacy_query": row["query"] or ""}
        canonical = json.dumps(definition, sort_keys=True, separators=(",", ":"))
        version_id = str(uuid.uuid4())
        state = "production" if row["enabled"] else "disabled"
        bind.execute(sa.text(
            "INSERT INTO detection_rule_versions "
            "(id,tenant_id,rule_id,version_number,lifecycle_status,rule_language,original_content,"
            "normalized_definition,parser_version,schema_version,created_by_id,validation_result,test_result,"
            "content_hash,source_metadata,import_metadata,published_at,created_at) "
            "VALUES (:id,:tenant,:rule,1,:state,:language,:original,:definition,'1.0.0','1.0',:creator,"
            ":validation,:tests,:hash,:source,:imported,:published,:created)"
        ), {
            "id": version_id, "tenant": row["tenant_id"], "rule": row["id"], "state": state,
            "language": "sigma" if row["sigma_rule"] else "structured", "original": row["sigma_rule"],
            "definition": canonical, "creator": row["created_by"],
            "validation": '{"valid":true,"warnings":["Backfilled legacy rule"]}',
            "tests": '{"status":"passed","source":"legacy_backfill"}',
            "hash": hashlib.sha256(canonical.encode()).hexdigest(), "source": '{"legacy":true}',
            "imported": "{}", "published": row["created_at"] if row["enabled"] else None, "created": row["created_at"],
        })
        bind.execute(sa.text(
            "UPDATE detection_rules SET current_version_id=:version, production_version_id=:production, "
            "lifecycle_status=:state, owner_id=created_by WHERE id=:rule"
        ), {"version": version_id, "production": version_id if row["enabled"] else None, "state": state, "rule": row["id"]})
        bind.execute(sa.text(
            "UPDATE detection_matches SET rule_version_id=:version, rule_content_hash=:hash WHERE rule_id=:rule"
        ), {"version": version_id, "hash": hashlib.sha256(canonical.encode()).hexdigest(), "rule": row["id"]})


def downgrade() -> None:
    op.drop_index("ix_detection_matches_tenant_version", table_name="detection_matches")
    op.drop_index("ix_detection_rules_tenant_owner", table_name="detection_rules")
    op.drop_index("ix_detection_rules_tenant_production", table_name="detection_rules")
    op.drop_index("ix_detection_rules_tenant_lifecycle", table_name="detection_rules")
    with op.batch_alter_table("detection_matches") as batch:
        for name in ("explanation","processing_version","data_source_provenance","mitre_mappings","risk_contribution","confidence","suppression_result","exceptions_evaluated","aggregate_values","matched_conditions","contributing_event_ids","group_key","window_end","window_start","triggered_at","detection_type","rule_content_hash","rule_version_id"):
            batch.drop_column(name)
    for name in reversed(NEW_TABLES):
        op.drop_table(name)
    with op.batch_alter_table("detection_rules") as batch:
        batch.drop_constraint("uq_detection_rules_tenant_sigma_id", type_="unique")
        for name in ("retired_at","last_tested_at","last_triggered_at","protected","alert_policy","data_source_requirements","mitre_mappings","tags","risk_contribution","confidence","team","owner_id","production_version_id","current_version_id","sigma_rule_id","detection_kind","lifecycle_status"):
            batch.drop_column(name)
