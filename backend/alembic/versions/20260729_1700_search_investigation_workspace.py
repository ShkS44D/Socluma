"""Search and investigation workspace.

Revision ID: 20260729_1700
Revises: 20260729_1600
"""
from alembic import op
import sqlalchemy as sa

revision = "20260729_1700"
down_revision = "20260729_1600"
branch_labels = None
depends_on = None

TABLES = (
    "search_history", "saved_searches", "saved_search_revisions", "search_templates",
    "shared_search_references", "scheduled_searches", "scheduled_search_runs",
    "entities", "event_entities", "entity_relationships", "investigations",
    "investigation_collaborators", "investigation_resources", "evidence_bookmarks",
    "evidence_snapshots", "investigation_workspace_notes", "investigation_note_revisions",
    "investigation_attachments",
    "search_export_jobs",
)


def upgrade() -> None:
    # These table definitions live in the canonical SQLAlchemy metadata and are
    # deliberately isolated to this revision's fixed allowlist. This keeps the
    # large relational workspace definition identical on SQLite and PostgreSQL.
    from src.models.sqlalchemy import Base
    bind = op.get_bind()
    for name in TABLES:
        model_table = Base.metadata.tables[name]
        model_table.create(bind=bind, checkfirst=True)
        existing_columns = {
            column["name"] for column in sa.inspect(bind).get_columns(name)
        }
        missing_columns = [
            column for column in model_table.columns if column.name not in existing_columns
        ]
        if missing_columns:
            with op.batch_alter_table(name) as batch:
                for column in missing_columns:
                    batch.add_column(column._copy())

    existing_indexes = {
        index["name"] for index in sa.inspect(bind).get_indexes("security_events")
    }
    indexes = (
        ("ix_security_events_tenant_category_timestamp", ["tenant_id", "event_category", "timestamp"]),
        ("ix_security_events_tenant_severity_timestamp", ["tenant_id", "severity", "timestamp"]),
        ("ix_security_events_tenant_collector_timestamp", ["tenant_id", "collector_id", "timestamp"]),
        ("ix_security_events_tenant_data_source_timestamp", ["tenant_id", "data_source_id", "timestamp"]),
    )
    for name, columns in indexes:
        if name not in existing_indexes:
            op.create_index(name, "security_events", columns)

    templates = (
        ("failed-logins", "Failed logins", "events", "event.outcome:failure", '{"type":"clause","field":"event.outcome","operator":":","value":"failure"}'),
        ("powershell-activity", "PowerShell activity", "events", "process.name:powershell.exe", '{"type":"clause","field":"process.name","operator":":","value":"powershell.exe"}'),
        ("high-severity-alerts", "High-severity alerts", "alerts", "severity>=high", '{"type":"clause","field":"severity","operator":">=","value":3}'),
        ("unassigned-incidents", "Open incidents", "incidents", "status:open", '{"type":"clause","field":"status","operator":":","value":"open"}'),
        ("recent-ip-entities", "Recently observed IP entities", "entities", "entity.type:ip", '{"type":"clause","field":"entity.type","operator":":","value":"ip"}'),
    )
    for identifier, name, scope, display_query, ast in templates:
        if bind.execute(
            sa.text("SELECT 1 FROM search_templates WHERE id=:id"), {"id": identifier}
        ).first():
            continue
        bind.execute(sa.text(
            "INSERT INTO search_templates "
            "(id, tenant_id, name, description, display_query, query_template, placeholders, resource_scope, protected, created_by_id) "
            "VALUES (:id, NULL, :name, :description, :display_query, :query_template, :placeholders, :scope, :protected, NULL)"
        ), {
            "id": identifier, "name": name, "description": f"Built-in {name.lower()} search",
            "display_query": display_query, "query_template": ast, "placeholders": "{}", "scope": scope, "protected": True,
        })


def downgrade() -> None:
    for name in (
        "ix_security_events_tenant_data_source_timestamp", "ix_security_events_tenant_collector_timestamp",
        "ix_security_events_tenant_severity_timestamp", "ix_security_events_tenant_category_timestamp",
    ):
        op.drop_index(name, table_name="security_events")
    for name in reversed(TABLES):
        op.drop_table(name)
