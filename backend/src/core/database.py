from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from .config import get_settings
from .logging import logger

settings = get_settings()

connect_args = {}
if settings.USE_SQLITE:
    connect_args = {"check_same_thread": False}

class SafeSession(Session):
    def commit(self) -> None:
        try:
            super().commit()
        except Exception:
            super().rollback()
            logger.exception("Database commit failed; transaction rolled back")
            raise

    def close(self) -> None:
        try:
            if self.in_transaction():
                super().rollback()
        except Exception:
            logger.exception("Database session rollback failed during close")
            raise
        finally:
            super().close()


engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    connect_args=connect_args
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, class_=SafeSession)

Base = declarative_base()


# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        logger.exception("Database session rolled back after unhandled request error")
        raise
    finally:
        db.close()


# Create tables for SQLite
def create_tables():
    Base.metadata.create_all(bind=engine)
    if settings.USE_SQLITE:
        _upgrade_sqlite_schema()


def _upgrade_sqlite_schema():
    inspector = inspect(engine)
    with engine.begin() as connection:
        incident_columns = {column["name"] for column in inspector.get_columns("incidents")}
        if "attack_technique" not in incident_columns:
            connection.execute(text("ALTER TABLE incidents ADD COLUMN attack_technique JSON"))
        if "why_suspicious" not in incident_columns:
            connection.execute(text("ALTER TABLE incidents ADD COLUMN why_suspicious TEXT"))
        if "ai_analyzed_at" not in incident_columns:
            connection.execute(text("ALTER TABLE incidents ADD COLUMN ai_analyzed_at DATETIME"))

        existing_tables = set(inspector.get_table_names())
        if "threat_intel" not in existing_tables:
            connection.execute(
                text(
                    """
                    CREATE TABLE threat_intel (
                        id VARCHAR(36) NOT NULL PRIMARY KEY,
                        tenant_id VARCHAR(36) NOT NULL,
                        incident_id VARCHAR(36),
                        indicator VARCHAR(255) NOT NULL,
                        type VARCHAR(6) NOT NULL,
                        source VARCHAR(100) NOT NULL,
                        result JSON NOT NULL,
                        risk_impact INTEGER NOT NULL DEFAULT 0,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(tenant_id) REFERENCES tenants (id),
                        FOREIGN KEY(incident_id) REFERENCES incidents (id)
                    )
                    """
                )
            )
            connection.execute(text("CREATE INDEX ix_threat_intel_indicator ON threat_intel (indicator)"))

        if "audit_logs" not in existing_tables:
            connection.execute(
                text(
                    """
                    CREATE TABLE audit_logs (
                        id VARCHAR(36) NOT NULL PRIMARY KEY,
                        tenant_id VARCHAR(36),
                        user_id VARCHAR(36),
                        action VARCHAR(100) NOT NULL,
                        resource_type VARCHAR(100),
                        resource_id VARCHAR(36),
                        ip_address VARCHAR(64),
                        details JSON,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(tenant_id) REFERENCES tenants (id),
                        FOREIGN KEY(user_id) REFERENCES users (id)
                    )
                    """
                )
            )
            connection.execute(text("CREATE INDEX ix_audit_logs_tenant_id ON audit_logs (tenant_id)"))
            connection.execute(text("CREATE INDEX ix_audit_logs_user_id ON audit_logs (user_id)"))
            connection.execute(text("CREATE INDEX ix_audit_logs_action ON audit_logs (action)"))
            connection.execute(text("CREATE INDEX ix_audit_logs_created_at ON audit_logs (created_at)"))

        # Add new columns to iocs
        iocs_columns = {column["name"] for column in inspector.get_columns("iocs")}
        if "confidence_score" not in iocs_columns:
            connection.execute(text("ALTER TABLE iocs ADD COLUMN confidence_score INTEGER DEFAULT 0"))
        if "tags" not in iocs_columns:
            connection.execute(text("ALTER TABLE iocs ADD COLUMN tags JSON"))

        # Create ioc_enrichments table
        if "ioc_enrichments" not in existing_tables:
            connection.execute(
                text(
                    """
                    CREATE TABLE ioc_enrichments (
                        id VARCHAR(36) NOT NULL PRIMARY KEY,
                        ioc_id VARCHAR(36) NOT NULL,
                        provider VARCHAR(100) NOT NULL,
                        reputation VARCHAR(50),
                        malicious_count INTEGER DEFAULT 0,
                        total_reports INTEGER DEFAULT 0,
                        raw_response JSON,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(ioc_id) REFERENCES iocs (id) ON DELETE CASCADE
                    )
                    """
                )
            )

        # Create incident_iocs table
        if "incident_iocs" not in existing_tables:
            connection.execute(
                text(
                    """
                    CREATE TABLE incident_iocs (
                        id VARCHAR(36) NOT NULL PRIMARY KEY,
                        tenant_id VARCHAR(36) NOT NULL,
                        incident_id VARCHAR(36) NOT NULL,
                        ioc_id VARCHAR(36) NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(tenant_id) REFERENCES tenants (id),
                        FOREIGN KEY(incident_id) REFERENCES incidents (id) ON DELETE CASCADE,
                        FOREIGN KEY(ioc_id) REFERENCES iocs (id) ON DELETE CASCADE
                    )
                    """
                )
            )
            
        # Upgrade the detection rule schema
        detection_rules_columns = {column["name"] for column in inspector.get_columns("detection_rules")}
        if "rule_type" not in detection_rules_columns:
            connection.execute(text('ALTER TABLE detection_rules ADD COLUMN rule_type VARCHAR(10) DEFAULT "CUSTOM"'))
        if "event_type" not in detection_rules_columns:
            connection.execute(text('ALTER TABLE detection_rules ADD COLUMN event_type VARCHAR(10)'))
        if "condition" not in detection_rules_columns:
            connection.execute(text('ALTER TABLE detection_rules ADD COLUMN condition JSON'))
        if "mitre_technique_id" not in detection_rules_columns:
            connection.execute(text('ALTER TABLE detection_rules ADD COLUMN mitre_technique_id VARCHAR(50)'))
        if "created_by" not in detection_rules_columns:
            connection.execute(text('ALTER TABLE detection_rules ADD COLUMN created_by VARCHAR(36)'))
        # SQLite doesn't support altering column nullability, so we can skip that for now
            
        # Upgrade detection_rules table to add rule_content
        detection_rules_columns = {column["name"] for column in inspector.get_columns("detection_rules")}
        if "rule_content" not in detection_rules_columns:
            connection.execute(text('ALTER TABLE detection_rules ADD COLUMN rule_content JSON'))
            
        # Upgrade alerts table
        alerts_columns = {column["name"] for column in inspector.get_columns("alerts")}
        if "detection_rule_id" not in alerts_columns:
            connection.execute(text('ALTER TABLE alerts ADD COLUMN detection_rule_id VARCHAR(36)'))
        if "event_id" not in alerts_columns:
            connection.execute(text('ALTER TABLE alerts ADD COLUMN event_id VARCHAR(36)'))
        if "why_matched" not in alerts_columns:
            connection.execute(text('ALTER TABLE alerts ADD COLUMN why_matched TEXT'))
        if "matched_condition" not in alerts_columns:
            connection.execute(text('ALTER TABLE alerts ADD COLUMN matched_condition TEXT'))
            
        # Upgrade detection_matches table to add alert_id
        detection_matches_columns = {column["name"] for column in inspector.get_columns("detection_matches")}
        if "alert_id" not in detection_matches_columns:
            connection.execute(text('ALTER TABLE detection_matches ADD COLUMN alert_id VARCHAR(36)'))

        users_columns = {column["name"] for column in inspector.get_columns("users")}
        if "failed_login_attempts" not in users_columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0"))
        if "locked_until" not in users_columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN locked_until DATETIME"))
        if "last_failed_login_at" not in users_columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN last_failed_login_at DATETIME"))
        if "last_login_at" not in users_columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN last_login_at DATETIME"))
        if "password_changed_at" not in users_columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN password_changed_at DATETIME"))

        existing_tables = set(inspector.get_table_names())
        if "refresh_tokens" not in existing_tables:
            connection.execute(
                text(
                    """
                    CREATE TABLE refresh_tokens (
                        id VARCHAR(36) NOT NULL PRIMARY KEY,
                        user_id VARCHAR(36) NOT NULL,
                        tenant_id VARCHAR(36) NOT NULL,
                        token_hash VARCHAR(64) NOT NULL UNIQUE,
                        jti VARCHAR(64) NOT NULL UNIQUE,
                        family_id VARCHAR(36) NOT NULL,
                        expires_at DATETIME NOT NULL,
                        revoked_at DATETIME,
                        replaced_by_token_id VARCHAR(36),
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_used_at DATETIME,
                        user_agent VARCHAR(512),
                        ip_address VARCHAR(64),
                        FOREIGN KEY(user_id) REFERENCES users (id),
                        FOREIGN KEY(tenant_id) REFERENCES tenants (id),
                        FOREIGN KEY(replaced_by_token_id) REFERENCES refresh_tokens (id)
                    )
                    """
                )
            )
            connection.execute(text("CREATE INDEX ix_refresh_tokens_user_id ON refresh_tokens (user_id)"))
            connection.execute(text("CREATE INDEX ix_refresh_tokens_tenant_id ON refresh_tokens (tenant_id)"))
            connection.execute(text("CREATE INDEX ix_refresh_tokens_jti ON refresh_tokens (jti)"))
            connection.execute(text("CREATE INDEX ix_refresh_tokens_family_id ON refresh_tokens (family_id)"))
            connection.execute(text("CREATE INDEX ix_refresh_tokens_expires_at ON refresh_tokens (expires_at)"))

        collectors_columns = {column["name"] for column in inspector.get_columns("collectors")} if "collectors" in existing_tables else set()
        if "collectors" in existing_tables and "token_lookup_hash" not in collectors_columns:
            connection.execute(text("ALTER TABLE collectors ADD COLUMN token_lookup_hash VARCHAR(64)"))
            connection.execute(text("CREATE UNIQUE INDEX ix_collectors_token_lookup_hash ON collectors (token_lookup_hash)"))
