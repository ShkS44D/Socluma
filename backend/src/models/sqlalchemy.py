from sqlalchemy import (
    Column, String, Boolean, Date, DateTime, Text, Float, JSON, Enum, ForeignKey, Integer, BigInteger, Index, UniqueConstraint
)
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
from src.core.database import Base
import enum


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    RESPONDER = "responder"
    VIEWER = "viewer"


class OrganizationRole(str, enum.Enum):
    OWNER = "owner"
    ADMINISTRATOR = "administrator"
    SOC_MANAGER = "soc_manager"
    ANALYST = "analyst"
    VIEWER = "viewer"


class OrganizationStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"
    PENDING_DELETION = "pending_deletion"
    DELETED = "deleted"


class InvitationStatus(str, enum.Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


class AIArtifactType(str, enum.Enum):
    INCIDENT_SUMMARY = "incident_summary"
    ALERT_EXPLANATION = "alert_explanation"
    IOC_ANALYSIS = "ioc_analysis"
    TIMELINE = "timeline"
    REPORT = "report"
    DETECTION_SUGGESTIONS = "detection_suggestions"
    PLAYBOOK_SUGGESTIONS = "playbook_suggestions"
    RISK_SCORE = "risk_score"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentPriority(str, enum.Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class AlertSourceType(str, enum.Enum):
    WEBHOOK = "webhook"
    API = "api"
    MANUAL = "manual"


class IndicatorType(str, enum.Enum):
    IP = "ip"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH = "hash"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    FILE_NAME = "file_name"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    CERTIFICATE_FINGERPRINT = "certificate_fingerprint"
    JA3 = "ja3"
    JA4 = "ja4"
    CRYPTOCURRENCY_ADDRESS = "cryptocurrency_address"


def indicator_type_enum() -> Enum:
    """Persist IOC enum values consistently across SQLite and PostgreSQL."""
    return Enum(
        IndicatorType,
        name="indicatortype",
        values_callable=lambda enum_type: [member.value for member in enum_type],
    )


class Classification(str, enum.Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN = "BENIGN"


class EvidenceType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    FILE = "file"
    URL = "url"


class RuleType(str, enum.Enum):
    CUSTOM = "custom"
    SIGMA = "sigma"


class EventType(str, enum.Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    FILE = "file"
    NETWORK = "network"
    PROCESS = "process"
    ALERT = "alert"
    USER_CREATION = "user_creation"


class PlaybookStatus(str, enum.Enum):
    DRAFT = "draft"
    TESTING = "testing"
    ACTIVE = "active"
    DISABLED = "disabled"
    ARCHIVED = "archived"


class PlaybookTriggerType(str, enum.Enum):
    ALERT_CREATED = "alert_created"
    INCIDENT_CREATED = "incident_created"
    INCIDENT_SEVERITY_CHANGED = "incident_severity_changed"
    MANUAL_RUN = "manual_run"
    SCHEDULED = "scheduled"
    WEBHOOK = "webhook"


class PlaybookStepType(str, enum.Enum):
    CONDITION = "condition"
    DELAY = "delay"
    APPROVAL = "approval"
    NOTIFICATION = "notification"
    AI_ANALYSIS = "ai_analysis"
    THREAT_INTEL_LOOKUP = "threat_intel_lookup"
    HTTP_REQUEST = "http_request"
    WEBHOOK = "webhook"
    PYTHON_SCRIPT = "python_script"
    CREATE_INCIDENT = "create_incident"
    UPDATE_INCIDENT = "update_incident"
    CLOSE_INCIDENT = "close_incident"
    TAG_ALERT = "tag_alert"
    ASSIGN_ANALYST = "assign_analyst"
    CREATE_TASK = "create_task"
    BRANCH = "branch"
    END = "end"
    ACTION = "action"


class PlaybookExecutionStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    AWAITING_APPROVAL = "awaiting_approval"
    PAUSED = "paused"


class PlaybookStepStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    AWAITING_APPROVAL = "awaiting_approval"


class PlaybookApprovalStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class LogSourceType(str, enum.Enum):
    WINDOWS_EDR = "windows_edr"
    LINUX_AUDIT = "linux_audit"
    FIREWALL = "firewall"
    CLOUDTRAIL = "cloudtrail"
    APPLICATION_LOG = "application_log"
    CUSTOM = "custom"


class LogSourceStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"


class LogSource(Base):
    __tablename__ = "log_sources"
    __table_args__ = (
        Index("ix_log_sources_tenant_status", "tenant_id", "status"),
        Index("ix_log_sources_tenant_last_seen", "tenant_id", "last_seen"),
        Index("ix_log_sources_tenant_created_at", "tenant_id", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    name = Column(String(255), nullable=False)
    type = Column(Enum(LogSourceType), default=LogSourceType.CUSTOM)
    description = Column(Text, nullable=True)
    status = Column(Enum(LogSourceStatus), default=LogSourceStatus.INACTIVE)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    collectors = relationship("Collector", back_populates="log_source", cascade="all, delete-orphan")


class CollectorStatus(str, enum.Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    ERROR = "error"


class Collector(Base):
    __tablename__ = "collectors"
    __table_args__ = (
        Index("ix_collectors_log_source_id", "log_source_id"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    log_source_id = Column(String(36), ForeignKey("log_sources.id"), nullable=True)
    name = Column(String(255), nullable=False)
    type = Column(String(100), nullable=False)
    hostname = Column(String(255), nullable=True)
    token = Column(String(255), nullable=False, unique=True)
    token_lookup_hash = Column(String(64), nullable=True, unique=True, index=True)
    credential_expires_at = Column(DateTime(timezone=True), nullable=True)
    credential_rotated_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_reason = Column(String(255), nullable=True)
    group_id = Column(String(36), ForeignKey("collector_groups.id", ondelete="SET NULL"), nullable=True)
    policy_version_id = Column(String(36), ForeignKey("collector_policy_versions.id", ondelete="SET NULL"), nullable=True)
    platform = Column(String(50), nullable=True)
    os_version = Column(String(150), nullable=True)
    collector_version = Column(String(50), nullable=True)
    architecture = Column(String(50), nullable=True)
    health_status = Column(String(30), nullable=False, default="offline")
    last_ingestion_at = Column(DateTime(timezone=True), nullable=True)
    last_failed_ingestion_at = Column(DateTime(timezone=True), nullable=True)
    last_authenticated_at = Column(DateTime(timezone=True), nullable=True)
    queue_depth = Column(Integer, nullable=False, default=0)
    spool_size_bytes = Column(BigInteger, nullable=False, default=0)
    dropped_event_count = Column(BigInteger, nullable=False, default=0)
    events_collected = Column(BigInteger, nullable=False, default=0)
    events_submitted = Column(BigInteger, nullable=False, default=0)
    events_accepted = Column(BigInteger, nullable=False, default=0)
    events_rejected = Column(BigInteger, nullable=False, default=0)
    retry_count = Column(BigInteger, nullable=False, default=0)
    cpu_percent = Column(Float, nullable=True)
    memory_percent = Column(Float, nullable=True)
    disk_percent = Column(Float, nullable=True)
    applied_policy_version = Column(Integer, nullable=True)
    checkpoint_status = Column(String(30), nullable=True)
    uptime_seconds = Column(BigInteger, nullable=True)
    service_status = Column(String(30), nullable=True)
    status = Column(Enum(CollectorStatus), default=CollectorStatus.OFFLINE)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    log_source = relationship("LogSource", back_populates="collectors")


class DataSource(Base):
    __tablename__ = "data_sources"
    __table_args__ = (
        UniqueConstraint("tenant_id", "source_key", name="uq_data_sources_tenant_key"),
        Index("ix_data_sources_tenant_health", "tenant_id", "health_status"),
        Index("ix_data_sources_tenant_last_received", "tenant_id", "last_received_at"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    collector_id = Column(String(36), ForeignKey("collectors.id", ondelete="SET NULL"), nullable=True)
    source_key = Column(String(150), nullable=False)
    name = Column(String(255), nullable=False)
    source_type = Column(String(50), nullable=False)
    vendor = Column(String(100), nullable=True)
    product = Column(String(100), nullable=True)
    parser_name = Column(String(100), nullable=False, default="json")
    transport = Column(String(30), nullable=False, default="https")
    enabled = Column(Boolean, nullable=False, default=True)
    minimum_quality_score = Column(Integer, nullable=False, default=0)
    last_event_at = Column(DateTime(timezone=True), nullable=True)
    last_received_at = Column(DateTime(timezone=True), nullable=True)
    last_successful_parse_at = Column(DateTime(timezone=True), nullable=True)
    last_failure_at = Column(DateTime(timezone=True), nullable=True)
    accepted_count = Column(BigInteger, nullable=False, default=0)
    rejected_count = Column(BigInteger, nullable=False, default=0)
    duplicate_count = Column(BigInteger, nullable=False, default=0)
    quality_score_total = Column(BigInteger, nullable=False, default=0)
    events_per_minute = Column(Float, nullable=False, default=0)
    ingestion_lag_seconds = Column(Float, nullable=True)
    health_status = Column(String(30), nullable=False, default="unknown")
    retention_class = Column(String(50), nullable=False, default="telemetry")
    safe_config = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class CollectorGroup(Base):
    __tablename__ = "collector_groups"
    __table_args__ = (UniqueConstraint("tenant_id", "normalized_name", name="uq_collector_groups_tenant_name"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    normalized_name = Column(String(120), nullable=False)
    description = Column(Text, nullable=True)
    policy_id = Column(String(36), ForeignKey("collector_policies.id", ondelete="SET NULL"), nullable=True)
    platform_filter = Column(String(50), nullable=True)
    tags = Column(JSON, nullable=False, default=list)
    status = Column(String(20), nullable=False, default="active")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CollectorPolicy(Base):
    __tablename__ = "collector_policies"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_collector_policies_tenant_name"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(150), nullable=False)
    description = Column(Text, nullable=True)
    active_version = Column(Integer, nullable=True)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class CollectorPolicyVersion(Base):
    __tablename__ = "collector_policy_versions"
    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_collector_policy_version"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    policy_id = Column(String(36), ForeignKey("collector_policies.id", ondelete="CASCADE"), nullable=False)
    version = Column(Integer, nullable=False)
    status = Column(String(20), nullable=False, default="draft")
    configuration = Column(JSON, nullable=False)
    checksum = Column(String(64), nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CollectorEnrollmentToken(Base):
    __tablename__ = "collector_enrollment_tokens"
    __table_args__ = (Index("ix_enrollment_tenant_expires", "tenant_id", "expires_at"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True)
    name = Column(String(150), nullable=False)
    platform = Column(String(50), nullable=True)
    group_id = Column(String(36), ForeignKey("collector_groups.id", ondelete="SET NULL"), nullable=True)
    max_uses = Column(Integer, nullable=False, default=1)
    used_count = Column(Integer, nullable=False, default=0)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CollectorCredential(Base):
    __tablename__ = "collector_credentials"
    __table_args__ = (Index("ix_collector_credentials_collector_active", "collector_id", "revoked_at", "expires_at"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    collector_id = Column(String(36), ForeignKey("collectors.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(255), nullable=False)
    lookup_hash = Column(String(64), nullable=False, unique=True)
    scopes = Column(JSON, nullable=False, default=lambda: ["ingestion", "heartbeat", "configuration", "version"])
    expires_at = Column(DateTime(timezone=True), nullable=False)
    overlap_until = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CollectorHeartbeatRecord(Base):
    __tablename__ = "collector_heartbeats"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    collector_id = Column(String(36), ForeignKey("collectors.id", ondelete="CASCADE"), nullable=False, index=True)
    health_status = Column(String(30), nullable=False)
    safe_metrics = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)


class CollectorCheckpoint(Base):
    __tablename__ = "collector_checkpoints"
    __table_args__ = (UniqueConstraint("collector_id", "source_key", name="uq_collector_checkpoint_source"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    collector_id = Column(String(36), ForeignKey("collectors.id", ondelete="CASCADE"), nullable=False)
    source_key = Column(String(200), nullable=False)
    checkpoint_version = Column(Integer, nullable=False, default=1)
    safe_state = Column(JSON, nullable=False)
    last_acknowledged_batch = Column(String(36), nullable=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class IngestionBatch(Base):
    __tablename__ = "ingestion_batches"
    __table_args__ = (
        UniqueConstraint("tenant_id", "actor_key", "batch_key", name="uq_ingestion_batch_actor_key"),
        Index("ix_ingestion_batches_tenant_received", "tenant_id", "received_at"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    collector_id = Column(String(36), ForeignKey("collectors.id", ondelete="SET NULL"), nullable=True)
    actor_key = Column(String(100), nullable=False)
    batch_key = Column(String(100), nullable=False)
    request_fingerprint = Column(String(64), nullable=False)
    state = Column(String(30), nullable=False, default="accepted")
    submitted_count = Column(Integer, nullable=False, default=0)
    accepted_count = Column(Integer, nullable=False, default=0)
    duplicate_count = Column(Integer, nullable=False, default=0)
    rejected_count = Column(Integer, nullable=False, default=0)
    receipt = Column(JSON, nullable=False, default=dict)
    received_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class IngestionReplayNonce(Base):
    __tablename__ = "ingestion_replay_nonces"
    __table_args__ = (UniqueConstraint("collector_id", "nonce", name="uq_ingestion_replay_nonce"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    collector_id = Column(String(36), ForeignKey("collectors.id", ondelete="CASCADE"), nullable=False)
    nonce = Column(String(100), nullable=False)
    request_fingerprint = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class TelemetryFailure(Base):
    __tablename__ = "telemetry_failures"
    __table_args__ = (Index("ix_telemetry_failures_tenant_state", "tenant_id", "state", "next_retry_at"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    collector_id = Column(String(36), ForeignKey("collectors.id", ondelete="SET NULL"), nullable=True)
    data_source_id = Column(String(36), ForeignKey("data_sources.id", ondelete="SET NULL"), nullable=True)
    event_id = Column(String(36), ForeignKey("security_events.id", ondelete="SET NULL"), nullable=True)
    batch_id = Column(String(36), ForeignKey("ingestion_batches.id", ondelete="SET NULL"), nullable=True)
    stage = Column(String(50), nullable=False)
    error_code = Column(String(80), nullable=False)
    safe_error = Column(Text, nullable=False)
    payload = Column(JSON, nullable=False, default=dict)
    state = Column(String(30), nullable=False, default="retry")
    attempts = Column(Integer, nullable=False, default=0)
    next_retry_at = Column(DateTime(timezone=True), nullable=True)
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class TelemetryImportJob(Base):
    __tablename__ = "telemetry_import_jobs"
    __table_args__ = (Index("ix_telemetry_import_jobs_tenant_created", "tenant_id", "created_at"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    format = Column(String(20), nullable=False)
    state = Column(String(30), nullable=False, default="queued")
    submitted_count = Column(Integer, nullable=False, default=0)
    accepted_count = Column(Integer, nullable=False, default=0)
    duplicate_count = Column(Integer, nullable=False, default=0)
    rejected_count = Column(Integer, nullable=False, default=0)
    safe_error = Column(Text, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class SearchHistory(Base):
    __tablename__ = "search_history"
    __table_args__ = (Index("ix_search_history_user_created", "tenant_id", "user_id", "created_at"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    display_query = Column(Text, nullable=False)
    normalized_query = Column(JSON, nullable=True)
    resource_scope = Column(String(30), nullable=False)
    time_range = Column(JSON, nullable=False)
    sort = Column(JSON, nullable=False)
    result_count = Column(Integer, nullable=False, default=0)
    execution_time_ms = Column(Float, nullable=False, default=0)
    success = Column(Boolean, nullable=False, default=True)
    error_code = Column(String(80), nullable=True)
    pinned = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SavedSearch(Base):
    __tablename__ = "saved_searches"
    __table_args__ = (
        UniqueConstraint("tenant_id", "owner_id", "normalized_name", name="uq_saved_search_owner_name"),
        Index("ix_saved_searches_tenant_visibility", "tenant_id", "visibility"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    owner_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(150), nullable=False)
    normalized_name = Column(String(150), nullable=False)
    description = Column(Text, nullable=True)
    display_query = Column(Text, nullable=False)
    query_ast = Column(JSON, nullable=False)
    resource_scope = Column(String(30), nullable=False)
    time_range = Column(JSON, nullable=False)
    sort = Column(JSON, nullable=False)
    visibility = Column(String(20), nullable=False, default="private")
    tags = Column(JSON, nullable=False, default=list)
    pinned = Column(Boolean, nullable=False, default=False)
    version = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class SavedSearchRevision(Base):
    __tablename__ = "saved_search_revisions"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    saved_search_id = Column(String(36), ForeignKey("saved_searches.id", ondelete="CASCADE"), nullable=False, index=True)
    version = Column(Integer, nullable=False)
    definition = Column(JSON, nullable=False)
    changed_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SearchTemplate(Base):
    __tablename__ = "search_templates"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_search_template_tenant_name"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    name = Column(String(150), nullable=False)
    description = Column(Text, nullable=True)
    display_query = Column(Text, nullable=False)
    query_template = Column(JSON, nullable=False)
    placeholders = Column(JSON, nullable=False, default=dict)
    resource_scope = Column(String(30), nullable=False)
    protected = Column(Boolean, nullable=False, default=False)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SharedSearchReference(Base):
    __tablename__ = "shared_search_references"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    saved_search_id = Column(String(36), ForeignKey("saved_searches.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ScheduledSearch(Base):
    __tablename__ = "scheduled_searches"
    __table_args__ = (Index("ix_scheduled_searches_status_next_run", "tenant_id", "status", "next_run_at"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    saved_search_id = Column(String(36), ForeignKey("saved_searches.id", ondelete="CASCADE"), nullable=False)
    owner_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    cadence = Column(String(20), nullable=False)
    status = Column(String(20), nullable=False, default="active")
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    next_run_at = Column(DateTime(timezone=True), nullable=False)
    last_result_count = Column(Integer, nullable=True)
    failure_reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ScheduledSearchRun(Base):
    __tablename__ = "scheduled_search_runs"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    schedule_id = Column(String(36), ForeignKey("scheduled_searches.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(20), nullable=False)
    result_count = Column(Integer, nullable=False, default=0)
    execution_time_ms = Column(Float, nullable=False, default=0)
    failure_reason = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class SearchEntity(Base):
    __tablename__ = "entities"
    __table_args__ = (
        UniqueConstraint("tenant_id", "entity_type", "normalized_value", name="uq_entities_tenant_type_value"),
        Index("ix_entities_tenant_last_seen", "tenant_id", "last_seen_at"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    entity_type = Column(String(30), nullable=False)
    normalized_value = Column(String(1024), nullable=False)
    display_value = Column(String(1024), nullable=False)
    attributes = Column(JSON, nullable=False, default=dict)
    first_seen_at = Column(DateTime(timezone=True), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), nullable=False)
    sighting_count = Column(BigInteger, nullable=False, default=1)
    confidence = Column(Float, nullable=False, default=1.0)
    extraction_source = Column(String(50), nullable=False, default="normalized_event")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class EventEntity(Base):
    __tablename__ = "event_entities"
    __table_args__ = (UniqueConstraint("event_id", "entity_id", "role", name="uq_event_entity_role"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    event_id = Column(String(36), ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False, index=True)
    entity_id = Column(String(36), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(50), nullable=False)
    evidence = Column(JSON, nullable=False, default=dict)
    observed_at = Column(DateTime(timezone=True), nullable=False)


class EntityRelationship(Base):
    __tablename__ = "entity_relationships"
    __table_args__ = (
        UniqueConstraint("tenant_id", "source_entity_id", "target_entity_id", "relationship_type", name="uq_entity_relationship"),
        Index("ix_entity_relationship_source", "tenant_id", "source_entity_id"),
        Index("ix_entity_relationship_target", "tenant_id", "target_entity_id"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    source_entity_id = Column(String(36), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False)
    target_entity_id = Column(String(36), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False)
    relationship_type = Column(String(60), nullable=False)
    observed = Column(Boolean, nullable=False, default=True)
    first_seen_at = Column(DateTime(timezone=True), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), nullable=False)
    sighting_count = Column(BigInteger, nullable=False, default=1)
    evidence_event_id = Column(String(36), ForeignKey("security_events.id", ondelete="SET NULL"), nullable=True)


class InvestigationWorkspace(Base):
    __tablename__ = "investigations"
    __table_args__ = (Index("ix_investigations_tenant_status", "tenant_id", "status", "updated_at"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default="open")
    owner_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    linked_incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    hypotheses = Column(JSON, nullable=False, default=list)
    classification = Column(String(30), nullable=False, default="confidential")
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class InvestigationCollaborator(Base):
    __tablename__ = "investigation_collaborators"
    __table_args__ = (UniqueConstraint("investigation_id", "user_id", name="uq_investigation_collaborator"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    added_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class InvestigationResource(Base):
    __tablename__ = "investigation_resources"
    __table_args__ = (UniqueConstraint("investigation_id", "resource_type", "resource_id", name="uq_investigation_resource"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    resource_type = Column(String(40), nullable=False)
    resource_id = Column(String(36), nullable=False)
    label = Column(String(255), nullable=True)
    added_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class EvidenceBookmark(Base):
    __tablename__ = "evidence_bookmarks"
    __table_args__ = (Index("ix_evidence_bookmarks_investigation_order", "investigation_id", "display_order"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    resource_type = Column(String(40), nullable=False)
    resource_id = Column(String(36), nullable=False)
    event_timestamp = Column(DateTime(timezone=True), nullable=True)
    label = Column(String(255), nullable=True)
    analyst_comment = Column(Text, nullable=True)
    relevance = Column(String(20), nullable=False, default="supporting")
    display_order = Column(Integer, nullable=False, default=0)
    snapshot_id = Column(String(36), nullable=True)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    removed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class EvidenceSnapshot(Base):
    __tablename__ = "evidence_snapshots"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    resource_type = Column(String(40), nullable=False)
    resource_id = Column(String(36), nullable=False)
    safe_projection = Column(JSON, nullable=False)
    raw_event_hash = Column(String(64), nullable=True)
    integrity_hash = Column(String(64), nullable=False)
    parser_version = Column(String(30), nullable=True)
    schema_version = Column(String(30), nullable=True)
    classification = Column(String(30), nullable=False, default="confidential")
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class InvestigationWorkspaceNote(Base):
    __tablename__ = "investigation_workspace_notes"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    author_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    tags = Column(JSON, nullable=False, default=list)
    pinned = Column(Boolean, nullable=False, default=False)
    version = Column(Integer, nullable=False, default=1)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class InvestigationNoteRevision(Base):
    __tablename__ = "investigation_note_revisions"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    note_id = Column(String(36), ForeignKey("investigation_workspace_notes.id", ondelete="CASCADE"), nullable=False, index=True)
    version = Column(Integer, nullable=False)
    content = Column(Text, nullable=False)
    changed_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class InvestigationAttachment(Base):
    __tablename__ = "investigation_attachments"
    __table_args__ = (Index("ix_investigation_attachments_tenant_investigation", "tenant_id", "investigation_id", "created_at"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    uploaded_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    display_name = Column(String(255), nullable=False)
    safe_filename = Column(String(255), nullable=False)
    content_type = Column(String(100), nullable=False)
    size_bytes = Column(BigInteger, nullable=False)
    sha256 = Column(String(64), nullable=False)
    classification = Column(String(30), nullable=False, default="confidential")
    storage_status = Column(String(30), nullable=False, default="metadata_only")
    malware_scan_status = Column(String(30), nullable=False, default="not_stored")
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SearchExportJob(Base):
    __tablename__ = "search_export_jobs"
    __table_args__ = (Index("ix_search_export_tenant_status_expiry", "tenant_id", "status", "expires_at"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    requested_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="SET NULL"), nullable=True)
    job_type = Column(String(30), nullable=False, default="search_export")
    format = Column(String(20), nullable=False)
    status = Column(String(20), nullable=False, default="queued")
    definition = Column(JSON, nullable=False)
    result_count = Column(Integer, nullable=False, default=0)
    artifact_path = Column(Text, nullable=True)
    checksum = Column(String(64), nullable=True)
    manifest = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class Tenant(Base):
    __tablename__ = "tenants"
    __table_args__ = (
        Index("ix_tenants_status_created_at", "status", "created_at"),
        Index("ix_tenants_subscription_plan", "subscription_plan"),
        Index("ix_tenants_scheduled_purge_at", "scheduled_purge_at"),
        Index("ix_tenants_deletion_requested_by_id", "deletion_requested_by_id"),
    )
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    logo = Column(String(1024), nullable=True)
    industry = Column(String(255), nullable=True)
    country = Column(String(100), nullable=True)
    timezone = Column(String(100), nullable=False, default="UTC")
    subscription_plan = Column(String(100), nullable=False, default="starter")
    max_users = Column(Integer, nullable=False, default=25)
    max_collectors = Column(Integer, nullable=False, default=25)
    max_storage = Column(BigInteger, nullable=False, default=10737418240)
    status = Column(Enum(OrganizationStatus), nullable=False, default=OrganizationStatus.ACTIVE)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    deletion_pin_hash = Column(String(255), nullable=True)
    deletion_pin_failed_attempts = Column(Integer, nullable=False, default=0)
    deletion_pin_locked_until = Column(DateTime(timezone=True), nullable=True)
    deletion_requested_at = Column(DateTime(timezone=True), nullable=True)
    scheduled_purge_at = Column(DateTime(timezone=True), nullable=True)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    deletion_requested_by_id = Column(
        String(36),
        ForeignKey(
            "users.id",
            name="fk_tenants_deletion_requester",
            ondelete="SET NULL",
            use_alter=True,
        ),
        nullable=True,
    )
    sensitive_action_approval_mode = Column(String(20), nullable=False, default="none")
    permission_revision = Column(Integer, nullable=False, default=1)
    
    users = relationship("User", back_populates="tenant", foreign_keys="User.tenant_id")
    alert_sources = relationship("AlertSource", back_populates="tenant")
    alerts = relationship("Alert", back_populates="tenant")
    incidents = relationship("Incident", back_populates="tenant")
    audit_logs = relationship("AuditLog", back_populates="tenant")
    memberships = relationship("OrganizationMembership", back_populates="tenant", cascade="all, delete-orphan")
    invitations = relationship("OrganizationInvitation", back_populates="tenant", cascade="all, delete-orphan")
    usage_snapshots = relationship("OrganizationUsage", back_populates="tenant", cascade="all, delete-orphan")
    deletion_requested_by = relationship("User", foreign_keys=[deletion_requested_by_id])


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        Index("ix_users_tenant_role_active", "tenant_id", "role", "is_active"),
        Index("ix_users_tenant_created_at", "tenant_id", "created_at"),
        Index("ix_users_locked_until", "locked_until"),
    )
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(Enum(UserRole), default=UserRole.ANALYST)
    is_active = Column(Boolean, default=True)
    failed_login_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_failed_login_at = Column(DateTime(timezone=True), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    password_changed_at = Column(DateTime(timezone=True), nullable=True)
    mfa_secret_encrypted = Column(Text, nullable=True)
    mfa_secret_key_version = Column(Integer, nullable=True)
    mfa_pending_secret_encrypted = Column(Text, nullable=True)
    mfa_pending_secret_key_version = Column(Integer, nullable=True)
    mfa_pending_expires_at = Column(DateTime(timezone=True), nullable=True)
    mfa_enabled_at = Column(DateTime(timezone=True), nullable=True)
    mfa_last_totp_step = Column(BigInteger, nullable=True)
    mfa_failed_attempts = Column(Integer, nullable=False, default=0)
    mfa_locked_until = Column(DateTime(timezone=True), nullable=True)
    email_verified_at = Column(DateTime(timezone=True), nullable=True)
    email_verification_exempt = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    tenant = relationship("Tenant", back_populates="users", foreign_keys=[tenant_id])
    assigned_incidents = relationship(
        "Incident",
        back_populates="assigned_analyst",
        foreign_keys="Incident.assigned_to",
    )
    investigation_notes = relationship("InvestigationNote", back_populates="user")
    feedback = relationship("Feedback", back_populates="user")
    evidence = relationship("IncidentEvidence", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")
    refresh_tokens = relationship("RefreshToken", back_populates="user", foreign_keys="RefreshToken.user_id")
    auth_sessions = relationship("AuthSession", back_populates="user", cascade="all, delete-orphan")
    auth_security_events = relationship("AuthSecurityEvent", back_populates="user", cascade="all, delete-orphan")
    organization_memberships = relationship(
        "OrganizationMembership",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="OrganizationMembership.user_id",
    )
    organization_invitations = relationship("OrganizationInvitation", back_populates="invited_user", foreign_keys="OrganizationInvitation.invited_user_id")


class OrganizationMembership(Base):
    __tablename__ = "organization_memberships"
    __table_args__ = (
        Index("ix_org_memberships_tenant_role_active", "tenant_id", "role", "is_active"),
        Index("ix_org_memberships_user_active", "user_id", "is_active"),
        Index("ix_org_memberships_unique_user_tenant", "user_id", "tenant_id", unique=True),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    role = Column(Enum(OrganizationRole), nullable=False, default=OrganizationRole.ANALYST)
    custom_role_id = Column(String(36), ForeignKey("organization_custom_roles.id"), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    invited_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant", back_populates="memberships")
    user = relationship("User", back_populates="organization_memberships", foreign_keys=[user_id])
    invited_by_user = relationship("User", foreign_keys=[invited_by])
    custom_role = relationship("OrganizationCustomRole", back_populates="memberships")


class OrganizationCustomRole(Base):
    __tablename__ = "organization_custom_roles"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_org_custom_roles_tenant_name"),
        Index("ix_org_custom_roles_tenant", "tenant_id"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    name = Column(String(100), nullable=False)
    normalized_name = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    permissions = Column(JSON, nullable=False, default=list)
    is_system = Column(Boolean, nullable=False, default=False)
    is_protected = Column(Boolean, nullable=False, default=False)
    permission_revision = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    memberships = relationship("OrganizationMembership", back_populates="custom_role")


class OrganizationAPIKey(Base):
    __tablename__ = "organization_api_keys"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_organization_api_keys_tenant_name"),
        UniqueConstraint("key_hash", name="uq_organization_api_keys_hash"),
        Index("ix_organization_api_keys_tenant_revoked", "tenant_id", "revoked_at"),
        Index("ix_organization_api_keys_expires", "expires_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    name = Column(String(100), nullable=False)
    key_prefix = Column(String(24), nullable=False, index=True)
    key_hash = Column(String(64), nullable=False)
    scopes = Column(JSON, nullable=False, default=list)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revocation_reason = Column(String(100), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SensitiveActionApproval(Base):
    __tablename__ = "sensitive_action_approvals"
    __table_args__ = (
        Index("ix_sensitive_approvals_tenant_status", "tenant_id", "status"),
        Index("ix_sensitive_approvals_expires", "expires_at"),
        Index("ix_sensitive_approvals_target", "tenant_id", "action_type", "target_resource_id"),
        UniqueConstraint("tenant_id", "request_fingerprint", name="uq_sensitive_approval_fingerprint"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    requester_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = Column(String(100), nullable=False, index=True)
    target_resource_type = Column(String(100), nullable=False)
    target_resource_id = Column(String(36), nullable=False)
    request_fingerprint = Column(String(64), nullable=False)
    required_approvals = Column(Integer, nullable=False, default=1)
    status = Column(String(20), nullable=False, default="pending")
    safe_metadata = Column(JSON, nullable=False, default=dict)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    rejected_at = Column(DateTime(timezone=True), nullable=True)
    executed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SensitiveActionApprovalDecision(Base):
    __tablename__ = "sensitive_action_approval_decisions"
    __table_args__ = (
        UniqueConstraint("approval_id", "approver_id", name="uq_sensitive_approval_approver"),
        Index("ix_sensitive_approval_decisions_approval", "approval_id", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    approval_id = Column(
        String(36), ForeignKey("sensitive_action_approvals.id", ondelete="CASCADE"), nullable=False, index=True
    )
    approver_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    decision = Column(String(20), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class OrganizationInvitation(Base):
    __tablename__ = "organization_invitations"
    __table_args__ = (
        Index("ix_org_invitations_tenant_status", "tenant_id", "status"),
        Index("ix_org_invitations_email_status", "email", "status"),
        Index("ix_org_invitations_token_hash", "token_hash", unique=True),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    email = Column(String(255), nullable=False)
    role = Column(Enum(OrganizationRole), nullable=False, default=OrganizationRole.ANALYST)
    token_hash = Column(String(64), nullable=False)
    status = Column(Enum(InvitationStatus), nullable=False, default=InvitationStatus.PENDING)
    invited_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    invited_user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    accepted_at = Column(DateTime(timezone=True), nullable=True)
    rejected_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant", back_populates="invitations")
    invited_by_user = relationship("User", foreign_keys=[invited_by])
    invited_user = relationship("User", back_populates="organization_invitations", foreign_keys=[invited_user_id])


class OrganizationUsage(Base):
    __tablename__ = "organization_usage"
    __table_args__ = (
        Index("ix_org_usage_tenant_period", "tenant_id", "period_start", "period_end"),
        Index("ix_org_usage_snapshot_date", "snapshot_date"),
        UniqueConstraint("tenant_id", "snapshot_date", name="uq_org_usage_tenant_snapshot_date"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    user_count = Column(Integer, nullable=False, default=0)
    collector_count = Column(Integer, nullable=False, default=0)
    event_count = Column(Integer, nullable=False, default=0)
    alert_count = Column(Integer, nullable=False, default=0)
    incident_count = Column(Integer, nullable=False, default=0)
    playbook_count = Column(Integer, nullable=False, default=0)
    playbook_execution_count = Column(Integer, nullable=False, default=0)
    soar_execution_count = Column(Integer, nullable=False, default=0)
    triage_ai_request_count = Column(BigInteger, nullable=False, default=0)
    storage_bytes = Column(BigInteger, nullable=False, default=0)
    api_request_count = Column(BigInteger, nullable=False, default=0)
    snapshot_date = Column(Date, nullable=True)
    period_start = Column(DateTime(timezone=True), nullable=True)
    period_end = Column(DateTime(timezone=True), nullable=True)
    calculated_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("Tenant", back_populates="usage_snapshots")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    __table_args__ = (
        Index("ix_refresh_tokens_user_revoked_expires", "user_id", "revoked_at", "expires_at"),
        Index("ix_refresh_tokens_tenant_created_at", "tenant_id", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    jti = Column(String(64), nullable=False, unique=True, index=True)
    family_id = Column(String(36), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    replaced_by_token_id = Column(String(36), ForeignKey("refresh_tokens.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    user_agent = Column(String(512), nullable=True)
    ip_address = Column(String(64), nullable=True)
    session_id = Column(String(36), ForeignKey("auth_sessions.id", ondelete="CASCADE"), nullable=True, index=True)
    revocation_reason = Column(String(100), nullable=True)

    user = relationship("User", back_populates="refresh_tokens", foreign_keys=[user_id])
    tenant = relationship("Tenant")
    replaced_by_token = relationship("RefreshToken", remote_side=[id])
    session = relationship("AuthSession", back_populates="refresh_tokens")


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    __table_args__ = (
        Index("ix_auth_sessions_user_revoked_expires", "user_id", "revoked_at", "expires_at"),
        Index("ix_auth_sessions_tenant_created", "tenant_id", "created_at"),
        UniqueConstraint("family_id", name="uq_auth_sessions_family_id"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    family_id = Column(String(36), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_activity_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    ip_address = Column(String(64), nullable=True, index=True)
    user_agent = Column(String(512), nullable=True)
    device_label = Column(String(255), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revocation_reason = Column(String(100), nullable=True)

    user = relationship("User", back_populates="auth_sessions")
    refresh_tokens = relationship("RefreshToken", back_populates="session", cascade="all, delete-orphan")


class AuthChallenge(Base):
    __tablename__ = "auth_challenges"
    __table_args__ = (
        Index("ix_auth_challenges_user_expires", "user_id", "expires_at"),
        UniqueConstraint("jti", name="uq_auth_challenges_jti"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    jti = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    failed_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(512), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class MFARecoveryCode(Base):
    __tablename__ = "mfa_recovery_codes"
    __table_args__ = (
        Index("ix_mfa_recovery_codes_user_used", "user_id", "used_at"),
        UniqueConstraint("code_hash", name="uq_mfa_recovery_code_hash"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    code_hash = Column(String(64), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuthOneTimeToken(Base):
    __tablename__ = "auth_one_time_tokens"
    __table_args__ = (
        Index("ix_auth_one_time_tokens_user_purpose_created", "user_id", "purpose", "created_at"),
        Index("ix_auth_one_time_tokens_expires", "expires_at"),
        UniqueConstraint("token_hash", name="uq_auth_one_time_token_hash"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    purpose = Column(String(32), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    requested_ip = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuthSecurityEvent(Base):
    __tablename__ = "auth_security_events"
    __table_args__ = (
        Index("ix_auth_security_events_user_created", "user_id", "created_at"),
        Index("ix_auth_security_events_tenant_created", "tenant_id", "created_at"),
        Index("ix_auth_security_events_user_severity", "user_id", "severity"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    result = Column(String(32), nullable=False)
    severity = Column(String(32), nullable=False, default="informational")
    reason_code = Column(String(100), nullable=True)
    ip_address = Column(String(64), nullable=True, index=True)
    user_agent = Column(String(512), nullable=True)
    device_label = Column(String(255), nullable=True)
    request_id = Column(String(128), nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    user = relationship("User", back_populates="auth_security_events")


class KnownAuthDevice(Base):
    __tablename__ = "known_auth_devices"
    __table_args__ = (
        UniqueConstraint("user_id", "fingerprint_hash", name="uq_known_auth_device_user_fingerprint"),
        Index("ix_known_auth_devices_user_last_seen", "user_id", "last_seen_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    fingerprint_hash = Column(String(64), nullable=False)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(512), nullable=True)
    device_label = Column(String(255), nullable=True)
    first_seen_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AlertSource(Base):
    __tablename__ = "alert_sources"
    __table_args__ = (
        Index("ix_alert_sources_tenant_name", "tenant_id", "name"),
        Index("ix_alert_sources_tenant_enabled", "tenant_id", "enabled"),
    )
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    name = Column(String(255), nullable=False)
    type = Column(Enum(AlertSourceType), default=AlertSourceType.WEBHOOK)
    api_key_hash = Column(String(255), nullable=True)
    enabled = Column(Boolean, default=True)
    config = Column(JSON, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    tenant = relationship("Tenant", back_populates="alert_sources")
    alerts = relationship("Alert", back_populates="source")


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_source_id", "source_id"),
        Index("ix_alerts_detection_rule_id", "detection_rule_id"),
        Index("ix_alerts_tenant_status_created_at", "tenant_id", "status", "created_at"),
        Index("ix_alerts_tenant_severity_created_at", "tenant_id", "severity", "created_at"),
        Index("ix_alerts_correlation_candidates", "tenant_id", "incident_id", "status", "created_at"),
        Index("ix_alerts_tenant_event_id", "tenant_id", "event_id"),
        UniqueConstraint("tenant_id", "event_id", "detection_rule_id", name="uq_alerts_tenant_event_rule"),
    )
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    source_id = Column(String(36), ForeignKey("alert_sources.id"), nullable=False)
    detection_rule_id = Column(String(36), ForeignKey("detection_rules.id"), nullable=True)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=True)
    event_id = Column(String(36), ForeignKey("security_events.id"), nullable=True)
    ocsf_data = Column(JSON, nullable=False)
    raw_data = Column(JSON, nullable=True)
    risk_score = Column(Float, nullable=True)
    severity = Column(Enum(Severity), default=Severity.MEDIUM)
    status = Column(Enum(AlertStatus), default=AlertStatus.OPEN)
    matched_condition = Column(Text, nullable=True)
    why_matched = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    processed_at = Column(DateTime(timezone=True), nullable=True)
    
    tenant = relationship("Tenant", back_populates="alerts")
    source = relationship("AlertSource", back_populates="alerts")
    detection_rule = relationship("DetectionRule")
    incident = relationship("Incident", back_populates="alerts")
    incident_associations = relationship("IncidentAlert", back_populates="alert")
    event = relationship("SecurityEvent")
    detection_matches = relationship("DetectionMatch", back_populates="alert")


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_assigned_to", "assigned_to"),
        Index("ix_incidents_tenant_priority", "tenant_id", "priority"),
        Index("ix_incidents_tenant_updated_at", "tenant_id", "updated_at"),
        Index("ix_incidents_tenant_status_updated_at", "tenant_id", "status", "updated_at"),
    )
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    risk_score = Column(Float, nullable=True)
    severity = Column(Enum(Severity), default=Severity.MEDIUM)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN)
    ai_summary = Column(Text, nullable=True)
    why_suspicious = Column(Text, nullable=True)
    ai_analyzed_at = Column(DateTime(timezone=True), nullable=True)
    attack_technique = Column(JSON, nullable=True)
    recommended_actions = Column(JSON, nullable=True)
    threat_intel_results = Column(JSON, nullable=True)
    creation_source = Column(String(64), nullable=False, default="manual")
    provenance_status = Column(String(32), nullable=False, default="manual")
    creation_reason = Column(Text, nullable=True)
    primary_alert_id = Column(String(36), nullable=True)
    correlation_rule_id = Column(String(36), nullable=True)
    correlation_rule_name = Column(String(255), nullable=True)
    correlation_key = Column(String(255), nullable=True)
    correlation_score = Column(Float, nullable=True)
    correlation_window_start = Column(DateTime(timezone=True), nullable=True)
    correlation_window_end = Column(DateTime(timezone=True), nullable=True)
    first_seen_at = Column(DateTime(timezone=True), nullable=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    risk_score_breakdown = Column(JSON, nullable=True)
    severity_reason = Column(Text, nullable=True)
    attack_summary = Column(Text, nullable=True)
    status_reason = Column(Text, nullable=True)
    classification = Column(Enum(Classification), nullable=True)
    priority = Column(Enum(IncidentPriority), default=IncidentPriority.P3)
    due_date = Column(DateTime(timezone=True), nullable=True)
    escalation_level = Column(Integer, nullable=False, default=0)
    assigned_to = Column(String(36), ForeignKey("users.id"), nullable=True)
    assigned_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    
    tenant = relationship("Tenant", back_populates="incidents")
    assigned_analyst = relationship("User", back_populates="assigned_incidents", foreign_keys=[assigned_to])
    alerts = relationship("Alert", back_populates="incident")
    incident_alerts = relationship("IncidentAlert", back_populates="incident")
    investigation_notes = relationship("InvestigationNote", back_populates="incident")
    feedback = relationship("Feedback", back_populates="incident")
    evidence = relationship("IncidentEvidence", back_populates="incident")
    threat_intel = relationship("ThreatIntel", back_populates="incident")
    iocs = relationship("IncidentIOC", back_populates="incident", cascade="all, delete-orphan")
    ai_artifacts = relationship("AIInvestigationArtifact", back_populates="incident", cascade="all, delete-orphan")
    ai_conversations = relationship("AIInvestigationConversation", back_populates="incident", cascade="all, delete-orphan")
    entities = relationship("IncidentEntity", back_populates="incident", cascade="all, delete-orphan")
    mitre_mappings = relationship("IncidentMitreMapping", back_populates="incident", cascade="all, delete-orphan")


class IncidentMitreMapping(Base):
    __tablename__ = "incident_mitre_mappings"
    __table_args__ = (
        UniqueConstraint("incident_id", "technique_id", name="uq_incident_mitre_mapping"),
        Index("ix_incident_mitre_tenant_tactic", "tenant_id", "tactic"),
        Index("ix_incident_mitre_tenant_technique", "tenant_id", "technique_id"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    tactic = Column(String(100), nullable=False)
    technique_id = Column(String(50), nullable=False)
    technique_name = Column(String(255), nullable=False)
    parent_technique_id = Column(String(50), nullable=False, default="")
    parent_technique_name = Column(String(255), nullable=False, default="")
    sub_technique_id = Column(String(50), nullable=True)
    sub_technique_name = Column(String(255), nullable=True)
    mapping_source = Column(String(32), nullable=False, default="correlated")
    confidence = Column(Float, nullable=False, default=0)
    confidence_reasons = Column(JSON, nullable=False, default=list)
    supporting_evidence = Column(JSON, nullable=False, default=list)
    source_alert_ids = Column(JSON, nullable=False, default=list)
    stage_order = Column(Integer, nullable=False, default=0)
    first_seen_at = Column(DateTime(timezone=True), nullable=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    incident = relationship("Incident", back_populates="mitre_mappings")


class AIInvestigationArtifact(Base):
    __tablename__ = "ai_investigation_artifacts"
    __table_args__ = (
        Index("ix_ai_artifacts_tenant_type_created_at", "tenant_id", "artifact_type", "created_at"),
        Index("ix_ai_artifacts_incident_type_created_at", "incident_id", "artifact_type", "created_at"),
        Index("ix_ai_artifacts_alert_type_created_at", "alert_id", "artifact_type", "created_at"),
        Index("ix_ai_artifacts_ioc_type_created_at", "ioc_id", "artifact_type", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=True)
    alert_id = Column(String(36), ForeignKey("alerts.id"), nullable=True)
    ioc_id = Column(String(36), ForeignKey("iocs.id"), nullable=True)
    artifact_type = Column(Enum(AIArtifactType), nullable=False)
    prompt_hash = Column(String(64), nullable=False, index=True)
    model = Column(String(100), nullable=False)
    content = Column(JSON, nullable=False)
    confidence_score = Column(Float, nullable=True)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("Tenant")
    incident = relationship("Incident", back_populates="ai_artifacts")
    alert = relationship("Alert")
    ioc = relationship("IOC")
    created_by_user = relationship("User", foreign_keys=[created_by])


class AIInvestigationConversation(Base):
    __tablename__ = "ai_investigation_conversations"
    __table_args__ = (
        Index("ix_ai_conversations_tenant_incident_created_at", "tenant_id", "incident_id", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    title = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    incident = relationship("Incident", back_populates="ai_conversations")
    user = relationship("User")
    messages = relationship("AIInvestigationMessage", back_populates="conversation", cascade="all, delete-orphan")


class AIInvestigationMessage(Base):
    __tablename__ = "ai_investigation_messages"
    __table_args__ = (
        Index("ix_ai_messages_conversation_created_at", "conversation_id", "created_at"),
        Index("ix_ai_messages_tenant_created_at", "tenant_id", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    conversation_id = Column(String(36), ForeignKey("ai_investigation_conversations.id"), nullable=False)
    role = Column(String(20), nullable=False)
    content = Column(Text, nullable=False)
    message_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("Tenant")
    conversation = relationship("AIInvestigationConversation", back_populates="messages")


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    __table_args__ = (
        UniqueConstraint("incident_id", "alert_id", name="uq_incident_alerts_incident_alert"),
        UniqueConstraint("alert_id", name="uq_incident_alerts_alert_id"),
        Index("ix_incident_alerts_incident_id", "incident_id"),
        Index("ix_incident_alerts_alert_id", "alert_id"),
        Index("ix_incident_alerts_incident_alert", "incident_id", "alert_id"),
    )
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    alert_id = Column(String(36), ForeignKey("alerts.id"), nullable=False)
    correlation_score = Column(Float, nullable=False)
    correlation_reason = Column(Text, nullable=True)
    is_primary = Column(Boolean, nullable=False, default=False)
    attachment_reason = Column(Text, nullable=True)
    sequence_order = Column(Integer, nullable=False, default=0)
    risk_contribution = Column(Float, nullable=True)
    matching_entities = Column(JSON, nullable=True)
    matching_indicators = Column(JSON, nullable=True)
    time_delta_seconds = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    incident = relationship("Incident", back_populates="incident_alerts")
    alert = relationship("Alert", back_populates="incident_associations")


class IncidentIOC(Base):
    __tablename__ = "incident_iocs"
    __table_args__ = (
        Index("ix_incident_iocs_tenant_incident", "tenant_id", "incident_id"),
        Index("ix_incident_iocs_tenant_ioc", "tenant_id", "ioc_id"),
        Index("ix_incident_iocs_unique_link", "tenant_id", "incident_id", "ioc_id"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    ioc_id = Column(String(36), ForeignKey("iocs.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("Tenant")
    incident = relationship("Incident", back_populates="iocs")
    ioc = relationship("IOC", back_populates="incidents")


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"
    __table_args__ = (
        Index("ix_investigation_notes_incident_created_at", "incident_id", "created_at"),
        Index("ix_investigation_notes_user_created_at", "user_id", "created_at"),
    )
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    incident = relationship("Incident", back_populates="investigation_notes")
    user = relationship("User", back_populates="investigation_notes")


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"
    __table_args__ = (
        Index("ix_incident_evidence_incident_created_at", "incident_id", "created_at"),
        Index("ix_incident_evidence_user_created_at", "user_id", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    source_event_id = Column(String(36), ForeignKey("security_events.id"), nullable=True)
    source_alert_id = Column(String(36), ForeignKey("alerts.id"), nullable=True)
    source_entity_id = Column(String(36), ForeignKey("incident_entities.id"), nullable=True)
    type = Column(Enum(EvidenceType), nullable=False)
    value = Column(String(1024), nullable=False)
    description = Column(Text, nullable=True)
    confidence = Column(Float, nullable=True)
    risk_contribution = Column(Float, nullable=True)
    evidence_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    incident = relationship("Incident", back_populates="evidence")
    user = relationship("User", back_populates="evidence")


class IncidentEntity(Base):
    __tablename__ = "incident_entities"
    __table_args__ = (
        Index("ix_incident_entities_tenant_incident", "tenant_id", "incident_id"),
        Index("ix_incident_entities_incident_type", "incident_id", "entity_type"),
        Index("ix_incident_entities_source_event", "source_event_id"),
        Index("ix_incident_entities_source_alert", "source_alert_id"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    entity_type = Column(String(40), nullable=False)
    value = Column(String(2048), nullable=False)
    normalized_value = Column(String(2048), nullable=False)
    role = Column(String(80), nullable=True)
    first_seen_at = Column(DateTime(timezone=True), nullable=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    source_event_id = Column(String(36), ForeignKey("security_events.id"), nullable=True)
    source_alert_id = Column(String(36), ForeignKey("alerts.id"), nullable=True)
    confidence = Column(Float, nullable=True)
    risk_contribution = Column(Float, nullable=True)
    entity_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    incident = relationship("Incident", back_populates="entities")
    source_event = relationship("SecurityEvent", foreign_keys=[source_event_id])
    source_alert = relationship("Alert", foreign_keys=[source_alert_id])


class Feedback(Base):
    __tablename__ = "feedback"
    __table_args__ = (
        Index("ix_feedback_tenant_incident", "tenant_id", "incident_id"),
        Index("ix_feedback_user_created_at", "user_id", "created_at"),
        Index("ix_feedback_tenant_classification", "tenant_id", "classification"),
    )
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    classification = Column(Enum(Classification), nullable=False)
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    incident = relationship("Incident", back_populates="feedback")
    user = relationship("User", back_populates="feedback")


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"
    __table_args__ = (
        Index("ix_threat_intel_cache_indicator_type_source", "indicator", "indicator_type", "source"),
        Index("ix_threat_intel_cache_expires_at", "expires_at"),
    )
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    indicator = Column(String(255), nullable=False, index=True)
    indicator_type = Column(indicator_type_enum(), nullable=False)
    data = Column(JSON, nullable=False)
    source = Column(String(100), nullable=False)
    cached_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)


class ThreatIntel(Base):
    __tablename__ = "threat_intel"
    __table_args__ = (
        Index("ix_threat_intel_tenant_indicator", "tenant_id", "indicator"),
        Index("ix_threat_intel_incident_id", "incident_id"),
        Index("ix_threat_intel_tenant_created_at", "tenant_id", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=True)
    indicator = Column(String(255), nullable=False, index=True)
    type = Column(indicator_type_enum(), nullable=False)
    source = Column(String(100), nullable=False)
    result = Column(JSON, nullable=False)
    risk_impact = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("Tenant")
    incident = relationship("Incident", back_populates="threat_intel")


class IOC(Base):
    __tablename__ = "iocs"
    __table_args__ = (
        Index("ix_iocs_tenant_type_value", "tenant_id", "type", "value"),
        UniqueConstraint("tenant_id", "type", "normalized_value", name="uq_iocs_tenant_type_normalized"),
        Index("ix_iocs_tenant_active_created_at", "tenant_id", "is_active", "created_at"),
        Index("ix_iocs_tenant_lifecycle_risk", "tenant_id", "lifecycle_status", "risk_score"),
        Index("ix_iocs_tenant_expiration", "tenant_id", "valid_until"),
        Index("ix_iocs_tenant_sightings", "tenant_id", "last_internal_sighting"),
        Index("ix_iocs_content_hash", "content_hash"),
        Index("ix_iocs_created_by", "created_by"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    type = Column(indicator_type_enum(), nullable=False)
    value = Column(String(1024), nullable=False, index=True)
    original_value = Column(String(2048), nullable=True)
    normalized_value = Column(String(2048), nullable=True)
    display_value = Column(String(2048), nullable=True)
    description = Column(Text, nullable=True)
    source = Column(String(255), nullable=True)
    severity = Column(Enum(Severity), default=Severity.MEDIUM)
    confidence_score = Column(Integer, default=0)  # 0-100
    source_reliability = Column(Integer, nullable=False, default=50)
    risk_score = Column(Integer, nullable=False, default=0)
    risk_reasons = Column(JSON, nullable=False, default=list)
    risk_score_version = Column(String(30), nullable=False, default="1.0")
    lifecycle_status = Column(String(30), nullable=False, default="new")
    review_status = Column(String(30), nullable=False, default="pending")
    reviewed_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    valid_from = Column(DateTime(timezone=True), nullable=True)
    valid_until = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    expired_at = Column(DateTime(timezone=True), nullable=True)
    tlp = Column(String(30), nullable=False, default="TLP:AMBER")
    source_references = Column(JSON, nullable=False, default=list)
    stix_id = Column(String(255), nullable=True)
    external_source_ids = Column(JSON, nullable=False, default=dict)
    internal_sighting_count = Column(Integer, nullable=False, default=0)
    first_internal_sighting = Column(DateTime(timezone=True), nullable=True)
    last_internal_sighting = Column(DateTime(timezone=True), nullable=True)
    enrichment_status = Column(String(30), nullable=False, default="pending")
    last_enriched_at = Column(DateTime(timezone=True), nullable=True)
    next_enrichment_at = Column(DateTime(timezone=True), nullable=True)
    false_positive = Column(Boolean, nullable=False, default=False)
    allowlisted = Column(Boolean, nullable=False, default=False)
    classification = Column(String(50), nullable=True)
    content_hash = Column(String(64), nullable=True)
    merged_from_ids = Column(JSON, nullable=False, default=list)
    tags = Column(JSON, nullable=True)  # list of strings
    is_active = Column(Boolean, default=True)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    created_by_user = relationship("User", foreign_keys=[created_by])
    reviewed_by_user = relationship("User", foreign_keys=[reviewed_by])
    enrichments = relationship("IOCEnrichment", back_populates="ioc", cascade="all, delete-orphan")
    incidents = relationship("IncidentIOC", back_populates="ioc", cascade="all, delete-orphan")
    sightings = relationship("IOCSighting", back_populates="ioc", cascade="all, delete-orphan")


class IOCEnrichment(Base):
    __tablename__ = "ioc_enrichments"
    __table_args__ = (
        Index("ix_ioc_enrichments_ioc_provider_created_at", "ioc_id", "provider", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ioc_id = Column(String(36), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(100), nullable=False)  # e.g., "virustotal", "abuseipdb", "otx"
    reputation = Column(String(50), nullable=True)  # e.g., "malicious", "suspicious", "clean"
    malicious_count = Column(Integer, default=0)
    total_reports = Column(Integer, default=0)
    raw_response = Column(JSON, nullable=True)
    provider_verdict = Column(String(50), nullable=True)
    confidence = Column(Integer, nullable=True)
    categories = Column(JSON, nullable=False, default=list)
    detection_counts = Column(JSON, nullable=False, default=dict)
    provider_first_seen = Column(DateTime(timezone=True), nullable=True)
    provider_last_seen = Column(DateTime(timezone=True), nullable=True)
    provider_references = Column(JSON, nullable=False, default=list)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    raw_response_hash = Column(String(64), nullable=True)
    safe_result = Column(JSON, nullable=False, default=dict)
    failure_code = Column(String(80), nullable=True)
    retryable = Column(Boolean, nullable=False, default=False)
    response_version = Column(String(30), nullable=False, default="1.0")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    ioc = relationship("IOC", back_populates="enrichments")


class IOCScoreHistory(Base):
    __tablename__ = "ioc_score_history"
    __table_args__ = (Index("ix_ioc_score_history_tenant_ioc_created", "tenant_id", "ioc_id", "created_at"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ioc_id = Column(String(36), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    score = Column(Integer, nullable=False)
    version = Column(String(30), nullable=False, default="1.0")
    reasons = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IOCSighting(Base):
    __tablename__ = "ioc_sightings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "ioc_id", "event_id", "matched_field", name="uq_ioc_sighting_event_field"),
        Index("ix_ioc_sightings_tenant_last", "tenant_id", "last_observed"),
        Index("ix_ioc_sightings_tenant_ioc_first", "tenant_id", "ioc_id", "first_observed"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ioc_id = Column(String(36), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    ioc_content_hash = Column(String(64), nullable=False)
    event_id = Column(String(36), ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False)
    alert_id = Column(String(36), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    entity_id = Column(String(36), ForeignKey("entities.id", ondelete="SET NULL"), nullable=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    collector_id = Column(String(36), ForeignKey("collectors.id", ondelete="SET NULL"), nullable=True)
    user_value = Column(String(255), nullable=True)
    host = Column(String(255), nullable=True)
    source_ip = Column(String(64), nullable=True)
    destination_ip = Column(String(64), nullable=True)
    data_source = Column(String(255), nullable=True)
    matched_field = Column(String(255), nullable=False)
    matched_value = Column(String(2048), nullable=False)
    first_observed = Column(DateTime(timezone=True), nullable=False)
    last_observed = Column(DateTime(timezone=True), nullable=False)
    observation_count = Column(Integer, nullable=False, default=1)
    confidence = Column(Integer, nullable=False, default=100)
    detection_source = Column(String(80), nullable=False, default="continuous_match")
    match_method = Column(String(50), nullable=False, default="exact")
    false_positive = Column(Boolean, nullable=False, default=False)
    false_positive_reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    ioc = relationship("IOC", back_populates="sightings")


class IOCWatchlist(Base):
    __tablename__ = "ioc_watchlists"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_ioc_watchlists_tenant_name"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    owner_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    collaborators = Column(JSON, nullable=False, default=list)
    tags = Column(JSON, nullable=False, default=list)
    policies = Column(JSON, nullable=False, default=dict)
    tlp = Column(String(30), nullable=False, default="TLP:AMBER")
    status = Column(String(30), nullable=False, default="active")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class IOCWatchlistMember(Base):
    __tablename__ = "ioc_watchlist_members"
    __table_args__ = (
        UniqueConstraint("tenant_id", "watchlist_id", "ioc_id", name="uq_ioc_watchlist_member"),
        Index("ix_ioc_watchlist_members_tenant_watchlist", "tenant_id", "watchlist_id"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    watchlist_id = Column(String(36), ForeignKey("ioc_watchlists.id", ondelete="CASCADE"), nullable=False)
    ioc_id = Column(String(36), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IOCListEntry(Base):
    __tablename__ = "ioc_list_entries"
    __table_args__ = (
        UniqueConstraint("tenant_id", "list_kind", "ioc_type", "normalized_value", name="uq_ioc_list_entry"),
        Index("ix_ioc_list_entries_tenant_kind_status", "tenant_id", "list_kind", "status"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    list_kind = Column(String(20), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    ioc_type = Column(String(50), nullable=False)
    normalized_value = Column(String(2048), nullable=False)
    reason = Column(Text, nullable=False)
    source = Column(String(255), nullable=True)
    starts_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status = Column(String(30), nullable=False, default="active")
    scope = Column(String(30), nullable=False, default="organization")
    tags = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IOCHuntJob(Base):
    __tablename__ = "ioc_hunt_jobs"
    __table_args__ = (Index("ix_ioc_hunt_jobs_tenant_status", "tenant_id", "status"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ioc_id = Column(String(36), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    requested_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status = Column(String(30), nullable=False, default="pending")
    query = Column(JSON, nullable=False, default=dict)
    progress = Column(Integer, nullable=False, default=0)
    events_scanned = Column(Integer, nullable=False, default=0)
    matches_found = Column(Integer, nullable=False, default=0)
    truncated = Column(Boolean, nullable=False, default=False)
    cancellation_requested = Column(Boolean, nullable=False, default=False)
    error_code = Column(String(80), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class ThreatIntelligenceRelationship(Base):
    __tablename__ = "threat_intelligence_relationships"
    __table_args__ = (
        UniqueConstraint("tenant_id", "source_type", "source_id", "relationship_type", "target_type", "target_id", name="uq_threat_relationship"),
        Index("ix_threat_relationships_tenant_source", "tenant_id", "source_type", "source_id"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    relationship_type = Column(String(80), nullable=False)
    source_type = Column(String(50), nullable=False)
    source_id = Column(String(255), nullable=False)
    target_type = Column(String(50), nullable=False)
    target_id = Column(String(255), nullable=False)
    confidence = Column(Integer, nullable=False, default=50)
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    source = Column(String(255), nullable=True)
    evidence_references = Column(JSON, nullable=False, default=list)
    status = Column(String(30), nullable=False, default="active")
    origin = Column(String(30), nullable=False, default="analyst_created")
    external_ids = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ThreatSourceCredential(Base):
    __tablename__ = "threat_source_credentials"
    __table_args__ = (
        UniqueConstraint("tenant_id", "provider", "name", name="uq_threat_source_tenant_provider_name"),
        Index("ix_threat_source_tenant_provider_status", "tenant_id", "provider", "status"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(30), nullable=False)
    name = Column(String(150), nullable=False)
    base_url = Column(String(2048), nullable=True)
    encrypted_credentials = Column(Text, nullable=False)
    encryption_key_version = Column(Integer, nullable=False, default=1)
    credential_fingerprint = Column(String(64), nullable=False)
    safe_metadata = Column(JSON, nullable=False, default=dict)
    status = Column(String(30), nullable=False, default="active")
    tls_verify = Column(Boolean, nullable=False, default=True)
    last_tested_at = Column(DateTime(timezone=True), nullable=True)
    last_successful_use_at = Column(DateTime(timezone=True), nullable=True)
    last_rotated_at = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatSyncConfiguration(Base):
    __tablename__ = "threat_sync_configurations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "provider", "name", name="uq_threat_sync_tenant_provider_name"),
        Index("ix_threat_sync_tenant_provider_enabled", "tenant_id", "provider", "enabled"),
        Index("ix_threat_sync_cursor", "tenant_id", "provider", "cursor_updated_at"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    credential_id = Column(String(36), ForeignKey("threat_source_credentials.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(20), nullable=False)
    name = Column(String(150), nullable=False)
    api_root = Column(String(2048), nullable=True)
    collection_id = Column(String(255), nullable=True)
    settings = Column(JSON, nullable=False, default=dict)
    safe_cursor = Column(JSON, nullable=False, default=dict)
    cursor_updated_at = Column(DateTime(timezone=True), nullable=True)
    schedule_seconds = Column(Integer, nullable=True)
    next_run_at = Column(DateTime(timezone=True), nullable=True)
    enabled = Column(Boolean, nullable=False, default=False)
    created_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatSyncJob(Base):
    __tablename__ = "threat_sync_jobs"
    __table_args__ = (
        Index("ix_threat_sync_jobs_tenant_status", "tenant_id", "status", "created_at"),
        Index("ix_threat_sync_jobs_configuration", "tenant_id", "configuration_id", "created_at"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    configuration_id = Column(String(36), ForeignKey("threat_sync_configurations.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(20), nullable=False)
    direction = Column(String(20), nullable=False, default="pull")
    status = Column(String(30), nullable=False, default="pending")
    progress = Column(Integer, nullable=False, default=0)
    counts = Column(JSON, nullable=False, default=dict)
    failure_code = Column(String(80), nullable=True)
    failure_details = Column(JSON, nullable=False, default=dict)
    cancellation_requested = Column(Boolean, nullable=False, default=False)
    requested_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IOCImportJob(Base):
    __tablename__ = "ioc_import_jobs"
    __table_args__ = (
        Index("ix_ioc_import_jobs_tenant_status", "tenant_id", "status", "created_at"),
        Index("ix_ioc_import_jobs_expires", "expires_at"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    format = Column(String(20), nullable=False)
    original_filename = Column(String(255), nullable=False)
    artifact_key = Column(String(1024), nullable=False)
    artifact_checksum = Column(String(64), nullable=False)
    encrypted_artifact = Column(Boolean, nullable=False, default=True)
    status = Column(String(30), nullable=False, default="uploaded")
    dry_run = Column(Boolean, nullable=False, default=True)
    options = Column(JSON, nullable=False, default=dict)
    counts = Column(JSON, nullable=False, default=dict)
    progress = Column(Integer, nullable=False, default=0)
    cancellation_requested = Column(Boolean, nullable=False, default=False)
    error_code = Column(String(80), nullable=True)
    requested_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class IOCImportRowResult(Base):
    __tablename__ = "ioc_import_row_results"
    __table_args__ = (
        UniqueConstraint("job_id", "row_number", name="uq_ioc_import_row"),
        Index("ix_ioc_import_rows_tenant_job_status", "tenant_id", "job_id", "status"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    job_id = Column(String(36), ForeignKey("ioc_import_jobs.id", ondelete="CASCADE"), nullable=False)
    row_number = Column(Integer, nullable=False)
    status = Column(String(30), nullable=False)
    ioc_id = Column(String(36), ForeignKey("iocs.id", ondelete="SET NULL"), nullable=True)
    error_code = Column(String(80), nullable=True)
    safe_details = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IOCBulkActionJob(Base):
    __tablename__ = "ioc_bulk_action_jobs"
    __table_args__ = (Index("ix_ioc_bulk_jobs_tenant_status", "tenant_id", "status", "created_at"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    action = Column(String(50), nullable=False)
    status = Column(String(30), nullable=False, default="pending")
    preview = Column(JSON, nullable=False, default=dict)
    request = Column(JSON, nullable=False, default=dict)
    results = Column(JSON, nullable=False, default=list)
    progress = Column(Integer, nullable=False, default=0)
    cancellation_requested = Column(Boolean, nullable=False, default=False)
    requested_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class IOCReviewAssignment(Base):
    __tablename__ = "ioc_review_assignments"
    __table_args__ = (
        Index("ix_ioc_review_tenant_reviewer_status", "tenant_id", "reviewer_id", "status"),
        Index("ix_ioc_review_tenant_due", "tenant_id", "due_at"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ioc_id = Column(String(36), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    reviewer_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    assigned_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status = Column(String(30), nullable=False, default="assigned")
    due_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class IOCReviewHistory(Base):
    __tablename__ = "ioc_review_history"
    __table_args__ = (Index("ix_ioc_review_history_tenant_ioc", "tenant_id", "ioc_id", "created_at"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ioc_id = Column(String(36), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    assignment_id = Column(String(36), ForeignKey("ioc_review_assignments.id", ondelete="SET NULL"), nullable=True)
    actor_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(50), nullable=False)
    comment = Column(Text, nullable=True)
    revision = Column(Integer, nullable=False, default=1)
    before_values = Column(JSON, nullable=False, default=dict)
    after_values = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IOCResponseRecommendation(Base):
    __tablename__ = "ioc_response_recommendations"
    __table_args__ = (
        Index("ix_ioc_response_tenant_status", "tenant_id", "status", "expires_at"),
        UniqueConstraint("tenant_id", "request_fingerprint", name="uq_ioc_response_fingerprint"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ioc_id = Column(String(36), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    action = Column(String(80), nullable=False)
    target_connector_type = Column(String(80), nullable=True)
    safe_context = Column(JSON, nullable=False, default=dict)
    request_fingerprint = Column(String(64), nullable=False)
    requester_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approval_id = Column(String(36), ForeignKey("sensitive_action_approvals.id", ondelete="SET NULL"), nullable=True)
    status = Column(String(30), nullable=False, default="pending_approval")
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class IOCNotificationState(Base):
    __tablename__ = "ioc_notification_states"
    __table_args__ = (
        UniqueConstraint("tenant_id", "deduplication_key", name="uq_ioc_notification_dedup"),
        Index("ix_ioc_notification_tenant_cooldown", "tenant_id", "cooldown_until"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ioc_id = Column(String(36), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=True)
    watchlist_id = Column(String(36), ForeignKey("ioc_watchlists.id", ondelete="CASCADE"), nullable=True)
    event_type = Column(String(80), nullable=False)
    deduplication_key = Column(String(64), nullable=False)
    delivery_status = Column(String(30), nullable=False, default="pending")
    recipient_scope = Column(JSON, nullable=False, default=dict)
    cooldown_until = Column(DateTime(timezone=True), nullable=False)
    last_delivered_at = Column(DateTime(timezone=True), nullable=True)
    delivery_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IOCReportJob(Base):
    __tablename__ = "ioc_report_jobs"
    __table_args__ = (
        Index("ix_ioc_report_tenant_status", "tenant_id", "status", "created_at"),
        Index("ix_ioc_report_expires", "expires_at"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    report_type = Column(String(80), nullable=False)
    format = Column(String(20), nullable=False)
    status = Column(String(30), nullable=False, default="pending")
    filters = Column(JSON, nullable=False, default=dict)
    artifact_key = Column(String(1024), nullable=True)
    checksum = Column(String(64), nullable=True)
    manifest = Column(JSON, nullable=False, default=dict)
    error_code = Column(String(80), nullable=True)
    requested_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (
        Index("ix_detection_rules_tenant_enabled", "tenant_id", "enabled"),
        Index("ix_detection_rules_tenant_event_type", "tenant_id", "event_type"),
        Index("ix_detection_rules_created_by", "created_by"),
        UniqueConstraint("tenant_id", "sigma_rule_id", name="uq_detection_rules_tenant_sigma_id"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    # Backward compatibility fields
    type = Column(Enum(RuleType), default=RuleType.CUSTOM)
    query = Column(Text, nullable=True)  # Allow null now
    sigma_rule = Column(Text, nullable=True)  # Allow null now
    # New Phase 16 fields
    rule_type = Column(Enum(RuleType), default=RuleType.CUSTOM)
    rule_content = Column(JSON, nullable=True)  # New field for Phase 6
    event_type = Column(Enum(EventType), nullable=True)
    severity = Column(Enum(Severity), default=Severity.MEDIUM)
    enabled = Column(Boolean, default=True)
    condition = Column(JSON, nullable=True)
    mitre_technique_id = Column(String(50), nullable=True)
    sigma_rule_id = Column(String(100), nullable=True)
    lifecycle_status = Column(String(30), nullable=False, default="draft")
    detection_kind = Column(String(30), nullable=False, default="event_match")
    current_version_id = Column(String(36), nullable=True)
    production_version_id = Column(String(36), nullable=True)
    owner_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    team = Column(String(120), nullable=True)
    confidence = Column(Float, nullable=False, default=0.5)
    risk_contribution = Column(Integer, nullable=False, default=0)
    tags = Column(JSON, nullable=False, default=list)
    mitre_mappings = Column(JSON, nullable=False, default=list)
    data_source_requirements = Column(JSON, nullable=False, default=list)
    alert_policy = Column(JSON, nullable=False, default=dict)
    protected = Column(Boolean, nullable=False, default=False)
    last_triggered_at = Column(DateTime(timezone=True), nullable=True)
    last_tested_at = Column(DateTime(timezone=True), nullable=True)
    retired_at = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    created_by_user = relationship("User", foreign_keys=[created_by])
    detection_matches = relationship("DetectionMatch", back_populates="rule", cascade="all, delete-orphan")


class DetectionRuleVersion(Base):
    __tablename__ = "detection_rule_versions"
    __table_args__ = (
        UniqueConstraint("rule_id", "version_number", name="uq_detection_rule_version"),
        Index("ix_detection_versions_tenant_status", "tenant_id", "lifecycle_status"),
        Index("ix_detection_versions_rule_created", "rule_id", "created_at"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(String(36), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False)
    version_number = Column(Integer, nullable=False)
    lifecycle_status = Column(String(30), nullable=False, default="draft")
    rule_language = Column(String(30), nullable=False, default="structured")
    original_content = Column(Text, nullable=True)
    normalized_definition = Column(JSON, nullable=False)
    parser_version = Column(String(30), nullable=False, default="1.0.0")
    schema_version = Column(String(30), nullable=False, default="1.0")
    change_summary = Column(Text, nullable=True)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    reviewer_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approver_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    review_requested_at = Column(DateTime(timezone=True), nullable=True)
    review_completed_at = Column(DateTime(timezone=True), nullable=True)
    approval_expires_at = Column(DateTime(timezone=True), nullable=True)
    approval_comment = Column(Text, nullable=True)
    validation_result = Column(JSON, nullable=False, default=dict)
    test_result = Column(JSON, nullable=False, default=dict)
    content_hash = Column(String(64), nullable=False)
    previous_version_id = Column(String(36), ForeignKey("detection_rule_versions.id", ondelete="SET NULL"), nullable=True)
    source_metadata = Column(JSON, nullable=False, default=dict)
    import_metadata = Column(JSON, nullable=False, default=dict)
    published_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DetectionRuleTestCase(Base):
    __tablename__ = "detection_rule_test_cases"
    __table_args__ = (Index("ix_detection_test_cases_tenant_version", "tenant_id", "version_id"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    version_id = Column(String(36), ForeignKey("detection_rule_versions.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(150), nullable=False)
    input_events = Column(JSON, nullable=False)
    expected = Column(JSON, nullable=False)
    content_hash = Column(String(64), nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DetectionRuleTestResult(Base):
    __tablename__ = "detection_rule_test_results"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    version_id = Column(String(36), ForeignKey("detection_rule_versions.id", ondelete="CASCADE"), nullable=False, index=True)
    test_case_id = Column(String(36), ForeignKey("detection_rule_test_cases.id", ondelete="CASCADE"), nullable=False)
    status = Column(String(20), nullable=False)
    actual = Column(JSON, nullable=False, default=dict)
    safe_message = Column(Text, nullable=True)
    duration_ms = Column(Float, nullable=False, default=0)
    run_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DetectionSimulationJob(Base):
    __tablename__ = "detection_simulation_jobs"
    __table_args__ = (Index("ix_detection_sim_tenant_status_expiry", "tenant_id", "status", "expires_at"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    version_id = Column(String(36), ForeignKey("detection_rule_versions.id", ondelete="CASCADE"), nullable=False)
    requested_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    status = Column(String(20), nullable=False, default="queued")
    time_start = Column(DateTime(timezone=True), nullable=False)
    time_end = Column(DateTime(timezone=True), nullable=False)
    event_limit = Column(Integer, nullable=False)
    events_scanned = Column(Integer, nullable=False, default=0)
    matches = Column(Integer, nullable=False, default=0)
    result = Column(JSON, nullable=False, default=dict)
    error = Column(String(100), nullable=True)
    cancel_requested = Column(Boolean, nullable=False, default=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class DetectionException(Base):
    __tablename__ = "detection_exceptions"
    __table_args__ = (Index("ix_detection_exception_tenant_rule_expiry", "tenant_id", "rule_id", "expires_at"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(String(36), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=True)
    name = Column(String(150), nullable=False)
    reason = Column(Text, nullable=False)
    criteria = Column(JSON, nullable=False)
    status = Column(String(20), nullable=False, default="active")
    starts_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    approved_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DetectionSuppressionPolicy(Base):
    __tablename__ = "detection_suppression_policies"
    __table_args__ = (UniqueConstraint("tenant_id", "rule_id", name="uq_detection_suppression_rule"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(String(36), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False)
    grouping_fields = Column(JSON, nullable=False, default=list)
    window_seconds = Column(Integer, nullable=False, default=300)
    maximum_alerts = Column(Integer, nullable=False, default=1)
    cooldown_seconds = Column(Integer, nullable=False, default=0)
    enabled = Column(Boolean, nullable=False, default=True)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class DetectionMaintenanceWindow(Base):
    __tablename__ = "detection_maintenance_windows"
    __table_args__ = (Index("ix_detection_maintenance_tenant_times", "tenant_id", "starts_at", "ends_at"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(150), nullable=False)
    reason = Column(Text, nullable=False)
    scope = Column(JSON, nullable=False)
    starts_at = Column(DateTime(timezone=True), nullable=False)
    ends_at = Column(DateTime(timezone=True), nullable=False)
    timezone = Column(String(80), nullable=False, default="UTC")
    status = Column(String(20), nullable=False, default="scheduled")
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    approved_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DetectionRuleHealthSnapshot(Base):
    __tablename__ = "detection_rule_health_snapshots"
    __table_args__ = (Index("ix_detection_health_tenant_rule_date", "tenant_id", "rule_id", "snapshot_date"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(String(36), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False)
    snapshot_date = Column(Date, nullable=False)
    metrics = Column(JSON, nullable=False)
    quality_score = Column(Float, nullable=False)
    quality_reasons = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DetectionExecutionState(Base):
    __tablename__ = "detection_execution_state"
    __table_args__ = (
        UniqueConstraint("tenant_id", "version_id", "group_key", name="uq_detection_state_group"),
        Index("ix_detection_state_expiry", "tenant_id", "expires_at"),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    version_id = Column(String(36), ForeignKey("detection_rule_versions.id", ondelete="CASCADE"), nullable=False)
    group_key = Column(String(512), nullable=False)
    state = Column(JSON, nullable=False, default=dict)
    processed_event_ids = Column(JSON, nullable=False, default=list)
    version = Column(Integer, nullable=False, default=1)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class DetectionRecommendation(Base):
    __tablename__ = "detection_recommendations"
    __table_args__ = (Index("ix_detection_recommendation_tenant_status", "tenant_id", "status", "created_at"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(String(36), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False)
    recommendation_type = Column(String(40), nullable=False)
    reason = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=False, default=dict)
    status = Column(String(20), nullable=False, default="open")
    dismissed_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    dismissed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DetectionContentPack(Base):
    __tablename__ = "detection_content_packs"
    __table_args__ = (UniqueConstraint("tenant_id", "identifier", "version", name="uq_detection_content_pack"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    identifier = Column(String(150), nullable=False)
    version = Column(String(50), nullable=False)
    name = Column(String(200), nullable=False)
    publisher = Column(String(200), nullable=False)
    manifest = Column(JSON, nullable=False)
    checksum = Column(String(64), nullable=False)
    installed_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IncidentComment(Base):
    __tablename__ = "incident_comments"
    __table_args__ = (
        Index("ix_incident_comments_tenant_incident_created_at", "tenant_id", "incident_id", "created_at"),
        Index("ix_incident_comments_user_created_at", "user_id", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    incident = relationship("Incident")
    user = relationship("User")


class NotificationType(str, enum.Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    ALERT = "alert"


class Notification(Base):
    __tablename__ = "notifications"
    __table_args__ = (
        Index("ix_notifications_user_read_created_at", "user_id", "is_read", "created_at"),
        Index("ix_notifications_tenant_created_at", "tenant_id", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=True)
    type = Column(Enum(NotificationType), default=NotificationType.INFO)
    is_read = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("Tenant")
    user = relationship("User")


class AssetCriticality(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MitreTactic(str, enum.Enum):
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class ActionType(str, enum.Enum):
    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    CLOSE_INCIDENT = "close_incident"
    ESCALATE_INCIDENT = "escalate_incident"
    CREATE_TASK = "create_task"


class ConnectorType(str, enum.Enum):
    WEBHOOK = "webhook"
    SLACK = "slack"
    TEAMS = "teams"
    SMTP_EMAIL = "smtp_email"
    GENERIC_REST = "generic_rest"


class ConnectorStatus(str, enum.Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    ERROR = "error"


class CredentialStatus(str, enum.Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    ROTATED = "rotated"


class ActionExecutionStatus(str, enum.Enum):
    QUEUED = "queued"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLED_BACK = "rolled_back"


class SOARApprovalStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ActionStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_tenant_timestamp", "tenant_id", "timestamp"),
        Index("ix_security_events_tenant_processed_created_at", "tenant_id", "processed", "created_at"),
        UniqueConstraint("tenant_id", "data_source_id", "source_event_id", name="uq_security_event_source_event"),
        UniqueConstraint("tenant_id", "data_source_id", "idempotency_key", name="uq_security_event_idempotency"),
        UniqueConstraint("tenant_id", "data_source_id", "content_fingerprint", name="uq_security_event_fingerprint"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    collector_id = Column(String(36), ForeignKey("collectors.id", ondelete="SET NULL"), nullable=True)
    data_source_id = Column(String(36), ForeignKey("data_sources.id", ondelete="SET NULL"), nullable=True)
    batch_id = Column(String(36), ForeignKey("ingestion_batches.id", ondelete="SET NULL"), nullable=True)
    source_event_id = Column(String(255), nullable=True)
    idempotency_key = Column(String(255), nullable=True)
    content_fingerprint = Column(String(64), nullable=True)
    source = Column(String(255), nullable=False)
    source_type = Column(String(80), nullable=True)
    vendor = Column(String(100), nullable=True)
    product = Column(String(100), nullable=True)
    parser_name = Column(String(100), nullable=True)
    parser_version = Column(String(30), nullable=True)
    schema_version = Column(String(30), nullable=False, default="1.0")
    event_category = Column(String(100), nullable=True)
    event_class = Column(String(100), nullable=True)
    event_type = Column(Enum(EventType), nullable=False)
    raw_event = Column(JSON, nullable=False)
    normalized_event = Column(JSON, nullable=False)
    severity = Column(Enum(Severity), default=Severity.MEDIUM)
    timestamp = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    original_offset = Column(String(10), nullable=True)
    received_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    processed_at = Column(DateTime(timezone=True), nullable=True)
    processing_status = Column(String(30), nullable=False, default="accepted")
    data_quality_score = Column(Integer, nullable=False, default=100)
    data_quality_reasons = Column(JSON, nullable=False, default=list)
    normalization_warnings = Column(JSON, nullable=False, default=list)
    processed = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("Tenant")
    detection_matches = relationship("DetectionMatch", back_populates="event")

    @property
    def detection_count(self) -> int:
        return len(self.detection_matches or [])

    @property
    def detection_status(self) -> str:
        return "matched" if self.detection_count > 0 else "none"


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        Index("ix_assets_tenant_hostname", "tenant_id", "hostname"),
        Index("ix_assets_tenant_ip_address", "tenant_id", "ip_address"),
        Index("ix_assets_tenant_criticality", "tenant_id", "criticality"),
        Index("ix_assets_tenant_last_seen", "tenant_id", "last_seen"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    hostname = Column(String(255), nullable=False)
    ip_address = Column(String(50), nullable=True)
    operating_system = Column(String(255), nullable=True)
    owner = Column(String(255), nullable=True)
    criticality = Column(Enum(AssetCriticality), default=AssetCriticality.MEDIUM)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    technique_id = Column(String(50), nullable=False, unique=True, index=True)
    name = Column(String(255), nullable=False)
    tactic = Column(Enum(MitreTactic, values_callable=lambda values: [item.value for item in values]), nullable=False)
    description = Column(Text, nullable=True)
    tactic_id = Column(String(64), nullable=True)
    tactic_order = Column(Integer, nullable=True)
    tactics = Column(JSON, nullable=False, default=list)
    parent_technique_id = Column(String(50), nullable=True)
    parent_technique_name = Column(String(255), nullable=True)
    sub_technique_id = Column(String(50), nullable=True)
    sub_technique_name = Column(String(255), nullable=True)
    is_subtechnique = Column(Boolean, nullable=False, default=False)
    is_revoked = Column(Boolean, nullable=False, default=False)
    is_deprecated = Column(Boolean, nullable=False, default=False)
    catalog_version = Column(String(32), nullable=True)
    catalog_source = Column(String(255), nullable=True)
    external_url = Column(String(1024), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ResponseAction(Base):
    __tablename__ = "response_actions"
    __table_args__ = (
        Index("ix_response_actions_tenant_incident_created_at", "tenant_id", "incident_id", "created_at"),
        Index("ix_response_actions_status", "status"),
        Index("ix_response_actions_executed_by", "executed_by"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    action_type = Column(Enum(ActionType), nullable=False)
    status = Column(Enum(ActionStatus), default=ActionStatus.PENDING)
    executed_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("Tenant")
    incident = relationship("Incident")
    executed_by_user = relationship("User", foreign_keys=[executed_by])


class ActionConnector(Base):
    __tablename__ = "action_connectors"
    __table_args__ = (
        Index("ix_action_connectors_tenant_type_status", "tenant_id", "type", "status"),
        Index("ix_action_connectors_tenant_name", "tenant_id", "name"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    name = Column(String(255), nullable=False)
    type = Column(Enum(ConnectorType), nullable=False)
    status = Column(Enum(ConnectorStatus), default=ConnectorStatus.ACTIVE)
    config = Column(JSON, nullable=False, default=dict)
    requires_approval = Column(Boolean, nullable=False, default=False)
    approval_roles = Column(JSON, nullable=True)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    updated_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    created_by_user = relationship("User", foreign_keys=[created_by])
    updated_by_user = relationship("User", foreign_keys=[updated_by])
    credentials = relationship("ConnectorCredential", back_populates="connector", cascade="all, delete-orphan")
    executions = relationship("ConnectorActionExecution", back_populates="connector")


class ConnectorCredential(Base):
    __tablename__ = "connector_credentials"
    __table_args__ = (
        Index("ix_connector_credentials_tenant_connector_status", "tenant_id", "connector_id", "status"),
        Index("ix_connector_credentials_tenant_name", "tenant_id", "name"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    connector_id = Column(String(36), ForeignKey("action_connectors.id"), nullable=False)
    name = Column(String(255), nullable=False)
    status = Column(Enum(CredentialStatus), default=CredentialStatus.ACTIVE)
    encrypted_secret = Column(Text, nullable=False)
    encryption_key_version = Column(Integer, nullable=False, default=1)
    secret_fingerprint = Column(String(64), nullable=False)
    schema_version = Column(Integer, nullable=False, default=1)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    updated_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    rotated_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    connector = relationship("ActionConnector", back_populates="credentials")
    created_by_user = relationship("User", foreign_keys=[created_by])
    updated_by_user = relationship("User", foreign_keys=[updated_by])


class ConnectorActionExecution(Base):
    __tablename__ = "connector_action_executions"
    __table_args__ = (
        Index("ix_connector_action_executions_tenant_status_created", "tenant_id", "status", "created_at"),
        Index("ix_connector_action_executions_connector_created", "connector_id", "created_at"),
        Index("ix_connector_action_executions_playbook_execution", "playbook_execution_id"),
        Index("ix_connector_action_executions_correlation_id", "correlation_id"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    connector_id = Column(String(36), ForeignKey("action_connectors.id"), nullable=False)
    credential_id = Column(String(36), ForeignKey("connector_credentials.id"), nullable=True)
    playbook_execution_id = Column(String(36), ForeignKey("playbook_executions.id"), nullable=True)
    playbook_step_id = Column(String(36), ForeignKey("playbook_execution_steps.id"), nullable=True)
    action_name = Column(String(255), nullable=False)
    status = Column(Enum(ActionExecutionStatus), default=ActionExecutionStatus.QUEUED)
    request = Column(JSON, nullable=True)
    response = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    retry_policy = Column(JSON, nullable=True)
    attempts = Column(Integer, nullable=False, default=0)
    max_attempts = Column(Integer, nullable=False, default=1)
    timeout_seconds = Column(Integer, nullable=True)
    worker_id = Column(String(255), nullable=True)
    correlation_id = Column(String(64), nullable=False)
    request_id = Column(String(64), nullable=True)
    requested_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    approved_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration_ms = Column(Integer, nullable=True)
    rollback_status = Column(String(64), nullable=True)
    rollback_result = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    connector = relationship("ActionConnector", back_populates="executions")
    credential = relationship("ConnectorCredential")
    requested_by_user = relationship("User", foreign_keys=[requested_by])
    approved_by_user = relationship("User", foreign_keys=[approved_by])
    approvals = relationship("SOARActionApproval", back_populates="execution", cascade="all, delete-orphan")
    logs = relationship("ConnectorActionLog", back_populates="execution", cascade="all, delete-orphan")


class SOARActionApproval(Base):
    __tablename__ = "soar_action_approvals"
    __table_args__ = (
        Index("ix_soar_action_approvals_execution_status", "execution_id", "status"),
        Index("ix_soar_action_approvals_tenant_status", "tenant_id", "status"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    execution_id = Column(String(36), ForeignKey("connector_action_executions.id"), nullable=False)
    required_role = Column(Enum(UserRole), nullable=True)
    status = Column(Enum(SOARApprovalStatus), default=SOARApprovalStatus.PENDING)
    requested_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    decided_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    decision_comment = Column(Text, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    decided_at = Column(DateTime(timezone=True), nullable=True)

    tenant = relationship("Tenant")
    execution = relationship("ConnectorActionExecution", back_populates="approvals")
    requested_by_user = relationship("User", foreign_keys=[requested_by])
    decided_by_user = relationship("User", foreign_keys=[decided_by])


class ConnectorActionLog(Base):
    __tablename__ = "connector_action_logs"
    __table_args__ = (
        Index("ix_connector_action_logs_execution_created", "execution_id", "created_at"),
        Index("ix_connector_action_logs_tenant_created", "tenant_id", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    execution_id = Column(String(36), ForeignKey("connector_action_executions.id"), nullable=False)
    level = Column(String(20), nullable=False, default="info")
    message = Column(Text, nullable=False)
    data = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("Tenant")
    execution = relationship("ConnectorActionExecution", back_populates="logs")


class DetectionMatch(Base):
    __tablename__ = "detection_matches"
    __table_args__ = (
        Index("ix_detection_matches_tenant_rule_created_at", "tenant_id", "rule_id", "created_at"),
        Index("ix_detection_matches_tenant_event", "tenant_id", "event_id"),
        UniqueConstraint("tenant_id", "event_id", "rule_id", name="uq_detection_matches_tenant_event_rule"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    event_id = Column(String(36), ForeignKey("security_events.id"), nullable=False)
    rule_id = Column(String(36), ForeignKey("detection_rules.id"), nullable=False)
    rule_version_id = Column(String(36), ForeignKey("detection_rule_versions.id", ondelete="SET NULL"), nullable=True)
    rule_content_hash = Column(String(64), nullable=True)
    alert_id = Column(String(36), ForeignKey("alerts.id"), nullable=True)
    matched = Column(Boolean, nullable=False, default=True)
    severity = Column(Enum(Severity), nullable=False)
    detection_type = Column(String(30), nullable=False, default="event_match")
    triggered_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    window_start = Column(DateTime(timezone=True), nullable=True)
    window_end = Column(DateTime(timezone=True), nullable=True)
    group_key = Column(String(512), nullable=True)
    contributing_event_ids = Column(JSON, nullable=False, default=list)
    matched_conditions = Column(JSON, nullable=False, default=list)
    aggregate_values = Column(JSON, nullable=False, default=dict)
    exceptions_evaluated = Column(JSON, nullable=False, default=list)
    suppression_result = Column(JSON, nullable=False, default=dict)
    confidence = Column(Float, nullable=False, default=0.5)
    risk_contribution = Column(Integer, nullable=False, default=0)
    mitre_mappings = Column(JSON, nullable=False, default=list)
    data_source_provenance = Column(JSON, nullable=False, default=dict)
    processing_version = Column(String(30), nullable=False, default="1.0")
    explanation = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("Tenant")
    event = relationship("SecurityEvent", back_populates="detection_matches")
    rule = relationship("DetectionRule")
    alert = relationship("Alert", back_populates="detection_matches")


class Playbook(Base):
    __tablename__ = "playbooks"
    __table_args__ = (
        Index("ix_playbooks_tenant_status", "tenant_id", "status"),
        Index("ix_playbooks_created_by", "created_by"),
        Index("ix_playbooks_tenant_trigger_status", "tenant_id", "trigger_type", "status"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(Enum(PlaybookStatus), default=PlaybookStatus.DRAFT)
    trigger_type = Column(Enum(PlaybookTriggerType), default=PlaybookTriggerType.MANUAL_RUN)
    trigger_conditions = Column(JSON, nullable=True)
    active_version_id = Column(
        String(36),
        ForeignKey("playbook_versions.id", name="fk_playbooks_active_version_id", use_alter=True),
        nullable=True,
    )
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    created_by_user = relationship("User", foreign_keys=[created_by])
    versions = relationship("PlaybookVersion", back_populates="playbook", foreign_keys="PlaybookVersion.playbook_id")
    active_version = relationship("PlaybookVersion", foreign_keys=[active_version_id], post_update=True)


class PlaybookVersion(Base):
    __tablename__ = "playbook_versions"
    __table_args__ = (
        Index("ix_playbook_versions_playbook_version", "playbook_id", "version_number", unique=True),
        Index("ix_playbook_versions_tenant_status", "tenant_id", "status"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    playbook_id = Column(String(36), ForeignKey("playbooks.id"), nullable=False)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    version_number = Column(Integer, nullable=False)
    status = Column(Enum(PlaybookStatus), default=PlaybookStatus.DRAFT)
    definition = Column(JSON, nullable=False)
    changelog = Column(Text, nullable=True)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    published_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    published_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("Tenant")
    playbook = relationship("Playbook", back_populates="versions", foreign_keys=[playbook_id])
    created_by_user = relationship("User", foreign_keys=[created_by])
    published_by_user = relationship("User", foreign_keys=[published_by])


class PlaybookStep(Base):
    __tablename__ = "playbook_steps"
    __table_args__ = (
        Index("ix_playbook_steps_playbook_order", "playbook_id", "order"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    playbook_id = Column(String(36), ForeignKey("playbooks.id"), nullable=False)
    name = Column(String(255), nullable=False)
    type = Column(Enum(PlaybookStepType), nullable=False)
    order = Column(Integer, nullable=False)
    config = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    playbook = relationship("Playbook")


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"
    __table_args__ = (
        Index("ix_playbook_executions_tenant_status_created_at", "tenant_id", "status", "created_at"),
        Index("ix_playbook_executions_incident_id", "incident_id"),
        Index("ix_playbook_executions_playbook_id", "playbook_id"),
        Index("ix_playbook_executions_version_id", "version_id"),
        Index("ix_playbook_executions_triggered_by", "triggered_by"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=True)
    alert_id = Column(String(36), ForeignKey("alerts.id"), nullable=True)
    playbook_id = Column(String(36), ForeignKey("playbooks.id"), nullable=True)
    version_id = Column(String(36), ForeignKey("playbook_versions.id"), nullable=True)
    trigger_type = Column(Enum(PlaybookTriggerType), default=PlaybookTriggerType.MANUAL_RUN)
    status = Column(Enum(PlaybookExecutionStatus), default=PlaybookExecutionStatus.PENDING)
    triggered_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    current_step_key = Column(String(255), nullable=True)
    context = Column(JSON, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    paused_at = Column(DateTime(timezone=True), nullable=True)
    cancelled_at = Column(DateTime(timezone=True), nullable=True)
    result = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("Tenant")
    incident = relationship("Incident")
    alert = relationship("Alert")
    playbook = relationship("Playbook")
    version = relationship("PlaybookVersion")
    steps = relationship("PlaybookExecutionStep", back_populates="execution", cascade="all, delete-orphan")
    approvals = relationship("PlaybookApproval", back_populates="execution", cascade="all, delete-orphan")
    logs = relationship("PlaybookRunLog", back_populates="execution", cascade="all, delete-orphan")
    triggered_by_user = relationship("User", foreign_keys=[triggered_by])


class PlaybookExecutionStep(Base):
    __tablename__ = "playbook_execution_steps"
    __table_args__ = (
        Index("ix_playbook_execution_steps_execution_order", "execution_id", "order"),
        Index("ix_playbook_execution_steps_status", "status"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    execution_id = Column(String(36), ForeignKey("playbook_executions.id"), nullable=False)
    playbook_id = Column(String(36), ForeignKey("playbooks.id"), nullable=True)
    version_id = Column(String(36), ForeignKey("playbook_versions.id"), nullable=True)
    step_key = Column(String(255), nullable=False)
    name = Column(String(255), nullable=False)
    type = Column(Enum(PlaybookStepType), nullable=False)
    order = Column(Integer, nullable=False, default=0)
    status = Column(Enum(PlaybookStepStatus), default=PlaybookStepStatus.PENDING)
    config = Column(JSON, nullable=True)
    result = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    attempts = Column(Integer, nullable=False, default=0)
    max_attempts = Column(Integer, nullable=False, default=1)
    timeout_seconds = Column(Integer, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    execution_time_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    execution = relationship("PlaybookExecution", back_populates="steps")
    playbook = relationship("Playbook")
    version = relationship("PlaybookVersion")


class PlaybookApproval(Base):
    __tablename__ = "playbook_approvals"
    __table_args__ = (
        Index("ix_playbook_approvals_execution_status", "execution_id", "status"),
        Index("ix_playbook_approvals_tenant_status", "tenant_id", "status"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    execution_id = Column(String(36), ForeignKey("playbook_executions.id"), nullable=False)
    execution_step_id = Column(String(36), ForeignKey("playbook_execution_steps.id"), nullable=True)
    requested_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    approved_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    status = Column(Enum(PlaybookApprovalStatus), default=PlaybookApprovalStatus.PENDING)
    message = Column(Text, nullable=True)
    decision_comment = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    decided_at = Column(DateTime(timezone=True), nullable=True)

    tenant = relationship("Tenant")
    execution = relationship("PlaybookExecution", back_populates="approvals")
    execution_step = relationship("PlaybookExecutionStep")
    requested_by_user = relationship("User", foreign_keys=[requested_by])
    approved_by_user = relationship("User", foreign_keys=[approved_by])


class PlaybookRunLog(Base):
    __tablename__ = "playbook_run_logs"
    __table_args__ = (
        Index("ix_playbook_run_logs_execution_created_at", "execution_id", "created_at"),
        Index("ix_playbook_run_logs_tenant_created_at", "tenant_id", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    execution_id = Column(String(36), ForeignKey("playbook_executions.id"), nullable=False)
    execution_step_id = Column(String(36), ForeignKey("playbook_execution_steps.id"), nullable=True)
    level = Column(String(20), nullable=False, default="info")
    message = Column(Text, nullable=False)
    data = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("Tenant")
    execution = relationship("PlaybookExecution", back_populates="logs")
    execution_step = relationship("PlaybookExecutionStep")


class PlaybookVariable(Base):
    __tablename__ = "playbook_variables"
    __table_args__ = (
        Index("ix_playbook_variables_tenant_scope_key", "tenant_id", "scope", "key"),
        Index("ix_playbook_variables_playbook_key", "playbook_id", "key"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    playbook_id = Column(String(36), ForeignKey("playbooks.id"), nullable=True)
    key = Column(String(255), nullable=False)
    value = Column(JSON, nullable=False)
    scope = Column(String(50), nullable=False, default="tenant")
    is_secret = Column(Boolean, nullable=False, default=False)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    updated_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    playbook = relationship("Playbook")
    created_by_user = relationship("User", foreign_keys=[created_by])
    updated_by_user = relationship("User", foreign_keys=[updated_by])


class MitreTechniqueImpact(Base):
    __tablename__ = "mitre_technique_impacts"
    __table_args__ = (
        Index("ix_mitre_technique_impacts_technique_id", "technique_id"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    technique_id = Column(String(50), ForeignKey("mitre_techniques.technique_id"), nullable=False)
    impact_score = Column(Integer, nullable=False, default=10)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_tenant_action_created_at", "tenant_id", "action", "created_at"),
        Index("ix_audit_logs_tenant_category_result", "tenant_id", "category", "status"),
        Index("ix_audit_logs_tenant_actor_created", "tenant_id", "actor_type", "user_id", "created_at"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
        UniqueConstraint("tenant_id", "sequence_number", name="uq_audit_logs_tenant_sequence"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_audit_logs_tenant_idempotency"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    actor_membership_id = Column(String(36), ForeignKey("organization_memberships.id", ondelete="SET NULL"), nullable=True)
    actor_session_id = Column(String(36), ForeignKey("auth_sessions.id", ondelete="SET NULL"), nullable=True)
    actor_type = Column(String(32), nullable=False, default="user")
    action = Column(String(100), nullable=False, index=True)
    category = Column(String(50), nullable=False, default="system", index=True)
    severity = Column(String(20), nullable=False, default="info")
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(String(36), nullable=True)
    parent_resource_type = Column(String(100), nullable=True)
    parent_resource_id = Column(String(36), nullable=True)
    ip_address = Column(String(64), nullable=True)
    actor_role = Column(String(100), nullable=True)
    status = Column(String(32), nullable=False, default="success")
    user_agent = Column(String(512), nullable=True)
    request_id = Column(String(128), nullable=True)
    correlation_id = Column(String(128), nullable=True)
    approval_request_id = Column(String(36), nullable=True)
    failure_reason = Column(String(255), nullable=True)
    before_values = Column(JSON, nullable=True)
    after_values = Column(JSON, nullable=True)
    details = Column(JSON, nullable=True)
    event_source = Column(String(50), nullable=False, default="application")
    retention_class = Column(String(50), nullable=False, default="administrative", index=True)
    data_classification = Column(String(20), nullable=False, default="confidential")
    sequence_number = Column(BigInteger, nullable=True)
    previous_event_hash = Column(String(64), nullable=True)
    event_hash = Column(String(64), nullable=True)
    hash_algorithm_version = Column(Integer, nullable=False, default=1)
    integrity_key_version = Column(Integer, nullable=False, default=1)
    idempotency_key = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    tenant = relationship("Tenant", back_populates="audit_logs")
    user = relationship("User", back_populates="audit_logs")


class AuditChainState(Base):
    __tablename__ = "audit_chain_states"

    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    last_sequence = Column(BigInteger, nullable=False, default=0)
    last_event_hash = Column(String(64), nullable=True)
    first_retained_sequence = Column(BigInteger, nullable=False, default=1)
    first_retained_previous_hash = Column(String(64), nullable=True)
    key_version = Column(Integer, nullable=False, default=1)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AuditRetentionPolicy(Base):
    __tablename__ = "audit_retention_policies"

    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    default_retention_days = Column(Integer, nullable=False, default=365)
    security_retention_days = Column(Integer, nullable=False, default=730)
    administrative_retention_days = Column(Integer, nullable=False, default=365)
    authentication_retention_days = Column(Integer, nullable=False, default=365)
    export_retention_days = Column(Integer, nullable=False, default=365)
    archive_before_purge = Column(Boolean, nullable=False, default=True)
    archive_retention_days = Column(Integer, nullable=False, default=2555)
    updated_by_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class AuditLegalHold(Base):
    __tablename__ = "audit_legal_holds"
    __table_args__ = (
        Index("ix_audit_legal_holds_tenant_status", "tenant_id", "status"),
        Index("ix_audit_legal_holds_dates", "start_at", "end_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(150), nullable=False)
    reason = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, default="active")
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    released_by_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    start_at = Column(DateTime(timezone=True), nullable=True)
    end_at = Column(DateTime(timezone=True), nullable=True)
    category_filters = Column(JSON, nullable=False, default=list)
    resource_filters = Column(JSON, nullable=False, default=list)
    safe_metadata = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    released_at = Column(DateTime(timezone=True), nullable=True)


class AuditArchiveJob(Base):
    __tablename__ = "audit_archive_jobs"
    __table_args__ = (
        Index("ix_audit_archive_jobs_tenant_status", "tenant_id", "status"),
        Index("ix_audit_archive_jobs_created", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    requested_by_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    status = Column(String(20), nullable=False, default="pending")
    date_from = Column(DateTime(timezone=True), nullable=True)
    date_to = Column(DateTime(timezone=True), nullable=True)
    records_considered = Column(Integer, nullable=False, default=0)
    records_archived = Column(Integer, nullable=False, default=0)
    records_purged = Column(Integer, nullable=False, default=0)
    records_held = Column(Integer, nullable=False, default=0)
    artifact_key = Column(String(255), nullable=True)
    manifest_checksum = Column(String(64), nullable=True)
    error_code = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class AuditExportJob(Base):
    __tablename__ = "audit_export_jobs"
    __table_args__ = (
        Index("ix_audit_export_jobs_tenant_status", "tenant_id", "status"),
        Index("ix_audit_export_jobs_expiration", "expires_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    requested_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    format = Column(String(20), nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    filters = Column(JSON, nullable=False, default=dict)
    record_count = Column(Integer, nullable=False, default=0)
    artifact_key = Column(String(255), nullable=True)
    checksum = Column(String(64), nullable=True)
    download_token_hash = Column(String(64), nullable=True)
    error_code = Column(String(100), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    cancelled_at = Column(DateTime(timezone=True), nullable=True)
