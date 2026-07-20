from sqlalchemy import (
    Column, String, Boolean, DateTime, Text, Float, JSON, Enum, ForeignKey, Integer, BigInteger, Index, UniqueConstraint
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
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


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
    status = Column(Enum(CollectorStatus), default=CollectorStatus.OFFLINE)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    log_source = relationship("LogSource", back_populates="collectors")


class Tenant(Base):
    __tablename__ = "tenants"
    __table_args__ = (
        Index("ix_tenants_status_created_at", "status", "created_at"),
        Index("ix_tenants_subscription_plan", "subscription_plan"),
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
    
    users = relationship("User", back_populates="tenant")
    alert_sources = relationship("AlertSource", back_populates="tenant")
    alerts = relationship("Alert", back_populates="tenant")
    incidents = relationship("Incident", back_populates="tenant")
    audit_logs = relationship("AuditLog", back_populates="tenant")
    memberships = relationship("OrganizationMembership", back_populates="tenant", cascade="all, delete-orphan")
    invitations = relationship("OrganizationInvitation", back_populates="tenant", cascade="all, delete-orphan")
    usage_snapshots = relationship("OrganizationUsage", back_populates="tenant", cascade="all, delete-orphan")


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
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    tenant = relationship("Tenant", back_populates="users")
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
    is_active = Column(Boolean, nullable=False, default=True)
    invited_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant", back_populates="memberships")
    user = relationship("User", back_populates="organization_memberships", foreign_keys=[user_id])
    invited_by_user = relationship("User", foreign_keys=[invited_by])


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
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    user_count = Column(Integer, nullable=False, default=0)
    collector_count = Column(Integer, nullable=False, default=0)
    event_count = Column(Integer, nullable=False, default=0)
    alert_count = Column(Integer, nullable=False, default=0)
    playbook_count = Column(Integer, nullable=False, default=0)
    soar_execution_count = Column(Integer, nullable=False, default=0)
    storage_bytes = Column(BigInteger, nullable=False, default=0)
    api_request_count = Column(BigInteger, nullable=False, default=0)
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

    user = relationship("User", back_populates="refresh_tokens", foreign_keys=[user_id])
    tenant = relationship("Tenant")
    replaced_by_token = relationship("RefreshToken", remote_side=[id])


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
    created_by_user = relationship("User")


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
    indicator_type = Column(Enum(IndicatorType), nullable=False)
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
    type = Column(Enum(IndicatorType), nullable=False)
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
        Index("ix_iocs_tenant_active_created_at", "tenant_id", "is_active", "created_at"),
        Index("ix_iocs_created_by", "created_by"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    type = Column(Enum(IndicatorType), nullable=False)
    value = Column(String(1024), nullable=False, index=True)
    description = Column(Text, nullable=True)
    source = Column(String(255), nullable=True)
    severity = Column(Enum(Severity), default=Severity.MEDIUM)
    confidence_score = Column(Integer, default=0)  # 0-100
    tags = Column(JSON, nullable=True)  # list of strings
    is_active = Column(Boolean, default=True)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    created_by_user = relationship("User")
    enrichments = relationship("IOCEnrichment", back_populates="ioc", cascade="all, delete-orphan")
    incidents = relationship("IncidentIOC", back_populates="ioc", cascade="all, delete-orphan")


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
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    ioc = relationship("IOC", back_populates="enrichments")


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (
        Index("ix_detection_rules_tenant_enabled", "tenant_id", "enabled"),
        Index("ix_detection_rules_tenant_event_type", "tenant_id", "event_type"),
        Index("ix_detection_rules_created_by", "created_by"),
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
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    created_by_user = relationship("User")
    detection_matches = relationship("DetectionMatch", back_populates="rule", cascade="all, delete-orphan")


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
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    source = Column(String(255), nullable=False)
    event_type = Column(Enum(EventType), nullable=False)
    raw_event = Column(JSON, nullable=False)
    normalized_event = Column(JSON, nullable=False)
    severity = Column(Enum(Severity), default=Severity.MEDIUM)
    timestamp = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
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
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    event_id = Column(String(36), ForeignKey("security_events.id"), nullable=False)
    rule_id = Column(String(36), ForeignKey("detection_rules.id"), nullable=False)
    alert_id = Column(String(36), ForeignKey("alerts.id"), nullable=True)
    matched = Column(Boolean, nullable=False, default=True)
    severity = Column(Enum(Severity), nullable=False)
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
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(String(36), nullable=True)
    ip_address = Column(String(64), nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    tenant = relationship("Tenant", back_populates="audit_logs")
    user = relationship("User", back_populates="audit_logs")
