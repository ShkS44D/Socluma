from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_serializer, field_validator
from datetime import date, datetime, timezone
from typing import Optional, List, Dict, Any
from src.models.sqlalchemy import (
    UserRole, 
    Severity, 
    AlertStatus, 
    IncidentStatus, 
    IncidentPriority,
    AlertSourceType, 
    IndicatorType,
    Classification,
    EvidenceType,
    NotificationType,
    EventType,
    AssetCriticality,
    MitreTactic,
    ActionType,
    ActionStatus,
    RuleType,
    LogSourceType,
    LogSourceStatus,
    CollectorStatus,
    PlaybookStatus,
    PlaybookTriggerType,
    PlaybookStepType,
    PlaybookExecutionStatus,
    PlaybookStepStatus,
    PlaybookApprovalStatus,
    ConnectorType,
    ConnectorStatus,
    CredentialStatus,
    ActionExecutionStatus,
    SOARApprovalStatus,
    OrganizationRole,
    OrganizationStatus,
    InvitationStatus,
    AIArtifactType,
)


# Health Check
class HealthComponent(BaseModel):
    status: str
    latency_ms: Optional[float] = None
    detail: Optional[str] = None


class HealthCheck(BaseModel):
    status: str
    database: Optional[str] = None
    redis: Optional[str] = None
    request_id: Optional[str] = None
    service: str = "backend"
    version: str = "1.1.0"
    environment: str
    timestamp: datetime
    checks: Dict[str, HealthComponent]


class HealthStatus(BaseModel):
    status: str
    request_id: Optional[str] = None
    service: str = "backend"
    version: str = "1.1.0"
    timestamp: datetime


class APIErrorResponse(BaseModel):
    timestamp: datetime
    request_id: Optional[str] = None
    status: int
    error_code: str
    message: str
    detail: str
    details: Optional[Any] = None
    documentation_url: str


class AIArtifact(BaseModel):
    id: str
    tenant_id: str
    incident_id: Optional[str] = None
    alert_id: Optional[str] = None
    ioc_id: Optional[str] = None
    artifact_type: AIArtifactType
    model: str
    content: Dict[str, Any]
    confidence_score: Optional[float] = None
    created_by: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class MITRETechniqueSuggestion(BaseModel):
    technique_id: str
    technique_name: str
    tactic: Optional[str] = None
    confidence: float = Field(ge=0, le=1)
    reasoning: str


class AIIncidentSummaryResponse(BaseModel):
    executive_summary: str
    technical_summary: str
    root_cause: str
    impact: str
    recommended_next_steps: List[str]
    suggested_containment: List[str]
    suggested_mitre_attack_techniques: List[MITRETechniqueSuggestion]
    confidence_score: float = Field(ge=0, le=100)
    analysis_mode: str = "provider_assisted"
    correlation_reasons: List[str] = Field(default_factory=list)
    risk_reasoning: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    entities: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_references: List[Dict[str, Any]] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    artifact: AIArtifact


class AIAlertExplanationResponse(BaseModel):
    why_triggered: str
    detection_rule: Optional[Dict[str, Any]] = None
    matched_fields: Dict[str, Any] = Field(default_factory=dict)
    why_suspicious: str
    false_positive_assessment: str
    recommended_actions: List[str]
    confidence_score: float = Field(ge=0, le=100)
    artifact: AIArtifact


class AIIocAnalysisResponse(BaseModel):
    threat_description: str
    malware_families: List[str]
    known_campaigns: List[str]
    confidence: float = Field(ge=0, le=100)
    risk_level: str
    recommended_blocking: List[str]
    mitre_attack_mapping: List[MITRETechniqueSuggestion]
    hunting_recommendations: List[str]
    artifact: AIArtifact


class AITimelineEntry(BaseModel):
    timestamp: datetime
    title: str
    description: Optional[str] = None
    source: str
    resource_id: Optional[str] = None


class AITimelineResponse(BaseModel):
    incident_id: str
    entries: List[AITimelineEntry]
    artifact: AIArtifact


class AIChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    conversation_id: Optional[str] = None


class AIChatMessage(BaseModel):
    id: str
    role: str
    content: str
    message_metadata: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AIChatResponse(BaseModel):
    conversation_id: str
    answer: str
    messages: List[AIChatMessage]
    evidence_references: List["EvidenceReferenceResponse"] = Field(default_factory=list)
    confidence: float = Field(default=0, ge=0, le=100)
    limitations: List[str] = Field(default_factory=list)
    suggested_follow_up_questions: List[str] = Field(default_factory=list)
    model: str
    provider: str
    generated_at: datetime
    request_id: Optional[str] = None
    fallback_used: bool = False
    context_stats: Dict[str, Any] = Field(default_factory=dict)
    token_usage: Optional[Dict[str, Optional[int]]] = None
    configured_model: Optional[str] = None
    provider_latency_ms: Optional[float] = None
    resolved_model: Optional[str] = None
    response_id: Optional[str] = None
    provider_request_id: Optional[str] = None
    completion_status: Optional[str] = None
    error_category: Optional[str] = None


class AIConversationSummaryResponse(BaseModel):
    id: str
    incident_id: str
    user_id: str
    title: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    message_count: int = 0


class AIConversationDetailResponse(AIConversationSummaryResponse):
    messages: List[AIChatMessage] = Field(default_factory=list)


class AIReportResponse(BaseModel):
    incident_id: str
    markdown: str
    sections: Dict[str, Any]
    artifact: AIArtifact


class AIDetectionSuggestion(BaseModel):
    rule_name: str
    logic: Dict[str, Any]
    fields: List[str]
    severity: Severity
    false_positive_considerations: List[str]


class AIDetectionSuggestionsResponse(BaseModel):
    suggestions: List[AIDetectionSuggestion]
    artifact: AIArtifact


class AIPlaybookSuggestion(BaseModel):
    name: str
    trigger: str
    conditions: List[str]
    actions: List[str]
    approvals: List[str]
    soar_steps: List[str]
    expected_outcome: str


class AIPlaybookSuggestionsResponse(BaseModel):
    suggestions: List[AIPlaybookSuggestion]
    artifact: AIArtifact


# Token
class Token(BaseModel):
    access_token: Optional[str] = None
    token_type: str = "bearer"
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    mfa_required: bool = False
    challenge_token: Optional[str] = None


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=512)


class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = None


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=128)


class MessageResponse(BaseModel):
    detail: str


class MFAChallengeRequest(BaseModel):
    challenge_token: str = Field(min_length=20, max_length=2048)
    code: str = Field(min_length=6, max_length=32)
    recovery_code: bool = False


class MFAEnrollmentStartRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)


class MFAEnrollmentConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class MFASensitiveActionRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class RecoveryCodesResponse(BaseModel):
    recovery_codes: List[str]


class EmailTokenRequest(BaseModel):
    token: str = Field(min_length=20, max_length=512)


class EmailAddressRequest(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequest(BaseModel):
    token: str = Field(min_length=20, max_length=512)
    new_password: str = Field(min_length=1, max_length=128)


class SessionResponse(BaseModel):
    id: str
    created_at: datetime
    last_activity_at: Optional[datetime] = None
    expires_at: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_label: Optional[str] = None
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    current: bool = False

    model_config = ConfigDict(from_attributes=True)


class SessionListResponse(BaseModel):
    items: List[SessionResponse]
    total: int
    page: int
    page_size: int


class AuthSecurityEventResponse(BaseModel):
    id: str
    event_type: str
    result: str
    severity: str
    reason_code: Optional[str] = None
    ip_address: Optional[str] = None
    device_label: Optional[str] = None
    request_id: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuthSecurityEventListResponse(BaseModel):
    items: List[AuthSecurityEventResponse]
    total: int
    page: int
    page_size: int


class AccountSecurityStatus(BaseModel):
    mfa_enabled: bool
    recovery_codes_remaining: int
    email_verified: bool
    email_verification_required: bool


class TokenData(BaseModel):
    user_id: Optional[str] = None


# Tenant
class TenantBase(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None
    logo: Optional[str] = None
    industry: Optional[str] = None
    country: Optional[str] = None
    timezone: str = "UTC"
    subscription_plan: str = "starter"
    max_users: int = 25
    max_collectors: int = 25
    max_storage: int = 10737418240


class TenantCreate(TenantBase):
    pass


class Tenant(TenantBase):
    id: str
    status: OrganizationStatus = OrganizationStatus.ACTIVE
    is_active: bool
    created_at: datetime
    updated_at: datetime
    deletion_requested_at: Optional[datetime] = None
    scheduled_purge_at: Optional[datetime] = None
    deleted_at: Optional[datetime] = None
    deletion_requested_by_id: Optional[str] = None
    sensitive_action_approval_mode: str = "none"
    permission_revision: int = 1

    model_config = ConfigDict(from_attributes=True)

    @field_serializer(
        "created_at",
        "updated_at",
        "deletion_requested_at",
        "scheduled_purge_at",
        "deleted_at",
    )
    def serialize_tenant_datetime(self, value: Optional[datetime]) -> Optional[str]:
        if value is None:
            return None
        aware = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        return aware.isoformat().replace("+00:00", "Z")


class OrganizationCreate(BaseModel):
    name: str
    slug: str
    deletion_pin: str = Field(pattern=r"^\d{4}$")
    description: Optional[str] = None
    logo: Optional[str] = None
    industry: Optional[str] = None
    country: Optional[str] = None
    timezone: str = "UTC"
    subscription_plan: str = "starter"
    max_users: int = Field(default=25, ge=1)
    max_collectors: int = Field(default=25, ge=0)
    max_storage: int = Field(default=10737418240, ge=0)


class OrganizationUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    logo: Optional[str] = None
    industry: Optional[str] = None
    country: Optional[str] = None
    timezone: Optional[str] = None
    subscription_plan: Optional[str] = None
    max_users: Optional[int] = Field(default=None, ge=1)
    max_collectors: Optional[int] = Field(default=None, ge=0)
    max_storage: Optional[int] = Field(default=None, ge=0)
    status: Optional[OrganizationStatus] = None
    sensitive_action_approval_mode: Optional[str] = Field(
        default=None, pattern=r"^(none|one_person|two_person)$"
    )


class Organization(Tenant):
    pass


class OrganizationMembership(BaseModel):
    id: str
    tenant_id: str
    user_id: str
    role: OrganizationRole
    is_active: bool
    invited_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    user: Optional["User"] = None

    model_config = ConfigDict(from_attributes=True)


class OrganizationMemberUpdate(BaseModel):
    role: Optional[OrganizationRole] = None
    custom_role_id: Optional[str] = None
    is_active: Optional[bool] = None


class DeletionPinRequest(BaseModel):
    pin: str = Field(pattern=r"^\d{4}$")
    current_password: str = Field(min_length=1)


class OrganizationDeleteRequest(BaseModel):
    pin: str = Field(
        pattern=r"^\d{4}$",
        description="Four-digit owner deletion PIN used to schedule deletion.",
        examples=["1234"],
    )
    approval_id: Optional[str] = Field(default=None, max_length=36)


class PermissionDescriptor(BaseModel):
    identifier: str
    category: str
    description: str
    owner_only: bool = False


class PermissionCatalog(BaseModel):
    permissions: list[PermissionDescriptor]


class EffectivePermissions(BaseModel):
    organization_id: str
    membership_id: str
    role: OrganizationRole
    custom_role_id: Optional[str] = None
    permissions: list[str]
    permission_revision: int


class CustomRoleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)
    permissions: list[str] = Field(default_factory=list)


class CustomRoleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)
    permissions: Optional[list[str]] = None


class CustomRole(BaseModel):
    id: str
    tenant_id: str
    name: str
    description: Optional[str] = None
    permissions: list[str]
    is_system: bool
    is_protected: bool = False
    permission_revision: int = 1
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class APIKeyCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    scopes: list[str] = Field(min_length=1, max_length=30)
    expires_in_days: int = Field(default=90, ge=1, le=365)


class APIKeyResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    key_prefix: str
    scopes: list[str]
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    created_at: datetime
    api_key: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)


class ApprovalRequestCreate(BaseModel):
    action_type: str = Field(min_length=3, max_length=100, pattern=r"^[a-z][a-z0-9_.-]+$")
    target_resource_type: str = Field(min_length=2, max_length=100)
    target_resource_id: str = Field(min_length=1, max_length=100)
    safe_metadata: Dict[str, Any] = Field(default_factory=dict)
    expires_in_minutes: int = Field(default=30, ge=5, le=1440)


class ApprovalDecisionRequest(BaseModel):
    decision: str = Field(pattern=r"^(approve|reject)$")


class ApprovalResponse(BaseModel):
    id: str
    tenant_id: str
    requester_id: str
    action_type: str
    target_resource_type: str
    target_resource_id: str
    required_approvals: int
    status: str
    safe_metadata: Dict[str, Any]
    expires_at: datetime
    approved_at: Optional[datetime] = None
    rejected_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class OrganizationInvitationCreate(BaseModel):
    email: EmailStr
    role: OrganizationRole = OrganizationRole.ANALYST
    expires_in_days: int = Field(default=7, ge=1, le=90)


class OrganizationInvitation(BaseModel):
    id: str
    tenant_id: str
    email: EmailStr
    role: OrganizationRole
    status: InvitationStatus
    invited_by: Optional[str] = None
    invited_user_id: Optional[str] = None
    expires_at: datetime
    accepted_at: Optional[datetime] = None
    rejected_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrganizationInvitationResponse(OrganizationInvitation):
    token: Optional[str] = None


class InvitationDecision(BaseModel):
    token: str


class TenantSwitchRequest(BaseModel):
    organization_id: str


class OrganizationUsage(BaseModel):
    organization_id: str
    user_count: int
    collector_count: int
    event_count: int
    alert_count: int
    incident_count: int
    playbook_count: int
    playbook_execution_count: int
    soar_execution_count: int
    triage_ai_request_count: int
    storage_bytes: int
    api_request_count: int
    period_start: datetime
    period_end: datetime
    storage_measurement: str
    limits: Dict[str, int]


class OrganizationUsageHistoryItem(BaseModel):
    snapshot_date: date
    user_count: int
    collector_count: int
    event_count: int
    alert_count: int
    incident_count: int
    playbook_count: int
    playbook_execution_count: int
    soar_execution_count: int
    triage_ai_request_count: int
    storage_bytes: int
    api_request_count: int
    calculated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SubscriptionInfo(BaseModel):
    plan: str
    limits: Dict[str, int]
    usage: OrganizationUsage


# User
class UserBase(BaseModel):
    email: str
    full_name: Optional[str] = None


class UserCreate(UserBase):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    tenant_name: str
    tenant_slug: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class User(UserBase):
    id: str
    tenant_id: str
    role: UserRole
    is_active: bool
    created_at: datetime
    updated_at: datetime
    mfa_enabled: bool = False
    email_verified: bool = False
    
    model_config = ConfigDict(from_attributes=True)
        
    @field_serializer('created_at', 'updated_at')
    def serialize_datetime(self, dt: datetime, _info) -> str:
        return dt.isoformat() + 'Z' if dt.tzinfo else dt.isoformat()

    @classmethod
    def model_validate(cls, obj, *args, **kwargs):
        model = super().model_validate(obj, *args, **kwargs)
        model.mfa_enabled = bool(getattr(obj, "mfa_enabled_at", None))
        model.email_verified = bool(
            getattr(obj, "email_verified_at", None)
            or getattr(obj, "email_verification_exempt", False)
        )
        return model


class AuditLog(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    actor_membership_id: Optional[str] = None
    actor_session_id: Optional[str] = None
    actor_type: str = "user"
    action: str
    category: str = "system"
    severity: str = "info"
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    parent_resource_type: Optional[str] = None
    parent_resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    actor_role: Optional[str] = None
    status: str = "success"
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
    approval_request_id: Optional[str] = None
    failure_reason: Optional[str] = None
    before_values: Optional[Dict[str, Any]] = None
    after_values: Optional[Dict[str, Any]] = None
    details: Optional[Dict[str, Any]] = None
    event_source: str = "application"
    retention_class: str = "administrative"
    data_classification: str = "confidential"
    sequence_number: Optional[int] = None
    previous_event_hash: Optional[str] = None
    event_hash: Optional[str] = None
    hash_algorithm_version: int = 1
    integrity_key_version: int = 1
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Alert Source
class AlertSourceBase(BaseModel):
    name: str
    type: AlertSourceType = AlertSourceType.API
    config: Optional[Dict[str, Any]] = None
    enabled: bool = True


class AlertSourceCreate(AlertSourceBase):
    api_key: Optional[str] = Field(default=None, min_length=16, max_length=256)


class AlertSourceUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[AlertSourceType] = None
    config: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None
    api_key: Optional[str] = Field(default=None, min_length=16, max_length=256)


class AlertSource(AlertSourceBase):
    id: str
    tenant_id: str
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class AlertSourceCreateResponse(AlertSource):
    generated_api_key: Optional[str] = None


# Alert
class AlertBase(BaseModel):
    severity: Severity = Severity.MEDIUM
    status: AlertStatus = AlertStatus.OPEN


class AlertCreate(BaseModel):
    source: str = "api"
    raw_data: Dict[str, Any]


class Alert(AlertBase):
    id: str
    tenant_id: str
    source_id: str
    detection_rule_id: Optional[str] = None
    incident_id: Optional[str] = None
    event_id: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    ocsf_data: Dict[str, Any]
    risk_score: Optional[float] = None
    matched_condition: Optional[str] = None
    why_matched: Optional[str] = None
    created_at: datetime
    processed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
        
    @field_serializer('created_at', 'processed_at')
    def serialize_datetime(self, dt: Optional[datetime], _info) -> Optional[str]:
        if dt is None:
            return None
        # Ensure the datetime is UTC and timezone-aware
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat().replace('+00:00', 'Z')


class AlertWithRule(Alert):
    detection_rule: Optional["DetectionRule"] = None
    
    model_config = ConfigDict(from_attributes=True)


# Pagination
class AlertListResponse(BaseModel):
    items: List[Alert]
    total: int
    page: int
    page_size: int


# Incident
class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: Severity = Severity.MEDIUM
    risk_score: float = Field(default=0, ge=0, le=100)
    status: IncidentStatus = IncidentStatus.OPEN
    priority: IncidentPriority = IncidentPriority.P3
    due_date: Optional[datetime] = None
    escalation_level: int = Field(default=0, ge=0)
    ai_summary: Optional[str] = None
    why_suspicious: Optional[str] = None
    ai_analyzed_at: Optional[datetime] = None
    attack_technique: Optional[Dict[str, Any]] = None
    recommended_actions: Optional[List[str]] = None
    threat_intel_results: Optional[List[Dict[str, Any]]] = None
    classification: Optional[Classification] = None
    creation_source: str = "manual"
    provenance_status: str = "manual"
    creation_reason: Optional[str] = None
    primary_alert_id: Optional[str] = None
    correlation_rule_id: Optional[str] = None
    correlation_rule_name: Optional[str] = None
    correlation_key: Optional[str] = None
    correlation_score: Optional[float] = None
    correlation_window_start: Optional[datetime] = None
    correlation_window_end: Optional[datetime] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    risk_score_breakdown: Dict[str, Any] = Field(default_factory=dict)
    severity_reason: Optional[str] = None
    attack_summary: Optional[str] = None
    status_reason: Optional[str] = None


class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus


class IncidentPriorityUpdate(BaseModel):
    priority: IncidentPriority
    due_date: Optional[datetime] = None
    escalation_level: int = Field(default=0, ge=0)


class IncidentAlertLink(BaseModel):
    id: str
    alert_id: str
    correlation_score: float
    correlation_reason: Optional[str] = None
    is_primary: bool = False
    attachment_reason: Optional[str] = None
    sequence_order: int = 0
    risk_contribution: Optional[float] = None
    matching_entities: List[Dict[str, Any]] = Field(default_factory=list)
    matching_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    time_delta_seconds: Optional[float] = None
    created_at: datetime
    alert: Alert

    model_config = ConfigDict(from_attributes=True)

    @field_validator("matching_entities", "matching_indicators", mode="before")
    @classmethod
    def normalize_legacy_null_lists(cls, value: Any) -> List[Dict[str, Any]]:
        return value or []


class IncidentMitreMappingResponse(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str
    parent_technique_id: str
    parent_technique_name: str
    sub_technique_id: Optional[str] = None
    sub_technique_name: Optional[str] = None
    mapping_source: str
    confidence: float
    confidence_reasons: List[str] = Field(default_factory=list)
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    source_alert_ids: List[str] = Field(default_factory=list)
    stage_order: int
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class MitreMatrixIncidentResponse(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    confidence: float
    supporting_alert_count: int
    mapping_source: str
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None


class MitreMatrixTechniqueResponse(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str
    parent_technique_id: str
    parent_technique_name: str
    sub_technique_id: Optional[str] = None
    sub_technique_name: Optional[str] = None
    mapping_source: str
    attack_stage_order: int
    incident_count: int
    supporting_alert_count: int
    incidents: List[MitreMatrixIncidentResponse]


class MitreMatrixResponse(BaseModel):
    techniques: List[MitreMatrixTechniqueResponse]
    incident_count: int


class Incident(IncidentBase):
    id: str
    tenant_id: str
    assigned_to: Optional[str] = None
    assigned_at: Optional[datetime] = None
    assigned_analyst: Optional[User] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    alert_count: int = 0

    model_config = ConfigDict(from_attributes=True)
        
    @field_serializer('created_at', 'updated_at', 'resolved_at', 'assigned_at')
    def serialize_datetime(self, dt: Optional[datetime], _info) -> Optional[str]:
        if dt is None:
            return None
        # Ensure the datetime is UTC and timezone-aware
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat().replace('+00:00', 'Z')


class IncidentDetail(IncidentBase):
    id: str
    tenant_id: str
    assigned_to: Optional[str] = None
    assigned_at: Optional[datetime] = None
    assigned_analyst: Optional[User] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    related_alerts: List[IncidentAlertLink]
    correlation_reasons: List[str]
    mitre_mappings: List[IncidentMitreMappingResponse] = Field(default_factory=list)
    related_alert_total: int = 0
    related_alert_page: int = 1
    related_alert_page_size: int = 20
    related_alert_has_more: bool = False

    model_config = ConfigDict(from_attributes=True)


class IncidentListResponse(BaseModel):
    items: List[Incident]
    total: int
    page: int
    page_size: int


class IncidentAssignmentRequest(BaseModel):
    user_id: str


class InvestigationNoteCreate(BaseModel):
    content: str = Field(min_length=1, max_length=5000)


class InvestigationNoteResponse(BaseModel):
    id: str
    incident_id: str
    user_id: str
    content: str
    created_at: datetime
    updated_at: datetime
    user: Optional[User] = None

    model_config = ConfigDict(from_attributes=True)


class AnalystActivity(BaseModel):
    user_id: str
    analyst_name: str
    assigned_count: int
    active_investigations: int
    note_count: int
    feedback_count: int
    resolved_count: int


class TimelineActor(BaseModel):
    user_id: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = None


class TimelineItem(BaseModel):
    id: str
    event_type: str
    title: str
    description: Optional[str] = None
    created_at: datetime
    actor: Optional[TimelineActor] = None
    metadata: Dict[str, Any] = {}


class IncidentStats(BaseModel):
    total_incidents: int
    critical_incidents: int
    average_risk_score: float
    active_investigations: int
    average_resolution_time_hours: float
    mean_time_to_detect_hours: float
    mean_time_to_respond_hours: float
    open_incidents_by_severity: Dict[str, int] = {}
    top_alert_sources: List[Dict[str, Any]] = []
    analyst_activity: List[AnalystActivity] = []


class IncidentEvidenceCreate(BaseModel):
    type: EvidenceType
    value: str = Field(min_length=1, max_length=1024)
    description: Optional[str] = Field(default=None, max_length=2000)


class IncidentEvidenceResponse(BaseModel):
    id: str
    incident_id: str
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    source_event_id: Optional[str] = None
    source_alert_id: Optional[str] = None
    source_entity_id: Optional[str] = None
    type: EvidenceType
    value: str
    description: Optional[str] = None
    confidence: Optional[float] = None
    risk_contribution: Optional[float] = None
    evidence_metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    user: Optional[User] = None

    model_config = ConfigDict(from_attributes=True)


class IncidentOriginResponse(BaseModel):
    creation_source: str
    provenance_status: str
    derived_fields: List[str] = Field(default_factory=list)
    creation_reason: str
    created_at: datetime
    first_seen_at: datetime
    last_seen_at: datetime
    status_reason: Optional[str] = None


class IncidentAlertContributionResponse(BaseModel):
    id: str
    event_id: Optional[str] = None
    detection_rule_id: Optional[str] = None
    detection_rule_name: Optional[str] = None
    severity: str
    status: str
    created_at: datetime
    why_matched: Optional[str] = None
    matched_condition: Optional[str] = None
    is_primary: bool
    attachment_reason: Optional[str] = None
    correlation_reason: Optional[str] = None
    correlation_score: float
    sequence_order: int
    risk_contribution: float
    matching_entities: List[Dict[str, Any]] = Field(default_factory=list)
    matching_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    time_delta_seconds: float


class IncidentSourceEventResponse(BaseModel):
    id: str
    source: str
    event_type: str
    severity: str
    timestamp: datetime
    created_at: datetime
    processed: bool


class IncidentDetectionMatchResponse(BaseModel):
    alert_id: str
    event_id: Optional[str] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    sigma_rule_id: Optional[str] = None
    matched_condition: Optional[str] = None
    why_matched: Optional[str] = None
    severity: str


class IncidentCorrelationResponse(BaseModel):
    rule_id: Optional[str] = None
    rule_name: str
    key: Optional[str] = None
    score: float
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    reasons: List[str] = Field(default_factory=list)


class IncidentTimelineSummaryItem(BaseModel):
    timestamp: datetime
    type: str
    title: str
    resource_id: str


class IncidentEntityResponse(BaseModel):
    id: str
    type: str
    value: str
    normalized_value: str
    role: Optional[str] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    source_event_id: Optional[str] = None
    source_alert_id: Optional[str] = None
    confidence: Optional[float] = None
    risk_contribution: Optional[float] = None


class IncidentIOCReferenceResponse(BaseModel):
    id: str
    type: str
    value: str
    severity: str
    confidence: int
    enrichment_count: int
    malicious_reports: int


class EvidenceReferenceResponse(BaseModel):
    type: str
    id: str
    label: str
    timestamp: Optional[str] = None
    navigation_path: Optional[str] = None
    available: bool = True
    unavailable_reason: Optional[str] = None


class IncidentEvidenceSummaryResponse(BaseModel):
    source_alert_count: int
    source_event_count: int
    affected_entity_count: int
    manual_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    references: List[EvidenceReferenceResponse] = Field(default_factory=list)


class CollectionPageMetadata(BaseModel):
    total: int
    included: int
    page: int = 1
    page_size: int
    has_more: bool


class IncidentExplanationResponse(BaseModel):
    incident_id: str
    origin: IncidentOriginResponse
    primary_alert: Optional[IncidentAlertContributionResponse] = None
    correlated_alerts: List[IncidentAlertContributionResponse] = Field(default_factory=list)
    source_events: List[IncidentSourceEventResponse] = Field(default_factory=list)
    detection_matches: List[IncidentDetectionMatchResponse] = Field(default_factory=list)
    correlation: IncidentCorrelationResponse
    timeline_summary: List[IncidentTimelineSummaryItem] = Field(default_factory=list)
    affected_entities: List[IncidentEntityResponse] = Field(default_factory=list)
    ioc_summary: List[IncidentIOCReferenceResponse] = Field(default_factory=list)
    mitre_attack_mapping: List[Dict[str, Any]] = Field(default_factory=list)
    risk_score_breakdown: Dict[str, Any] = Field(default_factory=dict)
    severity_reason: Optional[str] = None
    attack_summary: Optional[str] = None
    evidence_summary: IncidentEvidenceSummaryResponse
    recommended_investigation_questions: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    collection_metadata: Dict[str, CollectionPageMetadata] = Field(default_factory=dict)


class ThreatIntelResult(BaseModel):
    id: Optional[str] = None
    indicator: str
    type: IndicatorType
    source: str
    result: Dict[str, Any]
    risk_impact: int = 0
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class FeedbackCreate(BaseModel):
    classification: Classification
    comment: Optional[str] = None


class FeedbackResponse(BaseModel):
    id: str
    tenant_id: str
    incident_id: str
    user_id: str
    classification: Classification
    comment: Optional[str]
    created_at: datetime
    user: Optional[User] = None

    model_config = ConfigDict(from_attributes=True)


class FeedbackStats(BaseModel):
    total_reviewed: int
    true_positives: int
    false_positives: int
    benign: int
    accuracy_percentage: float


class AIAnalysisResponse(BaseModel):
    summary: str
    why_suspicious: str
    attack_technique: Dict[str, Any]
    recommended_actions: List[str]
    threat_intel_results: List[ThreatIntelResult] = []


# IOC Schemas
class IOCBase(BaseModel):
    type: IndicatorType
    value: str
    description: Optional[str] = None
    source: Optional[str] = None
    severity: Severity = Severity.MEDIUM
    confidence_score: int = 0
    source_reliability: int = Field(default=50, ge=0, le=100)
    lifecycle_status: str = "new"
    tlp: str = "TLP:AMBER"
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    source_references: List[str] = Field(default_factory=list)
    external_source_ids: Dict[str, str] = Field(default_factory=dict)
    stix_id: Optional[str] = None
    classification: Optional[str] = None
    tags: Optional[List[str]] = None
    is_active: bool = False


class IOCCreate(IOCBase):
    pass


class IOCUpdate(BaseModel):
    description: Optional[str] = None
    source: Optional[str] = None
    severity: Optional[Severity] = None
    confidence_score: Optional[int] = None
    source_reliability: Optional[int] = Field(default=None, ge=0, le=100)
    lifecycle_status: Optional[str] = None
    lifecycle_reason: Optional[str] = None
    tlp: Optional[str] = None
    valid_until: Optional[datetime] = None
    classification: Optional[str] = None
    tags: Optional[List[str]] = None
    is_active: Optional[bool] = None


class IOCEnrichment(BaseModel):
    id: str
    ioc_id: str
    provider: str
    reputation: Optional[str] = None
    malicious_count: int = 0
    total_reports: int = 0
    provider_verdict: Optional[str] = None
    confidence: Optional[int] = None
    categories: List[str] = Field(default_factory=list)
    detection_counts: Dict[str, int] = Field(default_factory=dict)
    provider_references: List[str] = Field(default_factory=list)
    safe_result: Dict[str, Any] = Field(default_factory=dict)
    failure_code: Optional[str] = None
    retryable: bool = False
    expires_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IOC(IOCBase):
    id: str
    tenant_id: str
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    original_value: Optional[str] = None
    normalized_value: Optional[str] = None
    display_value: Optional[str] = None
    risk_score: int = 0
    risk_reasons: List[Dict[str, Any]] = Field(default_factory=list)
    risk_score_version: str = "1.0"
    review_status: str = "pending"
    reviewed_by: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    expired_at: Optional[datetime] = None
    internal_sighting_count: int = 0
    first_internal_sighting: Optional[datetime] = None
    last_internal_sighting: Optional[datetime] = None
    enrichment_status: str = "pending"
    last_enriched_at: Optional[datetime] = None
    next_enrichment_at: Optional[datetime] = None
    false_positive: bool = False
    allowlisted: bool = False
    content_hash: Optional[str] = None
    enrichments: List[IOCEnrichment] = []

    model_config = ConfigDict(from_attributes=True)


class IOCListResponse(BaseModel):
    items: List[IOC]
    total: int
    page: int
    page_size: int


# Detection Rule Schemas
class DetectionRuleBase(BaseModel):
    name: str
    description: Optional[str] = None
    # Backward compatibility fields
    type: RuleType = RuleType.CUSTOM
    query: Optional[str] = None
    sigma_rule: Optional[str] = None
    # Detection rule metadata
    rule_type: RuleType = RuleType.CUSTOM
    rule_content: Optional[Dict[str, Any]] = None
    event_type: Optional[EventType] = None
    severity: Severity = Severity.MEDIUM
    enabled: bool = True
    condition: Optional[Dict[str, Any]] = None
    mitre_technique_id: Optional[str] = None


class DetectionRuleCreate(DetectionRuleBase):
    pass


class DetectionRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    # Backward compatibility fields
    type: Optional[RuleType] = None
    query: Optional[str] = None
    sigma_rule: Optional[str] = None
    # Detection rule metadata
    rule_type: Optional[RuleType] = None
    rule_content: Optional[Dict[str, Any]] = None
    event_type: Optional[EventType] = None
    severity: Optional[Severity] = None
    enabled: Optional[bool] = None
    condition: Optional[Dict[str, Any]] = None
    mitre_technique_id: Optional[str] = None


class DetectionRule(DetectionRuleBase):
    id: str
    tenant_id: str
    created_by: Optional[str] = None
    lifecycle_status: str = "draft"
    detection_kind: str = "event_match"
    current_version_id: Optional[str] = None
    production_version_id: Optional[str] = None
    owner_id: Optional[str] = None
    team: Optional[str] = None
    confidence: float = 0.5
    risk_contribution: int = 0
    tags: List[str] = Field(default_factory=list)
    mitre_mappings: List[str] = Field(default_factory=list)
    data_source_requirements: List[str] = Field(default_factory=list)
    last_triggered_at: Optional[datetime] = None
    last_tested_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DetectionRuleListResponse(BaseModel):
    items: List[DetectionRule]
    total: int
    page: int
    page_size: int


class DetectionRuleSigmaImport(BaseModel):
    content: str
    enabled: bool = True


class DetectionRuleTestRequest(BaseModel):
    event: Dict[str, Any]


class DetectionRuleTestResponse(BaseModel):
    matched: bool
    details: str
    explanation: Dict[str, Any]


# Security Event Schemas
class SecurityEventBase(BaseModel):
    source: str
    event_type: EventType
    raw_event: Dict[str, Any]
    normalized_event: Optional[Dict[str, Any]] = None
    severity: Severity = Severity.MEDIUM
    timestamp: Optional[datetime] = None
    data_source_id: Optional[str] = None
    source_event_id: Optional[str] = Field(default=None, max_length=255)
    idempotency_key: Optional[str] = Field(default=None, max_length=255)
    format: str = Field(default="json", pattern="^(json|syslog|cef|leef|windows|linux)$")
    raw_message: Optional[str] = Field(default=None, max_length=262144)


class SecurityEventCreate(SecurityEventBase):
    pass


class SecurityEvent(SecurityEventBase):
    id: str
    tenant_id: str
    processed: bool = False
    detection_count: int = 0
    detection_status: str = "none"
    created_at: datetime
    collector_id: Optional[str] = None
    batch_id: Optional[str] = None
    content_fingerprint: Optional[str] = None
    parser_name: Optional[str] = None
    parser_version: Optional[str] = None
    schema_version: str = "1.0"
    event_category: Optional[str] = None
    event_class: Optional[str] = None
    processing_status: str = "accepted"
    data_quality_score: int = 100
    data_quality_reasons: List[str] = Field(default_factory=list)
    normalization_warnings: List[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)
        
    @field_serializer('created_at', 'timestamp')
    def serialize_datetime(self, dt: datetime, _info) -> str:
        # Ensure the datetime is UTC and timezone-aware
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat().replace('+00:00', 'Z')


# Detection Responses
class EventAnalysisResponse(BaseModel):
    event_id: str
    processed: bool
    matched_rules: list[dict]
    incident_created: bool
    incident_id: Optional[str] = None


class IngestionResponse(SecurityEvent):
    processed: bool
    detections: list[dict]
    incident_created: Optional[bool] = None
    incident_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class EventsTodayStats(BaseModel):
    count: int


class IngestionBatchRequest(BaseModel):
    batch_id: str = Field(min_length=1, max_length=100)
    events: List[SecurityEventCreate] = Field(min_length=1)
    strict: bool = False


class IngestionItemReceipt(BaseModel):
    index: int
    status: str
    event_id: Optional[str] = None
    duplicate_of: Optional[str] = None
    error_code: Optional[str] = None
    message: Optional[str] = None


class IngestionBatchReceipt(BaseModel):
    receipt_id: str
    batch_id: str
    replayed: bool = False
    submitted: int
    accepted: int
    duplicates: int
    rejected: int
    items: List[IngestionItemReceipt]
    received_at: datetime


# Incident Comment Schemas
class IncidentCommentBase(BaseModel):
    content: str


class IncidentCommentCreate(IncidentCommentBase):
    pass


class IncidentComment(IncidentCommentBase):
    id: str
    tenant_id: str
    incident_id: str
    user_id: str
    created_at: datetime
    updated_at: datetime
    user: Optional[User] = None

    model_config = ConfigDict(from_attributes=True)


# Notification Schemas
class Notification(BaseModel):
    id: str
    tenant_id: str
    user_id: str
    title: str
    message: Optional[str] = None
    type: NotificationType
    is_read: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NotificationUpdateRead(BaseModel):
    is_read: bool = True


# Asset Schemas
class AssetBase(BaseModel):
    hostname: str
    ip_address: Optional[str] = None
    operating_system: Optional[str] = None
    owner: Optional[str] = None
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    last_seen: Optional[datetime] = None


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    operating_system: Optional[str] = None
    owner: Optional[str] = None
    criticality: Optional[AssetCriticality] = None
    last_seen: Optional[datetime] = None


class Asset(AssetBase):
    id: str
    tenant_id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# MITRE Technique Schemas
class MitreTechniqueBase(BaseModel):
    technique_id: str
    name: str
    tactic: MitreTactic
    description: Optional[str] = None
    tactic_id: Optional[str] = None
    tactic_order: Optional[int] = None
    tactics: List[Dict[str, Any]] = Field(default_factory=list)
    parent_technique_id: Optional[str] = None
    parent_technique_name: Optional[str] = None
    sub_technique_id: Optional[str] = None
    sub_technique_name: Optional[str] = None
    is_subtechnique: bool = False
    is_revoked: bool = False
    is_deprecated: bool = False
    catalog_version: Optional[str] = None
    catalog_source: Optional[str] = None
    external_url: Optional[str] = None


class MitreTechniqueCreate(MitreTechniqueBase):
    pass


class MitreTechnique(MitreTechniqueBase):
    id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Response Action Schemas
class ResponseActionBase(BaseModel):
    action_type: ActionType
    details: Optional[Dict[str, Any]] = None


class ResponseActionCreate(ResponseActionBase):
    pass


class ResponseAction(ResponseActionBase):
    id: str
    tenant_id: str
    incident_id: str
    status: ActionStatus = ActionStatus.PENDING
    executed_by: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# SOAR Connector Schemas
class ActionConnectorCreate(BaseModel):
    name: str
    type: ConnectorType
    config: Dict[str, Any] = Field(default_factory=dict)
    requires_approval: bool = False
    approval_roles: Optional[List[UserRole]] = None


class ActionConnectorUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[ConnectorStatus] = None
    config: Optional[Dict[str, Any]] = None
    requires_approval: Optional[bool] = None
    approval_roles: Optional[List[UserRole]] = None


class ActionConnector(BaseModel):
    id: str
    tenant_id: str
    name: str
    type: ConnectorType
    status: ConnectorStatus
    config: Dict[str, Any]
    requires_approval: bool
    approval_roles: Optional[List[UserRole]] = None
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ConnectorCredentialCreate(BaseModel):
    connector_id: str
    name: str
    secret: Dict[str, Any]


class ConnectorCredentialUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[CredentialStatus] = None
    secret: Optional[Dict[str, Any]] = None


class ConnectorCredential(BaseModel):
    id: str
    tenant_id: str
    connector_id: str
    name: str
    status: CredentialStatus
    secret_fingerprint: str
    schema_version: int
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    rotated_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ConnectorExecutionCreate(BaseModel):
    connector_id: str
    credential_id: Optional[str] = None
    action_name: str
    request: Dict[str, Any] = Field(default_factory=dict)
    retry_policy: Dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: Optional[int] = Field(default=30, ge=1, le=3600)
    requires_approval: Optional[bool] = None
    approval_roles: Optional[List[UserRole]] = None


class ConnectorActionExecution(BaseModel):
    id: str
    tenant_id: str
    connector_id: str
    credential_id: Optional[str] = None
    playbook_execution_id: Optional[str] = None
    playbook_step_id: Optional[str] = None
    action_name: str
    status: ActionExecutionStatus
    request: Optional[Dict[str, Any]] = None
    response: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    retry_policy: Optional[Dict[str, Any]] = None
    attempts: int
    max_attempts: int
    timeout_seconds: Optional[int] = None
    worker_id: Optional[str] = None
    correlation_id: str
    request_id: Optional[str] = None
    requested_by: Optional[str] = None
    approved_by: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    rollback_status: Optional[str] = None
    rollback_result: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SOARActionApproval(BaseModel):
    id: str
    tenant_id: str
    execution_id: str
    required_role: Optional[UserRole] = None
    status: SOARApprovalStatus
    requested_by: Optional[str] = None
    decided_by: Optional[str] = None
    decision_comment: Optional[str] = None
    expires_at: Optional[datetime] = None
    created_at: datetime
    decided_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class SOARApprovalDecision(BaseModel):
    comment: Optional[str] = None


class ConnectorActionLog(BaseModel):
    id: str
    tenant_id: str
    execution_id: str
    level: str
    message: str
    data: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ConnectorTestResponse(BaseModel):
    success: bool
    message: Optional[str] = None
    status_code: Optional[int] = None
    response: Dict[str, Any] = {}


# Playbook Schemas
class PlaybookStepDefinition(BaseModel):
    step_key: Optional[str] = None
    name: str
    type: PlaybookStepType
    config: Dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: Optional[int] = Field(default=None, ge=1, le=3600)
    retry_policy: Optional[Dict[str, Any]] = None
    on_success: Optional[str] = None
    on_failure: Optional[str] = None


class PlaybookBase(BaseModel):
    name: str
    description: Optional[str] = None
    status: PlaybookStatus = PlaybookStatus.DRAFT
    trigger_type: PlaybookTriggerType = PlaybookTriggerType.MANUAL_RUN
    trigger_conditions: Optional[Dict[str, Any]] = None


class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_type: PlaybookTriggerType = PlaybookTriggerType.MANUAL_RUN
    trigger_conditions: Optional[Dict[str, Any]] = None
    steps: List[PlaybookStepDefinition] = Field(default_factory=list)
    changelog: Optional[str] = None


class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[PlaybookStatus] = None
    trigger_type: Optional[PlaybookTriggerType] = None
    trigger_conditions: Optional[Dict[str, Any]] = None


class Playbook(PlaybookBase):
    id: str
    tenant_id: str
    active_version_id: Optional[str] = None
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PlaybookVersionCreate(BaseModel):
    steps: List[PlaybookStepDefinition] = Field(default_factory=list)
    changelog: Optional[str] = None


class PlaybookVersion(BaseModel):
    id: str
    playbook_id: str
    tenant_id: str
    version_number: int
    status: PlaybookStatus
    definition: Dict[str, Any]
    changelog: Optional[str] = None
    created_by: Optional[str] = None
    published_by: Optional[str] = None
    published_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PlaybookStepBase(BaseModel):
    name: str
    type: PlaybookStepType
    config: Dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: Optional[int] = Field(default=None, ge=1, le=3600)
    retry_policy: Optional[Dict[str, Any]] = None


class PlaybookStepCreate(PlaybookStepBase):
    pass


class PlaybookStep(PlaybookStepBase):
    id: str
    playbook_id: str
    order: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PlaybookExecutionCreate(BaseModel):
    incident_id: Optional[str] = None
    alert_id: Optional[str] = None
    playbook_id: Optional[str] = None
    trigger_type: PlaybookTriggerType = PlaybookTriggerType.MANUAL_RUN
    context: Dict[str, Any] = Field(default_factory=dict)


class PlaybookExecution(BaseModel):
    id: str
    tenant_id: str
    incident_id: Optional[str] = None
    alert_id: Optional[str] = None
    playbook_id: Optional[str] = None
    version_id: Optional[str] = None
    trigger_type: PlaybookTriggerType = PlaybookTriggerType.MANUAL_RUN
    status: PlaybookExecutionStatus = PlaybookExecutionStatus.PENDING
    triggered_by: Optional[str] = None
    current_step_key: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    paused_at: Optional[datetime] = None
    cancelled_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PlaybookExecutionStep(BaseModel):
    id: str
    execution_id: str
    playbook_id: Optional[str] = None
    version_id: Optional[str] = None
    step_key: str
    name: str
    type: PlaybookStepType
    order: int
    status: PlaybookStepStatus
    config: Optional[Dict[str, Any]] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    attempts: int
    max_attempts: int
    timeout_seconds: Optional[int] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    execution_time_ms: Optional[int] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PlaybookApproval(BaseModel):
    id: str
    tenant_id: str
    execution_id: str
    execution_step_id: Optional[str] = None
    requested_by: Optional[str] = None
    approved_by: Optional[str] = None
    status: PlaybookApprovalStatus
    message: Optional[str] = None
    decision_comment: Optional[str] = None
    created_at: datetime
    decided_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class PlaybookApprovalDecision(BaseModel):
    comment: Optional[str] = None


class PlaybookRunLog(BaseModel):
    id: str
    tenant_id: str
    execution_id: str
    execution_step_id: Optional[str] = None
    level: str
    message: str
    data: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PlaybookVariableCreate(BaseModel):
    playbook_id: Optional[str] = None
    key: str
    value: Any
    scope: str = "tenant"
    is_secret: bool = False


class PlaybookVariableUpdate(BaseModel):
    value: Optional[Any] = None
    scope: Optional[str] = None
    is_secret: Optional[bool] = None


class PlaybookVariable(BaseModel):
    id: str
    tenant_id: str
    playbook_id: Optional[str] = None
    key: str
    value: Any
    scope: str
    is_secret: bool
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Risk Score Response
class RiskScoreResponse(BaseModel):
    risk_score: float
    risk_level: str
    explanation: str


# LogSource Schemas
class LogSourceBase(BaseModel):
    name: str
    type: LogSourceType = LogSourceType.CUSTOM
    description: Optional[str] = None
    status: LogSourceStatus = LogSourceStatus.INACTIVE


class LogSourceCreate(LogSourceBase):
    pass


class LogSourceUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[LogSourceType] = None
    description: Optional[str] = None
    status: Optional[LogSourceStatus] = None


class LogSource(LogSourceBase):
    id: str
    tenant_id: str
    last_seen: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Collector Schemas
class CollectorBase(BaseModel):
    name: str
    type: str
    hostname: Optional[str] = None
    log_source_id: Optional[str] = None

    @field_validator("log_source_id", mode="before")
    @classmethod
    def normalize_optional_log_source_id(cls, value):
        if isinstance(value, str):
            value = value.strip()
            return value or None
        return value


class CollectorCreate(CollectorBase):
    pass


class CollectorRegistrationResponse(BaseModel):
    id: str
    token: str


class Collector(CollectorBase):
    id: str
    tenant_id: str
    status: CollectorStatus
    last_seen: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    health_status: str = "offline"
    collector_version: Optional[str] = None
    platform: Optional[str] = None
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    credential_expires_at: Optional[datetime] = None
    queue_depth: int = 0
    spool_size_bytes: int = 0
    dropped_event_count: int = 0
    events_accepted: int = 0
    events_rejected: int = 0

    model_config = ConfigDict(from_attributes=True)


class CollectorHeartbeat(BaseModel):
    collector_version: Optional[str] = Field(default=None, max_length=50)
    platform: Optional[str] = Field(default=None, max_length=50)
    os_version: Optional[str] = Field(default=None, max_length=150)
    architecture: Optional[str] = Field(default=None, max_length=50)
    queue_depth: int = Field(default=0, ge=0)
    spool_size_bytes: int = Field(default=0, ge=0)
    dropped_event_count: int = Field(default=0, ge=0)
    events_collected: int = Field(default=0, ge=0)
    events_submitted: int = Field(default=0, ge=0)
    retry_count: int = Field(default=0, ge=0)
    cpu_percent: Optional[float] = Field(default=None, ge=0, le=100)
    memory_percent: Optional[float] = Field(default=None, ge=0, le=100)
    disk_percent: Optional[float] = Field(default=None, ge=0, le=100)
    applied_policy_version: Optional[int] = Field(default=None, ge=1)
    checkpoint_status: Optional[str] = Field(default=None, max_length=30)
    uptime_seconds: Optional[int] = Field(default=None, ge=0)
    service_status: Optional[str] = Field(default=None, max_length=30)


class EnrollmentTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    platform: Optional[str] = Field(default=None, max_length=50)
    group_id: Optional[str] = None
    max_uses: int = Field(default=1, ge=1, le=100)
    expires_minutes: int = Field(default=30, ge=5, le=1440)


class EnrollmentTokenResponse(BaseModel):
    id: str
    token: str
    expires_at: datetime


class CollectorEnrollRequest(BaseModel):
    enrollment_token: str
    name: str = Field(min_length=1, max_length=255)
    type: str = Field(min_length=1, max_length=100)
    hostname: Optional[str] = Field(default=None, max_length=255)
    platform: Optional[str] = Field(default=None, max_length=50)
    os_version: Optional[str] = Field(default=None, max_length=150)
    collector_version: Optional[str] = Field(default=None, max_length=50)
    architecture: Optional[str] = Field(default=None, max_length=50)


class DataSourceCreate(BaseModel):
    source_key: str = Field(min_length=1, max_length=150)
    name: str = Field(min_length=1, max_length=255)
    source_type: str = Field(min_length=1, max_length=50)
    vendor: Optional[str] = Field(default=None, max_length=100)
    product: Optional[str] = Field(default=None, max_length=100)
    parser_name: str = Field(default="json", max_length=100)
    transport: str = Field(default="https", max_length=30)
    collector_id: Optional[str] = None
    minimum_quality_score: int = Field(default=0, ge=0, le=100)


class DataSourceResponse(DataSourceCreate):
    id: str
    tenant_id: str
    enabled: bool
    health_status: str
    accepted_count: int
    rejected_count: int
    duplicate_count: int
    events_per_minute: float
    ingestion_lag_seconds: Optional[float] = None
    last_received_at: Optional[datetime] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class DeadLetterResponse(BaseModel):
    id: str
    stage: str
    error_code: str
    safe_error: str
    state: str
    attempts: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


# Resolve forward references
AlertWithRule.model_rebuild()
AIChatResponse.model_rebuild()
