export interface HealthCheck {
  status: string
  database: string
  redis: string
  request_id?: string
  service?: string
  version?: string
  environment?: string
  timestamp?: string
  checks?: Record<string, {
    status: string
    latency_ms?: number
    detail?: string
  }>
}

export interface AuthResponse {
  access_token: string
  refresh_token?: string
  token_type: string
  expires_in?: number
}

export interface User {
  id: string
  email: string
  full_name?: string
  tenant_id: string
  role: string
  is_active: boolean
  created_at: string
  updated_at: string
}

export type UserRole = 'admin' | 'analyst' | 'responder' | 'viewer'
export type OrganizationRole = 'owner' | 'administrator' | 'soc_manager' | 'analyst' | 'viewer'
export type OrganizationStatus = 'active' | 'suspended' | 'disabled' | 'deleted'
export type InvitationStatus = 'pending' | 'accepted' | 'rejected' | 'expired' | 'revoked'

export interface Organization {
  id: string
  name: string
  slug: string
  description?: string | null
  logo?: string | null
  industry?: string | null
  country?: string | null
  timezone: string
  subscription_plan: string
  max_users: number
  max_collectors: number
  max_storage: number
  status: OrganizationStatus
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface OrganizationCreate {
  name: string
  slug: string
  description?: string
  industry?: string
  country?: string
  timezone?: string
  subscription_plan?: string
  max_users?: number
  max_collectors?: number
  max_storage?: number
}

export interface OrganizationMembership {
  id: string
  tenant_id: string
  user_id: string
  role: OrganizationRole
  is_active: boolean
  invited_by?: string | null
  created_at: string
  updated_at: string
  user?: User
}

export interface OrganizationInvitation {
  id: string
  tenant_id: string
  email: string
  role: OrganizationRole
  status: InvitationStatus
  invited_by?: string | null
  invited_user_id?: string | null
  expires_at: string
  accepted_at?: string | null
  rejected_at?: string | null
  created_at: string
  updated_at: string
  token?: string | null
}

export interface OrganizationUsage {
  organization_id: string
  user_count: number
  collector_count: number
  event_count: number
  alert_count: number
  playbook_count: number
  soar_execution_count: number
  storage_bytes: number
  api_request_count: number
  limits: Record<string, number>
}

export interface SubscriptionInfo {
  plan: string
  limits: Record<string, number>
  usage: OrganizationUsage
}

export interface AIArtifact {
  id: string
  tenant_id: string
  incident_id?: string | null
  alert_id?: string | null
  ioc_id?: string | null
  artifact_type: string
  model: string
  content: Record<string, any>
  confidence_score?: number | null
  created_by?: string | null
  created_at: string
}

export interface AIIncidentSummary {
  executive_summary: string
  technical_summary: string
  root_cause: string
  impact: string
  recommended_next_steps: string[]
  suggested_containment: string[]
  suggested_mitre_attack_techniques: Array<Record<string, any>>
  confidence_score: number
  artifact: AIArtifact
}

export interface AIChatResponse {
  conversation_id: string
  answer: string
  messages: Array<{ id: string; role: string; content: string; message_metadata?: Record<string, any> | null; created_at: string }>
  evidence_references: EvidenceReference[]
  confidence: number
  limitations: string[]
  suggested_follow_up_questions: string[]
  model: string
  provider: string
  generated_at: string
  request_id?: string | null
  fallback_used: boolean
  context_stats?: {
    available?: Record<string, number>
    included?: Record<string, number>
    omitted?: Record<string, number>
    context_bytes?: number
    estimated_tokens?: number
    selection_applied?: boolean
    max_bytes?: number
  }
  token_usage?: {
    input_tokens?: number | null
    output_tokens?: number | null
    total_tokens?: number | null
    cached_input_tokens?: number | null
    reasoning_tokens?: number | null
  } | null
  configured_model?: string | null
  provider_latency_ms?: number | null
  resolved_model?: string | null
  response_id?: string | null
  provider_request_id?: string | null
  completion_status?: string | null
  error_category?: string | null
}

export interface AIConversationSummary {
  id: string
  incident_id: string
  user_id: string
  title?: string | null
  created_at: string
  updated_at: string
  message_count: number
}

export interface AIConversationDetail extends AIConversationSummary {
  messages: AIChatResponse['messages']
}

export interface AIReportResponse {
  incident_id: string
  markdown: string
  sections: Record<string, any>
  artifact: AIArtifact
}

export interface AITimelineResponse {
  incident_id: string
  entries: Array<{ timestamp: string; title: string; description?: string | null; source: string; resource_id?: string | null }>
  artifact: AIArtifact
}

export interface AIAlertExplanation {
  why_triggered: string
  detection_rule?: Record<string, any> | null
  matched_fields: Record<string, any>
  why_suspicious: string
  false_positive_assessment: string
  recommended_actions: string[]
  confidence_score: number
  artifact: AIArtifact
}

export interface AIIocAnalysis {
  threat_description: string
  malware_families: string[]
  known_campaigns: string[]
  confidence: number
  risk_level: string
  recommended_blocking: string[]
  mitre_attack_mapping: Array<Record<string, any>>
  hunting_recommendations: string[]
  artifact: AIArtifact
}

export interface AIDetectionSuggestions {
  suggestions: Array<{
    rule_name: string
    logic: Record<string, any>
    fields: string[]
    severity: Severity
    false_positive_considerations: string[]
  }>
  artifact: AIArtifact
}

export interface AIPlaybookSuggestions {
  suggestions: Array<{
    name: string
    trigger: string
    conditions: string[]
    actions: string[]
    approvals: string[]
    soar_steps: string[]
    expected_outcome: string
  }>
  artifact: AIArtifact
}
export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type AlertStatus = 'open' | 'investigating' | 'resolved' | 'dismissed'
export type IncidentStatus = 'open' | 'investigating' | 'resolved' | 'closed'
export type IncidentPriority = 'p1' | 'p2' | 'p3' | 'p4'

export interface Alert {
  id: string
  tenant_id: string
  source_id: string
  incident_id?: string | null
  raw_data?: Record<string, unknown>
  ocsf_data: Record<string, any>
  severity: Severity
  status: AlertStatus
  risk_score?: number
  created_at: string
  processed_at?: string
  detection_rule_id?: string | null
  event_id?: string | null
  why_matched?: string | null
  matched_condition?: string | null
  detection_rule?: DetectionRule | null
}

export interface AlertWithRule extends Alert {
  detection_rule?: DetectionRule | null
}

export interface AlertListResponse {
  items: Alert[]
  total: number
  page: number
  page_size: number
}

export interface AlertCreate {
  source: string
  raw_data: Record<string, unknown>
}

export interface ThreatIntelResult {
  id?: string
  indicator: string
  type: 'ip' | 'domain' | 'url' | 'hash'
  source: string
  result: Record<string, any>
  risk_impact: number
  created_at?: string
}

export type Classification = 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'BENIGN'

export interface Incident {
  id: string
  tenant_id: string
  title: string
  description?: string
  severity: Severity
  risk_score: number
  status: IncidentStatus
  priority: IncidentPriority
  due_date?: string | null
  escalation_level: number
  ai_summary?: string | null
  why_suspicious?: string | null
  ai_analyzed_at?: string | null
  attack_technique?: Record<string, any> | null
  recommended_actions?: string[] | null
  threat_intel_results?: ThreatIntelResult[] | null
  classification?: Classification | null
  creation_source?: string
  creation_reason?: string | null
  primary_alert_id?: string | null
  correlation_rule_id?: string | null
  correlation_rule_name?: string | null
  correlation_key?: string | null
  correlation_score?: number | null
  correlation_window_start?: string | null
  correlation_window_end?: string | null
  first_seen_at?: string | null
  last_seen_at?: string | null
  risk_score_breakdown?: Record<string, any>
  severity_reason?: string | null
  attack_summary?: string | null
  status_reason?: string | null
  assigned_to?: string | null
  assigned_at?: string | null
  assigned_analyst?: User | null
  created_at: string
  updated_at: string
  resolved_at?: string | null
  alert_count: number
}

export interface IncidentRelatedAlert {
  id: string
  alert_id: string
  correlation_score: number
  correlation_reason?: string | null
  is_primary?: boolean
  attachment_reason?: string | null
  sequence_order?: number
  risk_contribution?: number | null
  matching_entities?: Array<Record<string, any>>
  matching_indicators?: Array<Record<string, any>>
  time_delta_seconds?: number | null
  created_at: string
  alert: Alert
}

export interface EvidenceReference {
  type: 'incident' | 'alert' | 'event' | 'detection_rule' | 'entity' | 'ioc' | 'evidence' | string
  id: string
  label: string
  timestamp?: string | null
  navigation_path?: string | null
  available?: boolean
  unavailable_reason?: string | null
}

export interface IncidentExplanation {
  incident_id: string
  origin: {
    creation_source: string
    provenance_status: 'recorded' | 'legacy_derived' | 'manual' | string
    derived_fields: string[]
    creation_reason: string
    created_at: string
    first_seen_at: string
    last_seen_at: string
    status_reason?: string | null
  }
  primary_alert?: IncidentAlertContribution | null
  correlated_alerts: IncidentAlertContribution[]
  source_events: Array<{
    id: string
    source: string
    event_type: string
    severity: string
    timestamp: string
    created_at: string
    processed: boolean
  }>
  detection_matches: Array<{
    alert_id: string
    event_id?: string | null
    rule_id?: string | null
    rule_name?: string | null
    mitre_technique_id?: string | null
    matched_condition?: string | null
    why_matched?: string | null
    severity: string
  }>
  correlation: {
    rule_id?: string | null
    rule_name: string
    key?: string | null
    score: number
    window_start?: string | null
    window_end?: string | null
    reasons: string[]
  }
  timeline_summary: Array<{ timestamp: string; type: string; title: string; resource_id: string }>
  affected_entities: Array<{
    id: string
    type: string
    value: string
    normalized_value: string
    role?: string | null
    first_seen_at?: string | null
    last_seen_at?: string | null
    source_event_id?: string | null
    source_alert_id?: string | null
    confidence?: number | null
    risk_contribution?: number | null
  }>
  ioc_summary: Array<{
    id: string
    type: string
    value: string
    severity: string
    confidence: number
    enrichment_count: number
    malicious_reports: number
  }>
  mitre_attack_mapping: Array<Record<string, any>>
  risk_score_breakdown: Record<string, any>
  severity_reason?: string | null
  attack_summary?: string | null
  evidence_summary: {
    source_alert_count: number
    source_event_count: number
    affected_entity_count: number
    manual_evidence: Array<Record<string, any>>
    references: EvidenceReference[]
  }
  recommended_investigation_questions: string[]
  limitations: string[]
  collection_metadata?: Record<string, {
    total: number
    included: number
    page: number
    page_size: number
    has_more: boolean
  }>
}

export interface IncidentAlertContribution {
  id: string
  event_id?: string | null
  detection_rule_id?: string | null
  detection_rule_name?: string | null
  severity: string
  status: string
  created_at: string
  why_matched?: string | null
  matched_condition?: string | null
  is_primary: boolean
  attachment_reason?: string | null
  correlation_reason?: string | null
  correlation_score: number
  sequence_order: number
  risk_contribution: number
  matching_entities: Array<Record<string, any>>
  matching_indicators: Array<Record<string, any>>
  time_delta_seconds: number
}

export interface IncidentDetail extends Omit<Incident, 'alert_count'> {
  related_alerts: IncidentRelatedAlert[]
  correlation_reasons: string[]
  related_alert_total: number
  related_alert_page: number
  related_alert_page_size: number
  related_alert_has_more: boolean
}

export interface InvestigationNote {
  id: string
  incident_id: string
  user_id: string
  content: string
  created_at: string
  updated_at: string
  user?: User
}

export interface TimelineActor {
  user_id?: string | null
  name?: string | null
  email?: string | null
}

export interface TimelineItem {
  id: string
  event_type:
    | 'incident_created'
    | 'alert_created'
    | 'status_changed'
    | 'feedback_submitted'
    | 'note_added'
    | 'assignment'
    | 'audit'
  title: string
  description?: string | null
  created_at: string
  actor?: TimelineActor | null
  metadata: Record<string, any>
}

export interface AnalystActivity {
  user_id: string
  analyst_name: string
  assigned_count: number
  active_investigations: number
  note_count: number
  feedback_count: number
  resolved_count: number
}

export interface IncidentListResponse {
  items: Incident[]
  total: number
  page: number
  page_size: number
}

export interface IncidentStats {
  total_incidents: number
  critical_incidents: number
  average_risk_score: number
  active_investigations: number
  average_resolution_time_hours: number
  mean_time_to_detect_hours?: number
  mean_time_to_respond_hours?: number
  open_incidents_by_severity?: Record<string, number>
  top_alert_sources?: Array<Record<string, any>>
  analyst_activity: AnalystActivity[]
}

export interface FeedbackCreate {
  classification: Classification
  comment?: string
}

export interface FeedbackResponse {
  id: string
  tenant_id: string
  incident_id: string
  user_id: string
  classification: Classification
  comment?: string
  created_at: string
  user?: {
    id: string
    email: string
    full_name?: string
  }
}

export interface FeedbackStats {
  total_reviewed: number
  true_positives: number
  false_positives: number
  benign: number
  accuracy_percentage: number
}

export interface AIAnalysisResponse {
  summary: string
  why_suspicious: string
  attack_technique: Record<string, any>
  recommended_actions: string[]
  threat_intel_results: ThreatIntelResult[]
}

export interface SecurityEvent {
  id: string
  tenant_id: string
  source: string
  event_type: string
  raw_event: Record<string, any>
  normalized_event: Record<string, any>
  severity: Severity
  timestamp: string
  processed: boolean
  detection_count?: number
  detection_status?: 'matched' | 'none' | string
  created_at: string
}

export interface EventAnalysisResponse {
  event_id: string
  processed: boolean
  matched_rules: Array<Record<string, any>>
  incident_created: boolean
  incident_id?: string | null
}

export interface IngestionResponse extends SecurityEvent {
  detections: Array<Record<string, any>>
  incident_created?: boolean | null
  incident_id?: string | null
}

export interface DetectionRule {
  id: string
  tenant_id: string
  created_by?: string | null
  name: string
  description?: string | null
  severity: Severity
  type?: string
  query?: string | null
  sigma_rule?: string | null
  rule_content?: Record<string, any> | null
  rule_type?: string
  event_type?: string | null
  enabled: boolean
  mitre_technique_id?: string | null
  created_at: string
  updated_at: string
}

export interface DetectionRuleCreate {
  name: string
  description?: string
  severity?: Severity
  type?: string
  rule_type?: string
  query?: string
  sigma_rule?: string
  rule_content?: Record<string, any>
  enabled?: boolean
}

export interface DetectionRuleUpdate extends Partial<DetectionRuleCreate> {}

// IOC Types
export type IndicatorType = 'ip' | 'domain' | 'url' | 'hash'

export interface IOCEnrichment {
  id: string
  ioc_id: string
  provider: string
  reputation?: string | null
  malicious_count: number
  total_reports: number
  raw_response?: Record<string, any> | null
  created_at: string
}

export interface IOC {
  id: string
  tenant_id: string
  type: IndicatorType
  value: string
  description?: string | null
  source?: string | null
  severity: Severity
  confidence_score: number
  tags?: string[] | null
  is_active: boolean
  created_by?: string | null
  created_at: string
  updated_at: string
  enrichments: IOCEnrichment[]
}

export interface IOCListResponse {
  items: IOC[]
  total: number
  page: number
  page_size: number
}

export interface IOCCreate {
  type: IndicatorType
  value: string
  description?: string
  source?: string
  severity?: Severity
  confidence_score?: number
  tags?: string[]
  is_active?: boolean
}

export interface IOCUpdate {
  description?: string
  source?: string
  severity?: Severity
  confidence_score?: number
  tags?: string[]
  is_active?: boolean
}

export interface IOCStats {
  total_iocs: number
  malicious_iocs: number
  high_confidence: number
  recent_iocs: number
}

export type LogSourceType = 'windows_edr' | 'linux_audit' | 'firewall' | 'cloudtrail' | 'application_log' | 'custom'
export type LogSourceStatus = 'active' | 'inactive' | 'error'

export interface LogSource {
  id: string
  tenant_id: string
  name: string
  type: LogSourceType
  description?: string
  status: LogSourceStatus
  last_seen?: string
  created_at: string
  updated_at: string
}

export interface LogSourceCreate {
  name: string
  type?: LogSourceType
  description?: string
  status?: LogSourceStatus
}

export interface LogSourceUpdate {
  name?: string
  type?: LogSourceType
  description?: string
  status?: LogSourceStatus
}

export type CollectorStatus = 'online' | 'offline' | 'error'

export interface Collector {
  id: string
  tenant_id: string
  name: string
  type: string
  hostname?: string
  log_source_id?: string
  status: CollectorStatus
  last_seen?: string
  created_at: string
  updated_at: string
}

export interface CollectorCreate {
  name: string
  type: string
  hostname?: string
  log_source_id?: string
}

export interface CollectorRegistrationResponse {
  id: string
  token: string
}

export type PlaybookStatus = 'draft' | 'testing' | 'active' | 'disabled' | 'archived'
export type PlaybookTriggerType =
  | 'alert_created'
  | 'incident_created'
  | 'incident_severity_changed'
  | 'manual_run'
  | 'scheduled'
  | 'webhook'
export type PlaybookStepType =
  | 'condition'
  | 'delay'
  | 'approval'
  | 'notification'
  | 'ai_analysis'
  | 'threat_intel_lookup'
  | 'http_request'
  | 'webhook'
  | 'python_script'
  | 'create_incident'
  | 'update_incident'
  | 'close_incident'
  | 'tag_alert'
  | 'assign_analyst'
  | 'create_task'
  | 'branch'
  | 'end'
  | 'action'
export type PlaybookExecutionStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'awaiting_approval'
  | 'paused'
export type PlaybookStepStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'skipped'
  | 'cancelled'
  | 'awaiting_approval'
export type PlaybookApprovalStatus = 'pending' | 'approved' | 'rejected' | 'cancelled'

export interface PlaybookStepDefinition {
  step_key?: string
  name: string
  type: PlaybookStepType
  config?: Record<string, any>
  timeout_seconds?: number | null
  retry_policy?: Record<string, any> | null
  on_success?: string | null
  on_failure?: string | null
}

export interface Playbook {
  id: string
  tenant_id: string
  name: string
  description?: string | null
  status: PlaybookStatus
  trigger_type: PlaybookTriggerType
  trigger_conditions?: Record<string, any> | null
  active_version_id?: string | null
  created_by?: string | null
  created_at: string
  updated_at: string
}

export interface PlaybookCreate {
  name: string
  description?: string
  trigger_type?: PlaybookTriggerType
  trigger_conditions?: Record<string, any>
  steps?: PlaybookStepDefinition[]
  changelog?: string
}

export interface PlaybookVersion {
  id: string
  playbook_id: string
  tenant_id: string
  version_number: number
  status: PlaybookStatus
  definition: { steps?: PlaybookStepDefinition[]; [key: string]: any }
  changelog?: string | null
  created_by?: string | null
  published_by?: string | null
  published_at?: string | null
  created_at: string
}

export interface PlaybookExecution {
  id: string
  tenant_id: string
  incident_id?: string | null
  alert_id?: string | null
  playbook_id?: string | null
  version_id?: string | null
  trigger_type: PlaybookTriggerType
  status: PlaybookExecutionStatus
  triggered_by?: string | null
  current_step_key?: string | null
  context?: Record<string, any> | null
  started_at?: string | null
  completed_at?: string | null
  paused_at?: string | null
  cancelled_at?: string | null
  result?: Record<string, any> | null
  created_at: string
}

export interface PlaybookExecutionStep {
  id: string
  execution_id: string
  step_key: string
  name: string
  type: PlaybookStepType
  order: number
  status: PlaybookStepStatus
  result?: Record<string, any> | null
  error?: string | null
  attempts: number
  max_attempts: number
  execution_time_ms?: number | null
  created_at: string
}

export interface PlaybookApproval {
  id: string
  tenant_id: string
  execution_id: string
  execution_step_id?: string | null
  status: PlaybookApprovalStatus
  message?: string | null
  decision_comment?: string | null
  created_at: string
  decided_at?: string | null
}

export interface PlaybookRunLog {
  id: string
  execution_id: string
  execution_step_id?: string | null
  level: string
  message: string
  data?: Record<string, any> | null
  created_at: string
}

export type ConnectorType = 'webhook' | 'slack' | 'teams' | 'smtp_email' | 'generic_rest'
export type ConnectorStatus = 'active' | 'disabled' | 'error'
export type CredentialStatus = 'active' | 'disabled' | 'rotated'
export type ActionExecutionStatus = 'queued' | 'awaiting_approval' | 'running' | 'completed' | 'failed' | 'cancelled' | 'rolled_back'
export type SOARApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired'

export interface ActionConnector {
  id: string
  tenant_id: string
  name: string
  type: ConnectorType
  status: ConnectorStatus
  config: Record<string, any>
  requires_approval: boolean
  approval_roles?: UserRole[] | null
  created_at: string
  updated_at: string
}

export interface ActionConnectorCreate {
  name: string
  type: ConnectorType
  config: Record<string, any>
  requires_approval?: boolean
  approval_roles?: UserRole[]
}

export interface ConnectorCredential {
  id: string
  tenant_id: string
  connector_id: string
  name: string
  status: CredentialStatus
  secret_fingerprint: string
  schema_version: number
  rotated_at?: string | null
  created_at: string
  updated_at: string
}

export interface ConnectorActionExecution {
  id: string
  tenant_id: string
  connector_id: string
  credential_id?: string | null
  playbook_execution_id?: string | null
  playbook_step_id?: string | null
  action_name: string
  status: ActionExecutionStatus
  request?: Record<string, any> | null
  response?: Record<string, any> | null
  error?: string | null
  retry_policy?: Record<string, any> | null
  attempts: number
  max_attempts: number
  timeout_seconds?: number | null
  worker_id?: string | null
  correlation_id: string
  request_id?: string | null
  requested_by?: string | null
  approved_by?: string | null
  started_at?: string | null
  completed_at?: string | null
  duration_ms?: number | null
  created_at: string
  updated_at: string
}

export interface SOARActionApproval {
  id: string
  tenant_id: string
  execution_id: string
  required_role?: UserRole | null
  status: SOARApprovalStatus
  decision_comment?: string | null
  expires_at?: string | null
  created_at: string
  decided_at?: string | null
}

export interface ConnectorActionLog {
  id: string
  tenant_id: string
  execution_id: string
  level: string
  message: string
  data?: Record<string, any> | null
  created_at: string
}
