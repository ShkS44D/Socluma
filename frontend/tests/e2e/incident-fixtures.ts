import { Page } from '@playwright/test'

export const INCIDENT_ID = '11111111-1111-4111-8111-111111111111'
export const ALERT_ID = '22222222-2222-4222-8222-222222222222'
export const EVENT_ID = '33333333-3333-4333-8333-333333333333'
export const RULE_ID = '44444444-4444-4444-8444-444444444444'
export const TENANT_ID = '55555555-5555-4555-8555-555555555555'
const NOW = '2026-07-16T08:00:00Z'

export const correlatedMitreMappings = [{
  tactic: 'Execution',
  technique_id: 'T1059.001',
  technique_name: 'PowerShell',
  parent_technique_id: 'T1059',
  parent_technique_name: 'Command and Scripting Interpreter',
  sub_technique_id: 'T1059.001',
  sub_technique_name: 'PowerShell',
  mapping_source: 'correlated',
  confidence: 86,
  confidence_reasons: ['Correlation strength: 80/100', 'Matched identifiers: hostname, agent_id'],
  supporting_evidence: [{
    alert_id: ALERT_ID,
    event_id: EVENT_ID,
    rule_id: RULE_ID,
    why_matched: 'PowerShell process matched the rule.',
    observed_at: NOW,
    evidence_fields: { hostname: 'controlled-host', agent_id: 'controlled-agent' },
  }],
  source_alert_ids: [ALERT_ID],
  stage_order: 0,
  first_seen_at: NOW,
  last_seen_at: NOW,
}]

const alertLink = (index = 0) => ({
  id: `60000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
  alert_id: index === 0 ? ALERT_ID : `70000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
  correlation_score: index === 0 ? 100 : 80,
  correlation_reason: index === 0 ? 'Primary alert created the incident' : 'Shared host in correlation window',
  is_primary: index === 0,
  attachment_reason: index === 0 ? 'This alert created the incident.' : 'Shared host in correlation window',
  sequence_order: index + 1,
  risk_contribution: 4,
  matching_entities: [],
  matching_indicators: [],
  time_delta_seconds: index * 10,
  created_at: NOW,
  alert: {
    id: index === 0 ? ALERT_ID : `70000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
    tenant_id: TENANT_ID,
    source_id: '88888888-8888-4888-8888-888888888888',
    detection_rule_id: RULE_ID,
    incident_id: INCIDENT_ID,
    event_id: EVENT_ID,
    raw_data: { Image: 'powershell.exe', CommandLine: 'powershell.exe -EncodedCommand test' },
    ocsf_data: { activity_name: 'Process launched' },
    severity: 'high',
    status: 'open',
    risk_score: 80,
    matched_condition: 'Image endswith powershell.exe',
    why_matched: 'PowerShell process matched the rule.',
    created_at: NOW,
    processed_at: NOW,
  },
})

export const incidentDetail = (overrides: Record<string, unknown> = {}) => ({
  id: INCIDENT_ID,
  tenant_id: TENANT_ID,
  title: 'Controlled PowerShell Incident',
  description: 'Controlled release-candidate incident.',
  severity: 'high',
  risk_score: 80,
  status: 'open',
  priority: 'P2',
  due_date: null,
  escalation_level: 0,
  assigned_to: null,
  assigned_at: null,
  assigned_analyst: null,
  ai_summary: null,
  why_suspicious: null,
  ai_analyzed_at: null,
  attack_technique: { technique_id: 'T1059.001', technique_name: 'PowerShell' },
  recommended_actions: [],
  threat_intel_results: [],
  classification: null,
  creation_source: 'detection_engine',
  provenance_status: 'recorded',
  creation_reason: 'The primary alert created this incident.',
  primary_alert_id: ALERT_ID,
  correlation_rule_id: null,
  correlation_rule_name: 'Built-in correlation',
  correlation_key: 'host:controlled',
  correlation_score: 80,
  correlation_window_start: NOW,
  correlation_window_end: NOW,
  first_seen_at: NOW,
  last_seen_at: NOW,
  risk_score_breakdown: { base_severity: 30, multiple_alerts: 10, total: 80 },
  severity_reason: 'High severity primary detection.',
  attack_summary: 'PowerShell activity was detected.',
  status_reason: 'Awaiting analyst triage.',
  created_at: NOW,
  updated_at: NOW,
  resolved_at: null,
  related_alerts: [alertLink(0)],
  correlation_reasons: ['Primary alert created the incident'],
  related_alert_total: 1,
  related_alert_page: 1,
  related_alert_page_size: 20,
  related_alert_has_more: false,
  mitre_mappings: correlatedMitreMappings,
  ...overrides,
})

export const incidentExplanation = (overrides: Record<string, unknown> = {}) => ({
  incident_id: INCIDENT_ID,
  origin: {
    creation_source: 'detection_engine',
    provenance_status: 'recorded',
    derived_fields: [],
    creation_reason: 'The primary alert created this incident.',
    created_at: NOW,
    first_seen_at: NOW,
    last_seen_at: NOW,
    status_reason: 'Awaiting analyst triage.',
  },
  primary_alert: {
    id: ALERT_ID,
    event_id: EVENT_ID,
    detection_rule_id: RULE_ID,
    detection_rule_name: 'Controlled PowerShell Rule',
    severity: 'high',
    status: 'open',
    created_at: NOW,
    why_matched: 'PowerShell process matched the rule.',
    matched_condition: 'Image endswith powershell.exe',
    is_primary: true,
    attachment_reason: 'This alert created the incident.',
    correlation_reason: 'Primary alert created the incident',
    correlation_score: 100,
    sequence_order: 1,
    risk_contribution: 80,
    matching_entities: [],
    matching_indicators: [],
    time_delta_seconds: 0,
  },
  correlated_alerts: [],
  source_events: [{ id: EVENT_ID, source: 'windows-edr', event_type: 'process', severity: 'high', timestamp: NOW, created_at: NOW, processed: true }],
  detection_matches: [{ alert_id: ALERT_ID, event_id: EVENT_ID, rule_id: RULE_ID, rule_name: 'Controlled PowerShell Rule', mitre_technique_id: 'T1059.001', matched_condition: 'Image endswith powershell.exe', why_matched: 'PowerShell process matched the rule.', severity: 'high' }],
  correlation: { rule_id: null, rule_name: 'Built-in correlation', key: 'host:controlled', score: 80, window_start: NOW, window_end: NOW, reasons: ['Primary alert created the incident'] },
  timeline_summary: [{ timestamp: NOW, type: 'event', title: 'Process event observed', resource_id: EVENT_ID }],
  affected_entities: [],
  ioc_summary: [],
  mitre_attack_mapping: [{ technique_id: 'T1059.001', technique_name: 'PowerShell', confidence: 0.9, reasoning: 'Detection rule mapping' }],
  risk_score_breakdown: { base_severity: 30, multiple_alerts: 10, total: 80 },
  severity_reason: 'High severity primary detection.',
  attack_summary: 'PowerShell activity was detected.',
  evidence_summary: {
    source_alert_count: 1,
    source_event_count: 1,
    affected_entity_count: 0,
    manual_evidence: [],
    references: [
      { type: 'incident', id: INCIDENT_ID, label: 'Controlled PowerShell Incident', timestamp: NOW, navigation_path: `/incidents/${INCIDENT_ID}`, available: true },
      { type: 'alert', id: ALERT_ID, label: 'Controlled PowerShell Rule', timestamp: NOW, navigation_path: `/alerts/${ALERT_ID}`, available: true },
      { type: 'event', id: EVENT_ID, label: 'process event', timestamp: NOW, navigation_path: `/events/${EVENT_ID}`, available: true },
      { type: 'detection_rule', id: RULE_ID, label: 'Controlled PowerShell Rule', timestamp: NOW, navigation_path: `/detection-rules/${RULE_ID}`, available: true },
    ],
  },
  recommended_investigation_questions: ['What evidence supports this incident?'],
  limitations: [],
  collection_metadata: {},
  ...overrides,
})

export const installIncidentRoutes = async (
  page: Page,
  options: {
    detail?: Record<string, unknown>
    explanation?: Record<string, unknown>
    pageTwoAlerts?: ReturnType<typeof alertLink>[]
    iocs?: unknown[]
  } = {},
) => {
  await page.route('**/api/v1/incidents/**', async (route) => {
    const url = new URL(route.request().url())
    if (url.pathname === `/api/v1/incidents/${INCIDENT_ID}/explanation`) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(options.explanation || incidentExplanation()) })
      return
    }
    if (url.pathname === `/api/v1/incidents/${INCIDENT_ID}/timeline`) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
      return
    }
    if (url.pathname === `/api/v1/incidents/${INCIDENT_ID}/iocs`) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(options.iocs || []) })
      return
    }
    if (url.pathname === `/api/v1/incidents/${INCIDENT_ID}`) {
      const detail = url.searchParams.get('alert_page') === '2'
        ? incidentDetail({
            ...(options.detail || {}),
            related_alerts: options.pageTwoAlerts || [],
            related_alert_page: 2,
            related_alert_has_more: false,
          })
        : (options.detail || incidentDetail())
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(detail) })
      return
    }
    await route.continue()
  })
}

export const manyAlertFixture = (count: number, offset = 0) => Array.from({ length: count }, (_, index) => alertLink(index + offset))
