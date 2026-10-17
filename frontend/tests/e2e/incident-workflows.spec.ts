import { expect, test } from '@playwright/test'
import { assertStablePage, login, monitorRuntime } from './helpers'
import {
  ALERT_ID,
  correlatedMitreMappings,
  EVENT_ID,
  INCIDENT_ID,
  incidentDetail,
  incidentExplanation,
  installIncidentRoutes,
  manyAlertFixture,
} from './incident-fixtures'

const openFixture = async (page: Parameters<typeof login>[0]) => {
  await page.goto(`/incidents/${INCIDENT_ID}`)
  await expect(page.getByRole('heading', { name: 'Incident: Controlled PowerShell Incident' })).toBeVisible()
  await assertStablePage(page)
}

test.describe('Incident intelligence release-candidate variants', () => {
  test('manual incident renders explicit provenance and empty primary evidence', async ({ page }) => {
    const assertNoFailures = monitorRuntime(page)
    await login(page)
    await installIncidentRoutes(page, {
      detail: incidentDetail({ creation_source: 'manual', provenance_status: 'manual', primary_alert_id: null, related_alerts: [], related_alert_total: 0 }),
      explanation: incidentExplanation({
        origin: { creation_source: 'manual', provenance_status: 'manual', derived_fields: [], creation_reason: 'Created manually by an analyst.', created_at: '2026-07-16T08:00:00Z', first_seen_at: '2026-07-16T08:00:00Z', last_seen_at: '2026-07-16T08:00:00Z', status_reason: 'Awaiting triage.' },
        primary_alert: null,
        correlated_alerts: [],
        source_events: [],
        detection_matches: [],
        evidence_summary: { source_alert_count: 0, source_event_count: 0, affected_entity_count: 0, manual_evidence: [], references: [] },
      }),
    })
    await openFixture(page)
    await expect(page.getByText('manual', { exact: true })).toBeVisible()
    await expect(page.getByText('No primary alert is available.')).toBeVisible()
    assertNoFailures()
  })

  test('legacy-derived incident labels derived provenance without invented correlation', async ({ page }) => {
    const assertNoFailures = monitorRuntime(page)
    await login(page)
    await installIncidentRoutes(page, {
      detail: incidentDetail({
        provenance_status: 'legacy_derived',
        mitre_mappings: correlatedMitreMappings.map((mapping) => ({
          ...mapping,
          mapping_source: 'legacy-derived',
          confidence_reasons: [],
          supporting_evidence: [],
          source_alert_ids: [],
        })),
      }),
      explanation: incidentExplanation({
        origin: { creation_source: 'detection_engine', provenance_status: 'legacy_derived', derived_fields: ['primary_alert'], creation_reason: 'Historical correlation details are unavailable.', created_at: '2026-07-16T08:00:00Z', first_seen_at: '2026-07-16T08:00:00Z', last_seen_at: '2026-07-16T08:00:00Z', status_reason: null },
        correlation: { rule_id: null, rule_name: 'Unavailable', key: null, score: 0, window_start: null, window_end: null, reasons: [] },
        limitations: ['The incident predates detailed correlation tracking.'],
      }),
    })
    await openFixture(page)
    await expect(page.getByText(/Legacy incident: derived fields are labelled/i)).toBeVisible()
    await expect(page.getByText('Unavailable', { exact: true })).toBeVisible()
    await expect(page.getByText('Historical metadata')).toBeVisible()
    await expect(page.getByText(/verified supporting alert evidence was not recorded/i)).toBeVisible()
    assertNoFailures()
  })

  test('playbook-created incident retains playbook provenance', async ({ page }) => {
    const assertNoFailures = monitorRuntime(page)
    await login(page)
    await installIncidentRoutes(page, {
      detail: incidentDetail({ creation_source: 'playbook_engine', provenance_status: 'recorded' }),
      explanation: incidentExplanation({
        origin: { creation_source: 'playbook_engine', provenance_status: 'recorded', derived_fields: [], creation_reason: 'Created by an approved playbook execution.', created_at: '2026-07-16T08:00:00Z', first_seen_at: '2026-07-16T08:00:00Z', last_seen_at: '2026-07-16T08:00:00Z', status_reason: 'Awaiting triage.' },
      }),
    })
    await openFixture(page)
    await expect(page.getByText('playbook engine', { exact: true })).toBeVisible()
    await expect(page.getByText(/Primary: Controlled PowerShell Rule/)).toBeVisible()
    assertNoFailures()
  })

  test('missing optional relationships render safe empty states', async ({ page }) => {
    const assertNoFailures = monitorRuntime(page)
    await login(page)
    await installIncidentRoutes(page, {
      detail: incidentDetail({ description: null, assigned_analyst: null, ai_summary: null, attack_technique: null, recommended_actions: null, threat_intel_results: [] }),
      explanation: incidentExplanation({ affected_entities: [], ioc_summary: [], limitations: ['No optional enrichment is available.'] }),
    })
    await openFixture(page)
    await expect(page.getByText('No structured entities were found in the linked evidence.')).toBeVisible()
    await expect(page.locator('body')).not.toContainText(/\bnull\b|\bundefined\b/i)
    assertNoFailures()
  })

  test('incident with no IOCs shows the correct threat-intelligence empty state', async ({ page }) => {
    const assertNoFailures = monitorRuntime(page)
    await login(page)
    await installIncidentRoutes(page, { iocs: [] })
    await openFixture(page)
    await page.getByRole('tab', { name: 'Threat Intelligence' }).click()
    await expect(page.getByText('No IOCs associated with this incident.')).toBeVisible()
    assertNoFailures()
  })

  test('incident with no MITRE mapping does not render a false mapping', async ({ page }) => {
    const assertNoFailures = monitorRuntime(page)
    await login(page)
    await installIncidentRoutes(page, {
      detail: incidentDetail({ attack_technique: null, mitre_mappings: [] }),
      explanation: incidentExplanation({ mitre_attack_mapping: [], detection_matches: [{ alert_id: ALERT_ID, event_id: EVENT_ID, rule_id: null, rule_name: 'Unmapped rule', mitre_technique_id: null, matched_condition: 'controlled', why_matched: 'controlled', severity: 'high' }] }),
    })
    await openFixture(page)
    await expect(page.getByText(/MITRE:/)).toHaveCount(0)
    await expect(page.getByText(/Primary: Controlled PowerShell Rule/)).toBeVisible()
    assertNoFailures()
  })

  test('correlated MITRE mapping renders parent, sub-technique, confidence, and stored evidence', async ({ page }) => {
    const assertNoFailures = monitorRuntime(page)
    await login(page)
    await installIncidentRoutes(page)
    await openFixture(page)
    await expect(page.getByText('Stage 1: Execution')).toBeVisible()
    await expect(page.getByText('Parent technique: T1059 Command and Scripting Interpreter')).toBeVisible()
    await expect(page.getByText('Sub-technique: T1059.001 PowerShell')).toBeVisible()
    await expect(page.getByText('86% confidence')).toBeVisible()
    await expect(page.getByText('Correlation strength: 80/100')).toBeVisible()
    await expect(page.getByText(`Alert: ${ALERT_ID}`)).toBeVisible()
    await expect(page.getByText('hostname: controlled-host')).toBeVisible()
    assertNoFailures()
  })

  test('many related alerts paginate without replacing the first page', async ({ page }) => {
    const assertNoFailures = monitorRuntime(page)
    const firstPage = manyAlertFixture(20)
    const secondPage = manyAlertFixture(5, 20)
    await login(page)
    await installIncidentRoutes(page, {
      detail: incidentDetail({ related_alerts: firstPage, related_alert_total: 25, related_alert_has_more: true }),
      pageTwoAlerts: secondPage,
    })
    await openFixture(page)
    await page.getByRole('tab', { name: 'Related Alerts' }).click()
    await expect(page.locator('tbody tr')).toHaveCount(20)
    await page.getByRole('button', { name: 'Load more alerts (20 of 25)' }).click()
    await expect(page.locator('tbody tr')).toHaveCount(25)
    await expect(page.getByRole('button', { name: /Load more alerts/ })).toHaveCount(0)
    assertNoFailures()
  })

  test('safe event evidence reference opens the referenced event', async ({ page }) => {
    const assertNoFailures = monitorRuntime(page)
    await login(page)
    await installIncidentRoutes(page)
    await page.route(`**/api/v1/events/${EVENT_ID}`, (route) => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ id: EVENT_ID, tenant_id: '55555555-5555-4555-8555-555555555555', source: 'windows-edr', event_type: 'process', raw_event: {}, normalized_event: {}, severity: 'high', timestamp: '2026-07-16T08:00:00Z', processed: true, detection_count: 1, created_at: '2026-07-16T08:00:00Z' }),
    }))
    await openFixture(page)
    await page.getByRole('link', { name: 'event: process event' }).click()
    await expect(page).toHaveURL(new RegExp(`/events/${EVENT_ID}$`))
    await expect(page.getByRole('heading', { name: 'Event: process' })).toBeVisible()
    assertNoFailures()
  })

  test('unavailable incident access returns an error state without a blank page', async ({ page }) => {
    const assertNoFailures = monitorRuntime(page, [/AxiosError/i, /Failed to load resource/i])
    await login(page)
    await page.goto('/incidents/99999999-9999-4999-8999-999999999999')
    await expect(page.getByText('Failed to load incident details.')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Retry' })).toBeVisible()
    await assertStablePage(page)
    assertNoFailures()
  })

  test('script-like entity values are rendered as text and never executed', async ({ page }) => {
    const assertNoFailures = monitorRuntime(page)
    const hostile = '<img src=x onerror="window.__soclumaInjected=true">'
    await login(page)
    await installIncidentRoutes(page, {
      explanation: incidentExplanation({
        affected_entities: [{ id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', type: 'process', value: hostile, normalized_value: hostile, role: 'observed', first_seen_at: '2026-07-16T08:00:00Z', last_seen_at: '2026-07-16T08:00:00Z', source_event_id: EVENT_ID, source_alert_id: ALERT_ID, confidence: 1, risk_contribution: 10 }],
      }),
    })
    await openFixture(page)
    await expect(page.getByText(`process: ${hostile}`)).toBeVisible()
    expect(await page.evaluate(() => Boolean((window as typeof window & { __soclumaInjected?: boolean }).__soclumaInjected))).toBe(false)
    assertNoFailures()
  })

  test('Socluma Copilot double submit sends one provider request', async ({ page }) => {
    const assertNoFailures = monitorRuntime(page)
    let chatRequests = 0
    await login(page)
    await page.route(`**/api/v1/ai/incident/${INCIDENT_ID}/conversations**`, async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
    })
    await page.route(`**/api/v1/ai/incident/${INCIDENT_ID}/chat`, async (route) => {
      chatRequests += 1
      await new Promise((resolve) => setTimeout(resolve, 250))
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ conversation_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', answer: 'One grounded response.', messages: [], evidence_references: [], confidence: 80, limitations: [], suggested_follow_up_questions: [], model: 'deterministic', provider: 'local_deterministic', generated_at: '2026-07-16T08:00:00Z', request_id: 'test', fallback_used: true, context_stats: {} }),
      })
    })
    await page.goto(`/ai/incident-copilot?incidentId=${INCIDENT_ID}`)
    await page.getByLabel('Question').fill('Which alert created it?')
    await page.getByRole('button', { name: 'Ask Socluma Copilot' }).dblclick()
    await expect(page.getByText('One grounded response.')).toBeVisible()
    expect(chatRequests).toBe(1)
    assertNoFailures()
  })

  test('Socluma Copilot labels OpenAI and historical Gemini provider metadata safely', async ({ page }) => {
    const assertNoFailures = monitorRuntime(page)
    await login(page)
    await page.route(`**/api/v1/ai/incident/${INCIDENT_ID}/conversations**`, async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
    })
    let provider = 'openai'
    await page.route(`**/api/v1/ai/incident/${INCIDENT_ID}/chat`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          conversation_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
          answer: 'Grounded provider response.',
          messages: [],
          evidence_references: [],
          confidence: 80,
          limitations: [],
          suggested_follow_up_questions: [],
          model: provider === 'openai' ? 'gpt-5.6-luna' : 'gemini-historical-snapshot',
          provider,
          generated_at: '2026-07-16T08:00:00Z',
          request_id: 'test',
          fallback_used: false,
          context_stats: {},
          token_usage: { input_tokens: 20, output_tokens: 10, total_tokens: 30, cached_input_tokens: 5, reasoning_tokens: 3 },
        }),
      })
      provider = 'gemini'
    })
    await page.goto(`/ai/incident-copilot?incidentId=${INCIDENT_ID}`)
    await page.getByRole('button', { name: 'Ask Socluma Copilot' }).click()
    await expect(page.getByText('OpenAI / gpt-5.6-luna')).toBeVisible()
    await expect(page.getByText('30 tokens (20 in / 10 out)')).toBeVisible()
    await page.getByRole('button', { name: 'Ask Socluma Copilot' }).click()
    await expect(page.getByText('Gemini (historical) / gemini-historical-snapshot')).toBeVisible()
    assertNoFailures()
  })

  test('Socluma Copilot conversation history survives a page reload', async ({ page }) => {
    const assertNoFailures = monitorRuntime(page)
    const conversationId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
    const messages = [
      { id: 'c1111111-1111-4111-8111-111111111111', role: 'user', content: 'What happened first?', created_at: '2026-07-16T08:00:00Z' },
      { id: 'c2222222-2222-4222-8222-222222222222', role: 'assistant', content: 'The process event occurred first.', created_at: '2026-07-16T08:00:01Z' },
    ]
    await login(page)
    await page.route(`**/api/v1/ai/incident/${INCIDENT_ID}/conversations**`, async (route) => {
      const url = new URL(route.request().url())
      const body = url.pathname.endsWith(`/${conversationId}`)
        ? { id: conversationId, incident_id: INCIDENT_ID, user_id: 'user', title: 'History', created_at: '2026-07-16T08:00:00Z', updated_at: '2026-07-16T08:00:01Z', message_count: 2, messages }
        : [{ id: conversationId, incident_id: INCIDENT_ID, user_id: 'user', title: 'History', created_at: '2026-07-16T08:00:00Z', updated_at: '2026-07-16T08:00:01Z', message_count: 2 }]
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
    })
    await page.goto(`/ai/incident-copilot?incidentId=${INCIDENT_ID}`)
    await expect(page.getByText('The process event occurred first.')).toBeVisible()
    await page.reload()
    await expect(page.getByText('What happened first?')).toBeVisible()
    await expect(page.getByText('The process event occurred first.')).toBeVisible()
    assertNoFailures()
  })
})
