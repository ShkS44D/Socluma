import { expect, test } from '@playwright/test'
import { login, monitorRuntime } from './helpers'

const apiBaseURL = process.env.E2E_API_BASE_URL || 'http://localhost:8001'

test('real event-to-correlated-incident-to-MITRE-matrix lifecycle', async ({ page }) => {
  test.setTimeout(90_000)
  test.skip(process.env.E2E_REAL_LIFECYCLE !== '1', 'Set E2E_REAL_LIFECYCLE=1 for the isolated real API lifecycle')
  const assertNoFailures = monitorRuntime(page)
  await login(page)
  const accessToken = await page.evaluate(() => localStorage.getItem('triageops.auth.accessToken'))
  expect(accessToken).toBeTruthy()
  const headers = { Authorization: `Bearer ${accessToken}` }

  const simulation = await page.request.post(`${apiBaseURL}/api/v1/events/simulate/full_attack_chain`, { headers })
  expect(simulation.status()).toBe(201)
  const events = await simulation.json() as Array<{ incident_created: boolean; incident_id?: string; detection_count: number }>
  expect(events).toHaveLength(3)
  expect(events[0].incident_created).toBe(false)
  expect(events.every((event) => event.detection_count >= 1)).toBe(true)
  const incidentIds = new Set(events.slice(1).map((event) => event.incident_id).filter(Boolean))
  expect(incidentIds.size).toBe(1)
  const incidentId = [...incidentIds][0]!

  const detailResponse = await page.request.get(`${apiBaseURL}/api/v1/incidents/${incidentId}?include_alert_payloads=true`, { headers })
  expect(detailResponse.ok()).toBeTruthy()
  const detail = await detailResponse.json()
  expect(detail.related_alert_total).toBe(3)
  expect(detail.mitre_mappings.length).toBeGreaterThanOrEqual(3)
  expect(detail.mitre_mappings.every((item: any) => item.mapping_source === 'correlated')).toBe(true)
  expect(detail.mitre_mappings.every((item: any) => item.source_alert_ids.length > 0 && item.supporting_evidence.length > 0)).toBe(true)

  await page.goto(`/incidents/${incidentId}`)
  await expect(page.getByRole('heading', { name: /Incident:/ })).toBeVisible()
  await expect(page.getByText('MITRE ATT&CK progression')).toBeVisible()
  await expect(page.getByText(/Parent technique:/).first()).toBeVisible()
  await expect(page.getByText(/confidence/).first()).toBeVisible()
  await expect(page.getByText('Stored evidence').first()).toBeVisible()
  await expect(page.getByText('Correlated evidence').first()).toBeVisible()

  await page.getByRole('button', { name: 'Open matrix' }).click()
  await expect(page).toHaveURL(new RegExp(`/mitre-matrix\\?incident_id=${incidentId}`))
  await expect(page.getByText('MITRE ATT&CK Matrix')).toBeVisible()
  await expect(page.getByText('1 supporting alert(s)').first()).toBeVisible()
  await page.getByLabel('Severity').click()
  await page.getByRole('option', { name: detail.severity }).click()
  await page.getByLabel('Status').click()
  await page.getByRole('option', { name: detail.status }).click()
  await page.getByRole('button').filter({ hasText: detail.title }).first().click()
  await expect(page).toHaveURL(new RegExp(`/incidents/${incidentId}$`))
  assertNoFailures()
})
