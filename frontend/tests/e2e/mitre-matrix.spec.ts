import { expect, test } from '@playwright/test'
import { INCIDENT_ID } from './incident-fixtures'
import { login, monitorRuntime } from './helpers'

const matrixPayload = {
  incident_count: 1,
  techniques: [{
    tactic: 'Execution',
    technique_id: 'T1059.001',
    technique_name: 'PowerShell',
    parent_technique_id: 'T1059',
    parent_technique_name: 'Command and Scripting Interpreter',
    sub_technique_id: 'T1059.001',
    sub_technique_name: 'PowerShell',
    mapping_source: 'correlated',
    attack_stage_order: 3,
    incident_count: 1,
    supporting_alert_count: 2,
    incidents: [{
      id: INCIDENT_ID,
      title: 'Controlled correlated incident',
      severity: 'high',
      status: 'open',
      confidence: 86,
      supporting_alert_count: 2,
      mapping_source: 'correlated',
      first_seen_at: '2026-07-16T08:00:00Z',
      last_seen_at: '2026-07-16T08:05:00Z',
    }],
  }],
}

test('incident-derived MITRE matrix renders, filters, and drills into its contributing incident', async ({ page }) => {
  const assertNoFailures = monitorRuntime(page)
  const requests: URL[] = []
  await login(page)
  await page.route('**/api/v1/incidents/mitre-matrix**', async (route) => {
    requests.push(new URL(route.request().url()))
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(matrixPayload) })
  })
  await page.goto(`/mitre-matrix?incident_id=${INCIDENT_ID}`)

  await expect(page.getByRole('heading', { name: 'MITRE ATT&CK Matrix' })).toBeVisible()
  await expect(page.getByText('Execution', { exact: true })).toBeVisible()
  await expect(page.getByText('T1059 Command and Scripting Interpreter')).toBeVisible()
  await expect(page.getByText('↳ T1059.001 PowerShell')).toBeVisible()
  await expect(page.getByText('1 incident(s)')).toBeVisible()
  await expect(page.getByText('2 supporting alert(s)')).toBeVisible()
  await expect(page.getByText('Correlated', { exact: true })).toBeVisible()
  expect(requests[0].searchParams.get('incident_id')).toBe(INCIDENT_ID)

  await page.getByLabel('Severity').click()
  await page.getByRole('option', { name: 'high' }).click()
  await expect.poll(() => requests.at(-1)?.searchParams.get('severity')).toBe('high')
  await page.getByLabel('Status').click()
  await page.getByRole('option', { name: 'open' }).click()
  await expect.poll(() => requests.at(-1)?.searchParams.get('status')).toBe('open')

  await page.getByText(/Controlled correlated incident/).click()
  await expect(page).toHaveURL(new RegExp(`/incidents/${INCIDENT_ID}$`))
  assertNoFailures()
})
