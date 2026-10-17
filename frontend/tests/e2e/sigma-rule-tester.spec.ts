import { expect, test } from '@playwright/test'
import { login, monitorRuntime } from './helpers'

const apiBaseURL = process.env.E2E_API_BASE_URL || 'http://localhost:8001'

test('saved USB Sigma rule is immediately available in the structured rule tester', async ({ page }) => {
  test.skip(process.env.E2E_SIGMA_RULE_TESTER !== '1', 'Set E2E_SIGMA_RULE_TESTER=1 for real rule tester coverage')
  const assertNoFailures = monitorRuntime(page)
  await login(page)
  const accessToken = await page.evaluate(() => localStorage.getItem('socluma.auth.accessToken'))
  const headers = { Authorization: `Bearer ${accessToken}` }
  const uniqueName = `USB Storage E2E ${Date.now()}`

  const create = await page.request.post(`${apiBaseURL}/api/v1/detection-rules`, {
    headers,
    data: {
      name: uniqueName,
      description: 'Real browser acceptance rule',
      rule_type: 'sigma',
      type: 'sigma',
      severity: 'medium',
      enabled: true,
      sigma_rule: `title: ${uniqueName}
id: 5308ab7f-70c2-4a49-a7f8-753fd52c2188
status: test
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 6416
    DeviceId|contains: USBSTOR
  condition: selection
falsepositives:
  - Approved removable storage devices
level: medium`,
    },
  })
  expect(create.status()).toBe(201)
  const rule = await create.json() as { id: string }

  try {
    await page.goto(`/detection-rules/${rule.id}`)
    await expect(page.getByRole('heading', { name: uniqueName })).toBeVisible()
    await page.getByLabel('Sample Windows event (JSON)').fill(JSON.stringify({
      source: 'windows-agent',
      event_type: 'file',
      raw_event: {
        EventID: '6416',
        Channel: 'Security',
        ProviderName: 'Microsoft-Windows-Security-Auditing',
        EventData: {
          DeviceId: 'USBSTOR\\Disk&Ven_E2E',
          ClassName: 'DiskDrive',
        },
      },
      normalized_event: { product: 'Windows', channel: 'Security' },
    }))
    await page.getByRole('button', { name: 'Run Test' }).click()
    await expect(page.getByText('Final result: MATCH')).toBeVisible()
    await expect(page.getByText(/product=windows matched/i)).toBeVisible()
    await expect(page.getByText(/DeviceId\|contains: expected/)).toBeVisible()
    assertNoFailures()
  } finally {
    await page.request.delete(`${apiBaseURL}/api/v1/detection-rules/${rule.id}`, { headers })
  }
})
