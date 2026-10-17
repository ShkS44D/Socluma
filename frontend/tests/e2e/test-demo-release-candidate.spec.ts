import { expect, test } from '@playwright/test'
import { login } from './helpers'

test('bulk IOC navigation and direct route use the same canonical permission', async ({ page }) => {
  await login(page)
  await expect(page.getByRole('button', { name: 'Bulk IOC Operations' }).first()).toBeVisible()
  await page.goto('/threat-intel/bulk')
  await expect(page.getByRole('heading', { name: 'Bulk IOC Operations' })).toBeVisible()
})

test('user without bulk permission sees neither navigation nor protected workspace', async ({ page }) => {
  await page.route('**/api/v1/access-control/effective', async (route) => {
    const response = await route.fetch()
    const body = await response.json() as { permissions: string[] }
    await route.fulfill({ response, json: { ...body, permissions: body.permissions.filter((value) => value !== 'ioc.bulk_manage') } })
  })
  await login(page)
  await expect(page.getByText('Bulk IOC Operations', { exact: true })).toHaveCount(0)
  await page.goto('/threat-intel/bulk')
  await expect(page.getByRole('heading', { name: 'Access denied' })).toBeVisible()
})

test('report download sends bearer authentication and honors a safe server filename', async ({ page }) => {
  let authorization = ''
  await login(page)
  page.on('request', (request) => {
    if (/\/api\/v1\/ioc-commercial\/reports\/[^/]+\/download$/.test(request.url())) {
      authorization = request.headers().authorization || ''
    }
  })
  await page.goto('/threat-intel/reports')
  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Open' }).first().click()
  const download = await downloadPromise
  expect(download.suggestedFilename()).toMatch(/^socluma-ioc-report-[0-9a-f-]+\.json$/)
  expect(authorization).toMatch(/^Bearer /)
  await expect(page.getByText(/Report downloaded as socluma-ioc-report-[0-9a-f-]+\.json/)).toBeVisible()
})
