import { expect, Page, test } from '@playwright/test'
import { login } from './helpers'

const openFirstIncident = async (page: Page): Promise<string> => {
  await page.goto('/incidents')
  await expect(page.getByRole('heading', { name: 'Incident Queue' })).toBeVisible()
  const row = page.locator('tbody tr').first()
  await expect(row).toBeVisible()
  await row.click()
  await expect(page).toHaveURL(/\/incidents\/[0-9a-f-]{36}$/i)
  await expect(page.getByRole('heading', { name: /^Incident:/ })).toBeVisible()
  return page.url()
}

test.describe('Incident intelligence browser regression', () => {
  test('login opens a real incident without browser errors', async ({ page }) => {
    const pageErrors: string[] = []
    page.on('pageerror', (error) => pageErrors.push(error.message))
    page.on('console', (message) => {
      if (message.type() === 'error') pageErrors.push(message.text())
    })
    await login(page)
    await openFirstIncident(page)
    await expect(page.getByText(/Related Alerts:/)).toBeVisible()
    expect(pageErrors).toEqual([])
  })

  test('secondary timeline data is requested only when its tab opens', async ({ page }) => {
    await login(page)
    const timelineRequests: string[] = []
    page.on('request', (request) => {
      if (request.url().includes('/timeline')) timelineRequests.push(request.url())
    })
    await openFirstIncident(page)
    expect(timelineRequests).toHaveLength(0)
    await page.getByRole('tab', { name: 'Timeline' }).click()
    await expect.poll(() => timelineRequests.length).toBe(1)
    await expect(page.getByText(/Timeline|No timeline events/i).last()).toBeVisible()
  })

  test('core incident remains usable when explanation fails', async ({ page }) => {
    await login(page)
    await page.route('**/api/v1/incidents/*/explanation', (route) => route.abort())
    await openFirstIncident(page)
    await expect(page.getByRole('heading', { name: 'Incident Details' })).toBeVisible()
    await expect(page.getByText('The explanation service is temporarily unavailable. Core incident data remains available.')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Retry' })).toHaveCount(0)
  })

  test('authentication logout event does not recurse or crash the page', async ({ page }) => {
    const pageErrors: string[] = []
    page.on('pageerror', (error) => pageErrors.push(error.message))
    page.on('console', (message) => {
      if (message.type() === 'error') pageErrors.push(message.text())
    })
    await login(page)
    await page.evaluate(() => window.dispatchEvent(new Event('socluma:auth-logout')))
    await expect(page).toHaveURL(/\/login$/)
    expect(pageErrors).toEqual([])
  })
})
