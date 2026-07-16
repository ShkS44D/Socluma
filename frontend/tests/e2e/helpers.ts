import { expect, Page, test } from '@playwright/test'

const email = process.env.E2E_EMAIL
const password = process.env.E2E_PASSWORD
let cachedAuth: { accessToken: string; refreshToken: string | null } | null = null

export const login = async (page: Page): Promise<void> => {
  test.skip(!email || !password, 'E2E_EMAIL and E2E_PASSWORD are required')
  if (cachedAuth) {
    await page.goto('/login')
    await page.evaluate(({ accessToken, refreshToken }) => {
      localStorage.setItem('triageops.auth.accessToken', accessToken)
      if (refreshToken) localStorage.setItem('triageops.auth.refreshToken', refreshToken)
    }, cachedAuth)
    await page.goto('/dashboard')
    await expect(page).toHaveURL(/\/dashboard$/)
    return
  }
  await page.goto('/login')
  await page.getByLabel('Email Address').fill(email!)
  await page.getByLabel('Password').fill(password!)
  await page.getByRole('button', { name: 'Sign In' }).click()
  await expect(page).toHaveURL(/\/dashboard$/)
  cachedAuth = await page.evaluate(() => ({
    accessToken: localStorage.getItem('triageops.auth.accessToken') || '',
    refreshToken: localStorage.getItem('triageops.auth.refreshToken'),
  }))
}

export const monitorRuntime = (page: Page, allowed: RegExp[] = []) => {
  const failures: string[] = []
  const permitted = (value: string) => allowed.some((pattern) => pattern.test(value))
  page.on('pageerror', (error) => {
    if (!permitted(error.message)) failures.push(`pageerror: ${error.message}`)
  })
  page.on('console', (message) => {
    if (message.type() === 'error' && !permitted(message.text())) failures.push(`console: ${message.text()}`)
  })
  page.on('requestfailed', (request) => {
    const value = `${request.url()} ${request.failure()?.errorText || ''}`
    if (request.failure()?.errorText === 'net::ERR_ABORTED') return
    if (!permitted(value)) failures.push(`requestfailed: ${value}`)
  })
  return () => expect(failures).toEqual([])
}

export const assertStablePage = async (page: Page): Promise<void> => {
  await expect(page.locator('body')).not.toContainText(/\bundefined\b/i)
  await expect(page.getByText(/Loading Incident Details|Loading workspace/i)).toHaveCount(0)
  await expect(page.locator('body')).toBeVisible()
}
