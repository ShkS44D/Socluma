import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import vm from 'node:vm'
import ts from 'typescript'

const makeStorage = () => {
  const entries = new Map()
  return {
    getItem: (key) => entries.get(key) ?? null,
    setItem: (key, value) => entries.set(key, String(value)),
    removeItem: (key) => entries.delete(key),
  }
}

function loadModule(relativePath) {
  const localStorage = makeStorage()
  const sessionStorage = makeStorage()
  const source = readFileSync(new URL(relativePath, import.meta.url), 'utf8')
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  })
  const context = {
    exports: {}, localStorage, sessionStorage,
    window: { localStorage, matchMedia: () => ({ matches: false }), dispatchEvent() {} },
  }
  vm.runInNewContext(outputText, context)
  return { api: context.exports, localStorage, sessionStorage }
}

test('previous access and refresh credentials migrate to Socluma keys', () => {
  const { api, localStorage } = loadModule('../../src/services/api/authStorage.ts')
  localStorage.setItem('vigilantai.auth.accessToken', 'Bearer old-access')
  localStorage.setItem('vigilantai.auth.refreshToken', 'old-refresh')
  assert.equal(api.getStoredAuthToken(), 'old-access')
  assert.equal(api.getStoredRefreshToken(), 'old-refresh')
  assert.equal(localStorage.getItem(api.AUTH_TOKEN_STORAGE_KEY), 'old-access')
  assert.equal(localStorage.getItem(api.REFRESH_TOKEN_STORAGE_KEY), 'old-refresh')
  assert.equal(localStorage.getItem('vigilantai.auth.accessToken'), null)
  assert.equal(localStorage.getItem('vigilantai.auth.refreshToken'), null)
})

test('access-token update preserves a previous refresh token', () => {
  const { api, localStorage } = loadModule('../../src/services/api/authStorage.ts')
  localStorage.setItem('vigilantai.auth.refreshToken', 'old-refresh')
  api.setStoredAuthToken('new-access')
  assert.equal(api.getStoredRefreshToken(), 'old-refresh')
})

test('logout removes current and previous credentials from both stores', () => {
  const { api, localStorage, sessionStorage } = loadModule('../../src/services/api/authStorage.ts')
  const keys = [api.AUTH_TOKEN_STORAGE_KEY, api.REFRESH_TOKEN_STORAGE_KEY, 'token',
    'vigilantai.auth.accessToken', 'vigilantai.auth.refreshToken']
  for (const storage of [localStorage, sessionStorage]) {
    for (const key of keys) storage.setItem(key, 'credential')
  }
  api.clearStoredAuthToken()
  for (const storage of [localStorage, sessionStorage]) {
    for (const key of keys) assert.equal(storage.getItem(key), null)
  }
})

test('theme preference migrates without changing the selected theme', () => {
  const { api, localStorage } = loadModule('../../src/utils/themePreference.ts')
  localStorage.setItem('vigilantai-theme-preference', 'light')
  assert.equal(api.getStoredThemePreference(), 'light')
  assert.equal(localStorage.getItem(api.THEME_PREFERENCE_KEY), 'light')
  assert.equal(localStorage.getItem('vigilantai-theme-preference'), null)
})

test('Socluma credentials and theme take precedence over previous values', () => {
  const auth = loadModule('../../src/services/api/authStorage.ts')
  auth.localStorage.setItem('vigilantai.auth.accessToken', 'old-access')
  auth.localStorage.setItem(auth.api.AUTH_TOKEN_STORAGE_KEY, 'current-access')
  assert.equal(auth.api.getStoredAuthToken(), 'current-access')
  const theme = loadModule('../../src/utils/themePreference.ts')
  theme.localStorage.setItem('vigilantai-theme-preference', 'light')
  theme.localStorage.setItem(theme.api.THEME_PREFERENCE_KEY, 'dark')
  assert.equal(theme.api.getStoredThemePreference(), 'dark')
})
