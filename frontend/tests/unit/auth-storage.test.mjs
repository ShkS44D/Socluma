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

test('stored access and refresh credentials are normalized', () => {
  const { api, localStorage } = loadModule('../../src/services/api/authStorage.ts')
  localStorage.setItem(api.AUTH_TOKEN_STORAGE_KEY, 'Bearer access-value')
  localStorage.setItem(api.REFRESH_TOKEN_STORAGE_KEY, ' refresh-value ')
  assert.equal(api.getStoredAuthToken(), 'access-value')
  assert.equal(api.getStoredRefreshToken(), 'refresh-value')
})

test('access-token update preserves the refresh token', () => {
  const { api, localStorage } = loadModule('../../src/services/api/authStorage.ts')
  localStorage.setItem(api.REFRESH_TOKEN_STORAGE_KEY, 'existing-refresh')
  api.setStoredAuthToken('new-access')
  assert.equal(api.getStoredRefreshToken(), 'existing-refresh')
})

test('logout removes credentials from both stores', () => {
  const { api, localStorage, sessionStorage } = loadModule('../../src/services/api/authStorage.ts')
  const keys = [api.AUTH_TOKEN_STORAGE_KEY, api.REFRESH_TOKEN_STORAGE_KEY, 'token']
  for (const storage of [localStorage, sessionStorage]) {
    for (const key of keys) storage.setItem(key, 'credential')
  }
  api.clearStoredAuthToken()
  for (const storage of [localStorage, sessionStorage]) {
    for (const key of keys) assert.equal(storage.getItem(key), null)
  }
})

test('theme preference returns the selected theme', () => {
  const { api, localStorage } = loadModule('../../src/utils/themePreference.ts')
  localStorage.setItem(api.THEME_PREFERENCE_KEY, 'light')
  assert.equal(api.getStoredThemePreference(), 'light')
  assert.equal(localStorage.getItem(api.THEME_PREFERENCE_KEY), 'light')
})

test('namespaced credentials take precedence over the fallback key', () => {
  const auth = loadModule('../../src/services/api/authStorage.ts')
  auth.localStorage.setItem('token', 'fallback-access')
  auth.localStorage.setItem(auth.api.AUTH_TOKEN_STORAGE_KEY, 'current-access')
  assert.equal(auth.api.getStoredAuthToken(), 'current-access')
  const theme = loadModule('../../src/utils/themePreference.ts')
  theme.localStorage.setItem(theme.api.THEME_PREFERENCE_KEY, 'dark')
  assert.equal(theme.api.getStoredThemePreference(), 'dark')
})
