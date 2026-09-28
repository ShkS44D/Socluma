export const AUTH_TOKEN_STORAGE_KEY = 'vigilantai.auth.accessToken'
export const REFRESH_TOKEN_STORAGE_KEY = 'vigilantai.auth.refreshToken'
export const LEGACY_AUTH_TOKEN_STORAGE_KEY = 'token'
export const AUTH_LOGOUT_EVENT = 'vigilantai:auth-logout'

const decodeBase64Url = (value: string): string => {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=')
  return window.atob(padded)
}

export const sanitizeStoredToken = (value: string | null | undefined): string | null => {
  if (!value) return null

  const trimmed = value.trim().replace(/^"(.*)"$/, '$1')
  const withoutBearer = trimmed.replace(/^Bearer\s+/i, '').trim()

  return withoutBearer || null
}

export const getStoredAuthToken = (): string | null => {
  const primary = sanitizeStoredToken(localStorage.getItem(AUTH_TOKEN_STORAGE_KEY))
  if (primary) {
    return primary
  }

  const legacy = sanitizeStoredToken(localStorage.getItem(LEGACY_AUTH_TOKEN_STORAGE_KEY))
  if (legacy) {
    localStorage.setItem(AUTH_TOKEN_STORAGE_KEY, legacy)
    localStorage.removeItem(LEGACY_AUTH_TOKEN_STORAGE_KEY)
    return legacy
  }

  return null
}

export const getStoredRefreshToken = (): string | null => {
  return sanitizeStoredToken(localStorage.getItem(REFRESH_TOKEN_STORAGE_KEY))
}

export const setStoredAuthToken = (token: string, refreshToken?: string | null): string => {
  const sanitizedToken = sanitizeStoredToken(token) || ''
  localStorage.setItem(AUTH_TOKEN_STORAGE_KEY, sanitizedToken)
  const sanitizedRefreshToken = sanitizeStoredToken(refreshToken)
  if (sanitizedRefreshToken) {
    localStorage.setItem(REFRESH_TOKEN_STORAGE_KEY, sanitizedRefreshToken)
  }
  localStorage.removeItem(LEGACY_AUTH_TOKEN_STORAGE_KEY)
  sessionStorage.removeItem(AUTH_TOKEN_STORAGE_KEY)
  sessionStorage.removeItem(REFRESH_TOKEN_STORAGE_KEY)
  sessionStorage.removeItem(LEGACY_AUTH_TOKEN_STORAGE_KEY)
  return sanitizedToken
}

export const clearStoredAuthToken = (): void => {
  localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY)
  localStorage.removeItem(REFRESH_TOKEN_STORAGE_KEY)
  localStorage.removeItem(LEGACY_AUTH_TOKEN_STORAGE_KEY)
  sessionStorage.removeItem(AUTH_TOKEN_STORAGE_KEY)
  sessionStorage.removeItem(REFRESH_TOKEN_STORAGE_KEY)
  sessionStorage.removeItem(LEGACY_AUTH_TOKEN_STORAGE_KEY)
}

interface JwtPayload {
  exp?: number
}

export const getTokenExpiry = (token: string): number | null => {
  try {
    const [, payload] = token.split('.')
    if (!payload) return null
    const parsed = JSON.parse(decodeBase64Url(payload)) as JwtPayload
    return typeof parsed.exp === 'number' ? parsed.exp : null
  } catch {
    return null
  }
}

export const isTokenExpired = (token: string, skewSeconds: number = 30): boolean => {
  const exp = getTokenExpiry(token)
  if (!exp) return false
  return exp <= Math.floor(Date.now() / 1000) + skewSeconds
}

export const hasUsableStoredToken = (): boolean => {
  const token = getStoredAuthToken()
  if (!token) return false

  if (isTokenExpired(token)) {
    clearStoredAuthToken()
    return false
  }

  return true
}

export const dispatchAuthLogoutEvent = (): void => {
  window.dispatchEvent(new Event(AUTH_LOGOUT_EVENT))
}
