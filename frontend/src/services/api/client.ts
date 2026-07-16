import axios, { AxiosHeaders, AxiosResponse, InternalAxiosRequestConfig } from 'axios'
import {
  clearStoredAuthToken,
  dispatchAuthLogoutEvent,
  getStoredAuthToken,
  getStoredRefreshToken,
  isTokenExpired,
  setStoredAuthToken,
} from './authStorage'
import { AuthResponse } from './types'

const apiBaseURL = import.meta.env.VITE_API_BASE_URL || ''

const api = axios.create({
  baseURL: apiBaseURL,
  timeout: Number(import.meta.env.VITE_API_TIMEOUT_MS || 20000),
  headers: {
    'Content-Type': 'application/json',
  },
})

let refreshPromise: Promise<string | null> | null = null

const isAuthenticationEndpoint = (url?: string): boolean => {
  return Boolean(url && /\/api\/v1\/auth\/(login|register)$/.test(url))
}

const redirectToLogin = (): void => {
  if (window.location.pathname !== '/login') {
    window.location.assign('/login')
  }
}

const refreshAccessToken = async (): Promise<string | null> => {
  const refreshToken = getStoredRefreshToken()
  if (!refreshToken) {
    return null
  }

  if (!refreshPromise) {
    refreshPromise = axios
      .post<AuthResponse>(`${apiBaseURL}/api/v1/auth/refresh`, {
        refresh_token: refreshToken,
      })
      .then((response) => {
        const { access_token, refresh_token } = response.data
        setStoredAuthToken(access_token, refresh_token)
        return access_token
      })
      .catch(() => null)
      .finally(() => {
        refreshPromise = null
      })
  }

  return refreshPromise
}

const setAuthorizationHeader = (
  config: InternalAxiosRequestConfig,
  token: string
): InternalAxiosRequestConfig => {
  const headerValue = `Bearer ${token}`

  if (config.headers instanceof AxiosHeaders) {
    config.headers.set('Authorization', headerValue)
  } else {
    // Convert to AxiosHeaders
    const headers = AxiosHeaders.from(config.headers || {})
    headers.set('Authorization', headerValue)
    config.headers = headers
  }

  return config
}

api.interceptors.request.use(
  (config) => {
    const token = getStoredAuthToken()
    if (!token) {
      return config
    }

    if (isTokenExpired(token)) {
      return refreshAccessToken().then((newToken) => {
        if (!newToken) {
          clearStoredAuthToken()
          dispatchAuthLogoutEvent()
          redirectToLogin()
          return Promise.reject(new Error('Authentication token has expired.'))
        }
        return setAuthorizationHeader(config, newToken)
      })
    }

    return setAuthorizationHeader(config, token)
  },
  (error) => Promise.reject(error)
)

api.interceptors.response.use(
  (response: AxiosResponse) => response,
  async (error) => {
    const originalRequest = error.config as (InternalAxiosRequestConfig & { _retry?: boolean }) | undefined

    if (
      error.response?.status === 401 &&
      originalRequest &&
      !originalRequest._retry &&
      !isAuthenticationEndpoint(originalRequest.url)
    ) {
      originalRequest._retry = true
      const newToken = await refreshAccessToken()
      if (newToken) {
        return api(setAuthorizationHeader(originalRequest, newToken))
      }
    }

    if (error.response?.status === 401 && !isAuthenticationEndpoint(error.config?.url)) {
      clearStoredAuthToken()
      dispatchAuthLogoutEvent()
      redirectToLogin()
    }
    return Promise.reject(error)
  }
)

export default api
