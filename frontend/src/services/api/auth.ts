import api from './client'
import { AccountSecurityStatus, AuthResponse, AuthSecurityEvent, AuthSession, LoginResponse, User } from './types'

export const register = async (data: {
  email: string
  password: string
  full_name?: string
  tenant_name: string
  tenant_slug: string
}): Promise<User> => {
  const response = await api.post<User>('/api/v1/auth/register', data)
  return response.data
}

export const login = async (data: {
  email: string
  password: string
}): Promise<LoginResponse> => {
  const response = await api.post<LoginResponse>('/api/v1/auth/login', data)
  return response.data
}

export const completeMfaLogin = async (data: {
  challenge_token: string
  code: string
  recovery_code: boolean
}): Promise<LoginResponse> => {
  const response = await api.post<LoginResponse>('/api/v1/auth/mfa/complete', data)
  return response.data
}

export const requestPasswordReset = async (email: string): Promise<string> =>
  (await api.post('/api/v1/auth/password-reset/request', { email })).data.detail

export const completePasswordReset = async (token: string, newPassword: string): Promise<string> =>
  (await api.post('/api/v1/auth/password-reset/complete', { token, new_password: newPassword })).data.detail

export const requestEmailVerification = async (email: string): Promise<string> =>
  (await api.post('/api/v1/auth/email-verification/request', { email })).data.detail

export const confirmEmailVerification = async (token: string): Promise<string> =>
  (await api.post('/api/v1/auth/email-verification/confirm', { token })).data.detail

export const getAccountSecurityStatus = async (): Promise<AccountSecurityStatus> =>
  (await api.get('/api/v1/account/security/status')).data

export const startMfa = async (currentPassword: string) =>
  (await api.post('/api/v1/account/security/mfa/start', { current_password: currentPassword })).data as {
    qr_code_data_url: string; manual_key: string; provisioning_uri: string; expires_at: string
  }

export const confirmMfa = async (code: string): Promise<string[]> =>
  (await api.post('/api/v1/account/security/mfa/confirm', { code })).data.recovery_codes

export const disableMfa = async (currentPassword: string, code: string): Promise<void> => {
  await api.post('/api/v1/account/security/mfa/disable', { current_password: currentPassword, code })
}

export const regenerateRecoveryCodes = async (currentPassword: string, code: string): Promise<string[]> =>
  (await api.post('/api/v1/account/security/recovery-codes/regenerate', {
    current_password: currentPassword, code,
  })).data.recovery_codes

export const getAuthSessions = async (): Promise<AuthSession[]> =>
  (await api.get('/api/v1/account/security/sessions')).data.items

export const revokeAuthSession = async (id: string): Promise<void> => {
  await api.delete(`/api/v1/account/security/sessions/${id}`)
}

export const getAuthSecurityEvents = async (): Promise<AuthSecurityEvent[]> =>
  (await api.get('/api/v1/account/security/events')).data.items

export const getMe = async (): Promise<User> => {
  const response = await api.get<User>('/api/v1/auth/me')
  return response.data
}

export const refreshToken = async (refresh_token: string): Promise<AuthResponse> => {
  const response = await api.post<AuthResponse>('/api/v1/auth/refresh', { refresh_token })
  return response.data
}

export const logout = async (refresh_token?: string | null): Promise<void> => {
  await api.post('/api/v1/auth/logout', { refresh_token })
}

export const logoutAll = async (): Promise<void> => {
  await api.post('/api/v1/auth/logout-all')
}

export const changePassword = async (data: {
  current_password: string
  new_password: string
}): Promise<void> => {
  await api.post('/api/v1/auth/change-password', data)
}

export const getTenantUsers = async (): Promise<User[]> => {
  const response = await api.get<User[]>('/api/v1/auth/users')
  return response.data
}

export const getUser = async (userId: string): Promise<User> => {
  const response = await api.get<User>(`/api/v1/auth/users/${userId}`)
  return response.data
}

export const updateUser = async (userId: string, data: Partial<{
  full_name?: string
  role?: string
  is_active?: boolean
}>): Promise<User> => {
  const response = await api.put<User>(`/api/v1/auth/users/${userId}`, data)
  return response.data
}

export const deleteUser = async (userId: string): Promise<void> => {
  await api.delete(`/api/v1/auth/users/${userId}`)
}
