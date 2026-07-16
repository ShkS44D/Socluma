import api from './client'
import { AuthResponse, User } from './types'

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
}): Promise<AuthResponse> => {
  const response = await api.post<AuthResponse>('/api/v1/auth/login', data)
  return response.data
}

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
