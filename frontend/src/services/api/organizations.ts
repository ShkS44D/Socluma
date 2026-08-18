import api from './client'
import {
  AuthResponse,
  Organization,
  OrganizationCreate,
  OrganizationInvitation,
  OrganizationMembership,
  OrganizationRole,
  OrganizationUsage,
  SubscriptionInfo,
} from './types'

export const listOrganizations = async (): Promise<Organization[]> => {
  const response = await api.get<Organization[]>('/api/v1/organizations')
  return response.data
}

export const getCurrentOrganization = async (): Promise<Organization> => {
  const response = await api.get<Organization>('/api/v1/organizations/current')
  return response.data
}

export const getOrganization = async (organizationId: string): Promise<Organization> => {
  const response = await api.get<Organization>(`/api/v1/organizations/${organizationId}`)
  return response.data
}

export const createOrganization = async (data: OrganizationCreate): Promise<Organization> => {
  const response = await api.post<Organization>('/api/v1/organizations', data)
  return response.data
}

export const updateOrganization = async (
  organizationId: string,
  data: Partial<OrganizationCreate> & { status?: string }
): Promise<Organization> => {
  const response = await api.patch<Organization>(`/api/v1/organizations/${organizationId}`, data)
  return response.data
}

export const setDeletionPin = async (organizationId: string, pin: string, currentPassword: string): Promise<void> => {
  await api.put(`/api/v1/organizations/${organizationId}/deletion-pin`, { pin, current_password: currentPassword })
}

export const deleteOrganization = async (organizationId: string, pin: string): Promise<Organization> => {
  const response = await api.delete<Organization>(`/api/v1/organizations/${organizationId}`, { data: { pin } })
  return response.data
}

export const cancelOrganizationDeletion = async (organizationId: string): Promise<Organization> => {
  const response = await api.post<Organization>(`/api/v1/organizations/${organizationId}/deletion/cancel`)
  return response.data
}

export const switchOrganization = async (organizationId: string): Promise<AuthResponse> => {
  const response = await api.post<AuthResponse>('/api/v1/organizations/switch', { organization_id: organizationId })
  return response.data
}

export const listOrganizationMembers = async (organizationId: string): Promise<OrganizationMembership[]> => {
  const response = await api.get<OrganizationMembership[]>(`/api/v1/organizations/${organizationId}/members`)
  return response.data
}

export const updateOrganizationMember = async (
  organizationId: string,
  membershipId: string,
  data: { role?: OrganizationRole; custom_role_id?: string; is_active?: boolean }
): Promise<OrganizationMembership> => {
  const response = await api.patch<OrganizationMembership>(
    `/api/v1/organizations/${organizationId}/members/${membershipId}`,
    data
  )
  return response.data
}

export const listOrganizationInvitations = async (organizationId: string): Promise<OrganizationInvitation[]> => {
  const response = await api.get<OrganizationInvitation[]>(`/api/v1/organizations/${organizationId}/invitations`)
  return response.data
}

export const createOrganizationInvitation = async (
  organizationId: string,
  data: { email: string; role: OrganizationRole; expires_in_days?: number }
): Promise<OrganizationInvitation> => {
  const response = await api.post<OrganizationInvitation>(`/api/v1/organizations/${organizationId}/invitations`, data)
  return response.data
}

export const acceptOrganizationInvitation = async (token: string): Promise<OrganizationInvitation> => {
  const response = await api.post<OrganizationInvitation>('/api/v1/organizations/invitations/accept', { token })
  return response.data
}

export const rejectOrganizationInvitation = async (token: string): Promise<OrganizationInvitation> => {
  const response = await api.post<OrganizationInvitation>('/api/v1/organizations/invitations/reject', { token })
  return response.data
}

export const getOrganizationUsage = async (organizationId: string): Promise<OrganizationUsage> => {
  const response = await api.get<OrganizationUsage>(`/api/v1/organizations/${organizationId}/usage`)
  return response.data
}

export const getOrganizationSubscription = async (organizationId: string): Promise<SubscriptionInfo> => {
  const response = await api.get<SubscriptionInfo>(`/api/v1/organizations/${organizationId}/subscription`)
  return response.data
}

export const getOrganizationApiKeys = async (organizationId: string): Promise<Record<string, unknown>> => {
  const response = await api.get<Record<string, unknown>>(`/api/v1/organizations/${organizationId}/api-keys`)
  return response.data
}
