import api from './client'

export interface CustomRole {
  id: string; tenant_id: string; name: string; description?: string | null
  permissions: string[]; is_system: boolean; is_protected: boolean
  permission_revision: number; created_at: string; updated_at: string
}
export interface PermissionDescriptor {
  identifier: string; category: string; description: string; owner_only: boolean
}
export interface EffectivePermissions {
  organization_id: string; membership_id: string; role: string; custom_role_id?: string | null
  permissions: string[]; permission_revision: number
}
export const getEffectivePermissions = async () =>
  (await api.get<EffectivePermissions>('/api/v1/access-control/effective')).data
export const listPermissions = async () =>
  (await api.get<{permissions: PermissionDescriptor[]}>('/api/v1/access-control/permissions')).data.permissions
export const listCustomRoles = async () => (await api.get<CustomRole[]>('/api/v1/access-control/roles')).data
export const createCustomRole = async (data: Pick<CustomRole, 'name' | 'permissions'> & {description?: string}) =>
  (await api.post<CustomRole>('/api/v1/access-control/roles', data)).data
export const updateCustomRole = async (id: string, data: Partial<Pick<CustomRole, 'name' | 'description' | 'permissions'>>) =>
  (await api.patch<CustomRole>(`/api/v1/access-control/roles/${id}`, data)).data
export const deleteCustomRole = async (id: string) => api.delete(`/api/v1/access-control/roles/${id}`)
