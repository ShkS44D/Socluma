import { create } from 'zustand'
import { getEffectivePermissions } from '../services/api/accessControl'

interface PermissionState {
  permissions: string[]
  role: string | null
  organizationId: string | null
  loaded: boolean
  load: () => Promise<void>
  clear: () => void
  can: (permission: string) => boolean
}

export const usePermissionStore = create<PermissionState>((set, get) => ({
  permissions: [],
  role: null,
  organizationId: null,
  loaded: false,
  load: async () => {
    const effective = await getEffectivePermissions()
    set({
      permissions: effective.permissions,
      role: effective.role,
      organizationId: effective.organization_id,
      loaded: true,
    })
  },
  clear: () => set({ permissions: [], role: null, organizationId: null, loaded: false }),
  can: (permission) => get().permissions.includes(permission),
}))
