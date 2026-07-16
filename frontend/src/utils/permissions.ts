export type UserRole = 'admin' | 'analyst' | 'responder' | 'viewer'

export const ROLES: Record<UserRole, number> = {
  viewer: 1,
  responder: 2,
  analyst: 3,
  admin: 4,
}

export interface Permission {
  requiredRole: UserRole
}

export function hasRole(userRole: string | null, requiredRole: UserRole): boolean {
  if (!userRole) return false
  const userRoleKey = userRole.toLowerCase() as UserRole
  // Check if userRoleKey is actually in ROLES
  if (!(userRoleKey in ROLES)) {
    return false
  }
  return ROLES[userRoleKey] >= ROLES[requiredRole]
}

export function canAccess(
  userRole: string | null,
  permission: Permission
): boolean {
  return hasRole(userRole, permission.requiredRole)
}

export const PERMISSIONS = {
  deleteRules: { requiredRole: 'admin' },
  manageUsers: { requiredRole: 'admin' },
  analyzeIncidents: { requiredRole: 'analyst' },
  runInvestigations: { requiredRole: 'analyst' },
  executeResponseActions: { requiredRole: 'responder' },
}
