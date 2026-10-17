# Authorization Model

## Security boundary

The backend is the authoritative authorization boundary. Frontend navigation,
route guards, and disabled buttons improve usability but are not security
controls. Every tenant operation resolves an authenticated access-token tenant,
an active organization, an active membership, and the required effective
permission. Missing context is denied. A route organization identifier must
match the signed active-organization context; cross-tenant identifiers return a
non-enumerating not-found response.

Global `User.role` remains only as a legacy platform/bootstrap compatibility
field. It does not authorize tenant resources. Tenant authority comes from
`OrganizationMembership.role` or its assigned custom role.

## Active organization

Access tokens contain the active tenant (`tid`) and session (`sid`). Every
request revalidates the tenant, membership, user, and session. Refresh tokens
retain the same tenant context. Switching organizations validates an active
membership and issues a new token pair without changing the user's persisted
primary tenant or global role. Disabled, deleted, and pending-deletion
organizations cannot be selected for ordinary access. The frontend clears
permission state and tenant-specific cached state during a switch.

## Permission catalog and built-in roles

Stable permissions are defined in `backend/src/core/permissions.py` and grouped
for the role editor. They separate view, create, update, assign, close, enable,
delete, execute, approve, export, and security-management operations across
users, roles, organizations, alerts, incidents, detections, Sigma, playbooks,
SOAR, threat intelligence, audit, Socluma Copilot, collectors, API keys,
subscriptions, usage, reports, assets, notifications, and settings.

- **Owner:** all organization permissions, including protected security,
  deletion, cancellation, and owner management.
- **Administrator:** broad operational and membership administration, but no
  organization security/deletion, custom-role deletion, or unrestricted SOAR
  approval.
- **SOC Manager:** operational management of investigations, detections,
  analysts, reports, and response workflows without ownership or critical
  security authority.
- **Analyst:** investigation, alert/incident work, evidence-oriented resources,
  and Socluma Copilot without user, role, credential, or organization-security
  administration.
- **Viewer:** explicit read-only operational access.

Built-in role identities are code-controlled and cannot be deleted. Custom role
names are normalized and unique within a tenant. Reserved built-in names,
unknown permissions, permissions the actor does not possess, and owner-only
permissions are rejected. Assigned custom roles cannot be deleted. Permission
changes increment a revision and are resolved from the database on requests so
revocations take effect promptly.

## Protected policies

Reusable policy helpers compare effective protected capabilities, not only role
names. They block self-promotion, grants beyond the actor's permissions,
non-owner owner assignment or management, cross-tenant assignment, unsafe
custom-role mutation, and disabling or demoting the final active owner. Session
revocation is self-service unless the actor has organization security authority.
Tenant-scoped service queries validate resource and parent ownership.

## Sensitive-action approval

Organizations can select `none`, `one_person`, or `two_person` approval for the
supported sensitive actions. Approval records bind tenant, requester, action
type, target, expiration, and an HMAC fingerprint of safe metadata. The
requester cannot approve their request; two-person mode requires two distinct
authorized approvers. Expired, rejected, mismatched, executed, or reused
approvals are rejected. Metadata recursively rejects secret-like fields.
Organization deletion is the first action integrated with this foundation.

## API keys, collectors, and WebSockets

Organization API keys are tenant-bound, hash-only at rest, shown once, expiring,
revocable, and limited to an allowlist of explicit non-administrative scopes.
Authentication rejects missing scopes, expiry, and revocation. Collector
credentials remain limited to ingestion and heartbeat endpoints and derive
their tenant from the credential; they cannot authenticate analyst/admin
dependencies. WebSockets validate access-token tenant membership and session,
authorize the channel permission, close at token expiry, and re-check active
membership during heartbeat.

## Stable errors

Authentication failures use 401. Authenticated authorization failures use 403
with codes such as `MEMBERSHIP_REQUIRED`, `MEMBERSHIP_DISABLED`,
`ORGANIZATION_DISABLED`, `PERMISSION_DENIED`, `OWNER_REQUIRED`,
`OWNER_ONLY_PERMISSION`, `FINAL_OWNER_PROTECTED`, `ROLE_PROTECTED`,
`ROLE_IN_USE`, `ROLE_ASSIGNMENT_DENIED`, and
`PRIVILEGE_ESCALATION_BLOCKED`. Cross-tenant object probes use 404
`RESOURCE_ACCESS_DENIED`. Approval failures use `APPROVAL_REQUIRED`,
`APPROVAL_INVALID`, and `APPROVAL_EXPIRED`.

## Route migration inventory

Public routes are limited to health/docs and authentication entry flows.
Account-security and notification routes are authenticated, own-resource
policies. Tenant routers use explicit permissions:

| Area | Read | Mutating/sensitive |
| --- | --- | --- |
| Organizations/members | `organization.view`, `users.view` | `organization.update`, `organization.security.manage`, `organization.delete`, `users.invite`, `roles.assign` |
| Roles/API keys/audit | `roles.view`, `api_keys.view`, `audit.view` | `roles.create/update/delete`, `api_keys.manage`, `audit.export` |
| Alerts/incidents | `alerts.view`, `incidents.view` | operation-specific create/update/assign/close permissions |
| Detections/Sigma | `detections.view`, `sigma.view` | create/update/enable/delete permissions |
| Playbooks/SOAR | `playbooks.view`, `soar.view` | create/update/publish/execute/approve and credential permissions |
| Telemetry/intelligence | collector, alert, asset, and threat-intelligence view permissions | explicit manage/revoke/create permissions |
| Socluma Copilot | `triage_ai.use` | management remains separately reserved |
| Usage/subscription/reporting | `usage.view`, `subscriptions.view`, `reports.view` | export permissions where applicable |

Health and intentionally public authentication endpoints have no tenant
permission. Registration/bootstrap creation is the only path that creates an
initial owner membership. Compatibility aliases normalize old custom-role
permission identifiers at runtime; no route uses the legacy `require_roles`
guard.

## Testing strategy

Tests cover built-in and custom-role matrices, missing/disabled memberships,
cross-tenant route denial, owner-only restrictions, privilege escalation,
final-owner protection, role conflicts and role-in-use behavior, session-bound
tenant switching, API-key scope/expiry/hash behavior, approval separation and
non-reuse, collector separation, migrations, and frontend compilation. Add a
negative tenant and permission case whenever a protected endpoint is added.

There is no hidden organization super-admin bypass. Development bootstrap is
explicit configuration and production startup validation rejects unsafe
defaults. SSO, SCIM, MSP hierarchy, temporary-elevation UI, and full SOAR
workflow approvals are not implemented.
