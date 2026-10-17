# Socluma User Manual

For version history, reviews, tests, simulation, exceptions, maintenance windows,
ATT&CK coverage, and content packs, see
[Detection Engineering](DETECTION_ENGINEERING.md).

## Search and investigations

Open **Search**, choose Events, Alerts, Incidents, or Entities, enter a structured query, and run it. Results stay inside the active organization and default to 24 hours. Save useful queries or use **Investigation Workspace** for resources, evidence, and notes. Syntax and troubleshooting are in `SEARCH_INVESTIGATIONS.md`.

## Audit administration

Authorized users can open **Audit Logs** to filter historical events and inspect
actor, action, resource, severity, result, request IDs, and safe before/after data.
The other tabs verify chain integrity, edit retention, manage legal holds, and
request CSV, JSONL, or evidence-package exports. A failed integrity check requires
investigation; Socluma never automatically repairs it. Downloads expire and
require the authorization issued with the export job.

## Introduction

Socluma is a tenant-isolated SOC platform for collecting telemetry, triaging alerts, managing incidents, running detections and response automation, and using Socluma Copilot for evidence-grounded investigation support.

## Login and account access

1. Open the Socluma sign-in page.
2. Enter your organization email and password.
3. Select **Sign In**. Repeated failures can temporarily lock the account.
4. Use the organization switcher when you belong to multiple organizations. Access and data change with the selected organization.
5. Sign out from the profile menu. Change your password in Settings; doing so revokes existing sessions.

### MFA, recovery, and account security

Open **Account Security** to enable authenticator MFA. Enter your current password, scan the QR code (or enter the manual key), and confirm a current six-digit code. MFA becomes active only after confirmation. Save the ten recovery codes immediately: each works once and cannot be displayed again. You may regenerate them after confirming your password and authenticator code, which invalidates all older codes.

When MFA is active, sign-in pauses after the password step for an authenticator or recovery code. Repeated invalid codes temporarily lock MFA verification. If you lose both the authenticator and recovery codes, contact an authorized administrator and follow your organization’s identity-verification process.

The same page lists your sessions and recent authentication activity. Revoke devices you do not recognize, use **Log out all devices** after suspected compromise, and investigate items marked suspicious or critical.

Use **Forgot password?** on the sign-in page to request a reset link. The page always shows the same response, whether or not an address exists. A successful reset revokes all existing sessions. Email-verification and reset links are single-use and expire.

## Dashboard, alerts, and incidents

The Dashboard summarizes current alert volume, incidents, severity, and recent activity. Open **Alerts** to filter and investigate the queue. Select an alert for evidence and status actions. Promote or associate relevant alerts with an incident. Use **Incidents** to assign ownership, change priority/status, add evidence and notes, and review the timeline.

## Detection and Sigma rules

Open **Detection Rules** to inspect, create, test, enable, or disable rules when your assigned permissions allow it. Sigma rules use the same tenant boundary and should be tested against representative telemetry before activation.

## Socluma Copilot

Open **Socluma Copilot** from Investigations. Choose an incident or supported artifact, ask a focused question, and verify responses against cited tenant evidence. Do not submit passwords, tokens, keys, or unrelated personal information.

## Playbooks and SOAR connectors

Use **Playbooks** to draft, test, approve, publish, and monitor workflows. Connector setup is under **SOAR Connectors**. Store credentials only in the connector credential fields. Approval-gated or disruptive actions should be reviewed before execution.

## Threat intelligence

Use **Threat Intelligence** to search and enrich indicators. Confirm confidence, source, age, and tenant relevance before changing an incident based on enrichment.

Authorized analysts also receive dedicated IOC workspaces for review assignments, watchlists,
historical hunts, encrypted threat sources, TAXII/MISP synchronization, dry-run bulk imports,
relationship graphs, disabled detection drafts, approval-gated response recommendations, and
expiring reports. Credentials are entered only in **Threat Sources** and are never displayed
again. Do not paste keys into IOC descriptions, notes, filters, screenshots, or support messages.

## Users, roles, and permissions

Owners and authorized administrators manage members and invitations from Administration. **Roles & Permissions** lists custom roles and their individual permissions. Create a role, select only the necessary permissions, save it, then assign it to members. Administrators intentionally do not receive owner-only role or account-deletion permissions. Only an owner can grant owner-level access, and the final active owner cannot be removed.

The organization selector changes the active security context and refreshes
permissions. If a direct link opens **Unauthorized**, switch to the correct
organization or ask an owner for the specific permission. Custom roles cannot
include owner-only permissions, use protected role names, or grant more
authority than their creator possesses. API key secrets appear only once at
creation; store them securely and revoke them when no longer needed.

## Deletion PIN and account deletion

1. As an organization owner, open **Organization Settings**.
2. Under **Deletion PIN**, enter exactly four digits and your current password.
3. Select **Set / Reset PIN**. The PIN is hashed and is never displayed again.
4. To schedule deletion, switch to another organization, select **Schedule deletion**, and enter the PIN. The organization immediately enters a restricted `pending_deletion` state. The dialog shows the scheduled purge time, and an owner can use **Cancel deletion** during the cooling-off period. After the deadline, an administrator can run the purge task; operational data is removed while deletion audit evidence is retained.

## Understanding usage

The Usage page shows current tenant-scoped counts for active users, collectors, stored events, alerts, incidents, playbook definitions and executions, SOAR actions, Socluma Copilot requests, and API requests. API request totals use the active UTC month and exclude health, metrics, API documentation, and static documentation traffic. “Application Payload Storage (estimate)” measures persisted event and alert JSON plus incident text; it is not the server's disk usage.

Five failed verification attempts trigger a temporary 15-minute lock. If the PIN is forgotten, an owner can reset it with their current password. Deletion disables the organization and access to its tenant data; follow your retention and backup procedures before confirming.

## Viewing and exporting logs

Open **Audit Logs** to search historical activity, filter by status and other supported fields, change pages, and review UTC timestamps. Choose **Export CSV** or **Export JSON** to export the complete filtered result. Exports themselves are audited. Users can access only their current organization’s logs.

## Troubleshooting

- **Access denied:** confirm the selected organization and ask an owner to review your role permissions.
- **Account locked:** wait for the lock period or contact an owner.
- **No telemetry:** verify collector status and its log source configuration.
- **Playbook action failed:** review execution history and connector health.
- **Socluma Copilot unavailable:** continue the investigation with stored evidence and ask an administrator to check provider configuration.

## Security best practices

Use a unique password, protect the deletion PIN separately, grant least privilege, keep at least two trusted owners, review audit logs and exports, rotate connector credentials, validate Socluma Copilot output, and never paste secrets into notes, prompts, or support requests.
