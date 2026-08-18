# TriageOps Developer Manual

For rule schemas, lifecycle transitions, simulation workers, migration 1800, and
the offline CLI, see [Phase 7 Detection Engineering](PHASE7_DETECTION_ENGINEERING.md).

## Phase 6 search contract

See `PHASE6_SEARCH_INVESTIGATIONS.md`. Add searchable fields only through the central catalog with type, operators, resource, and permission, followed by parser, tenant-isolation, projection, and index tests. Never pass display query text to raw SQL.

## Phase 4 audit contract

Call `audit_service.record` with a stable action, explicit resource, result, and safe
before/after values for every security or administrative state change. Never insert,
update, or delete `AuditLog` directly. Metadata is sanitized centrally, but callers
must still avoid collecting unnecessary personal or secret data. Use
`audit_management_service` and the existing Celery tasks for retention and exports.
Configure versioned encryption and integrity keys as documented in
`PHASE4_AUDIT_DATA_PROTECTION.md`; never put keys in models, APIs, logs, or fixtures.

## Architecture

TriageOps consists of a FastAPI/SQLAlchemy backend, React/TypeScript frontend, collector agent, PostgreSQL or SQLite database, optional Redis/Celery workers, and Docker/Nginx deployment definitions. API routers call tenant-aware services; models and Alembic migrations define durable state.

## Backend and frontend structure

Backend code lives under `backend/src`: `api/v1` contains HTTP routes, `services` contains business rules, `models` contains SQLAlchemy and Pydantic models, and `core` contains authentication, permissions, database, crypto, logging, and observability. Frontend code is under `frontend/src`: pages compose reusable components and use typed modules in `services/api`; Zustand stores authentication state.

## Authentication and tenant isolation

Login verifies a Passlib hash, applies rate limits and account lockout, issues short-lived access and rotating refresh tokens, and records audit activity. API dependencies resolve the active user and tenant from the signed token. Every data query must include the active `tenant_id`; organization switching requires an active membership and issues a new token pair.

## RBAC and permissions

Built-in organization roles are owner, administrator, SOC manager, analyst, and viewer. `core/permissions.py` maps them to granular permission strings. Custom roles store a validated permission list and may be assigned through organization memberships. Backend routes use `require_permission`; frontend hiding is defense in depth only. Owner assignment, custom-role mutation, protected-role deletion, and final-owner removal are separately guarded.

## Deletion PIN design

Tenants store only a Passlib hash, failure count, and lock timestamp. A four-digit Pydantic constraint rejects malformed input. Setting/resetting requires an owner membership and current-password verification. Deletion requires owner access and PIN verification; five failures lock verification for 15 minutes. PIN values are excluded from responses and sanitized from audit metadata.

## Database and migrations

`20260727_1200_security_rbac_audit.py` adds PIN state, custom roles, membership assignment, and audit context. `20260729_1200_phase1_foundation_integrity.py` adds scheduled-deletion timestamps/requester integrity and unique daily usage aggregates. `20260729_1300_authentication_account_security.py` adds hardened account/session state. `20260729_1400_granular_rbac_tenant_isolation.py` adds permission revisions, normalized protected custom roles, scoped API keys, and sensitive-action approvals. These migrations use additive or batch-safe operations for PostgreSQL and SQLite. Back up and verify production data first, confirm `alembic heads` reports one head, then apply with `alembic upgrade head`.

Organization deletion is requested through `DELETE /api/v1/organizations/{id}`, cancelled through `POST /api/v1/organizations/{id}/deletion/cancel`, and inspected through `GET /api/v1/organizations/{id}/deletion/status`. The service uses row locking, makes request/cancel/purge transitions idempotent, and writes the state change and audit record in one transaction. `purge_due_organizations` is an explicitly invokable Celery task; no scheduler is introduced in this phase.

Usage middleware records one atomic counter row per tenant and UTC date. `GET /api/v1/organizations/{id}/usage` returns current counts and refreshes the daily snapshot; `/usage/history` accepts `start_date` and `end_date`, rejects reversed ranges, and limits requests to 366 days. Storage is the estimated length of managed application payloads, not infrastructure capacity.

## Audit logging and exports

`AuditService` is the single append path and sanitizes keys associated with passwords, PINs, tokens, secrets, API keys, and credentials. Records support UTC time, tenant, actor, actor role, action, resource, outcome, IP, user agent, request ID, safe metadata, and failure reason. Audit APIs are tenant-scoped, permission protected, paginated, searchable, filterable, and date sortable. CSV/JSON exports include all filtered rows and create an audit event. The query helper is the extension point for future archived sources or background exports.

## Triage AI

Triage AI retains compatibility with existing internal AI route and class names. Services build tenant-scoped evidence packages, invoke the configured provider, persist safe artifacts, and audit safe request metadata. Never log prompt secrets or full sensitive payloads.

## Collectors, detection, correlation, playbooks, and SOAR

Collectors authenticate with hashed lookup tokens, normalize source events, and send them to ingestion routes. Detection services evaluate tenant rules and Sigma content; correlation groups matches into incidents. Playbook services manage definitions, execution steps, approval gates, and worker tasks. Connector services separate encrypted credentials from display configuration and record executions.

## Commercial IOC operations

Phase 7.6 uses `ioc_commercial_service`, `/api/v1/ioc-commercial`, and bounded Celery
tasks. Migration `20260730_1950` adds threat-source metadata, sync jobs, import and bulk jobs,
review history, response recommendations, notification deduplication, and report jobs. Every
lookup is tenant-scoped.

External calls must use the safe request path: HTTPS only, TLS verification, no embedded
credentials, DNS/private-network rejection, redirect revalidation, optional destination
allowlisting, size bounds, and timeouts. Never serialize encrypted or decrypted credential
fields. Imports and reports use encrypted tenant-scoped artifacts, checksums, expiry, row limits,
and sanitized filenames. Provider adapters and TAXII/MISP parsers must report unsupported content
and use mocked contract tests.

Response execution reuses the sensitive-action approval service, whose fingerprint binds the
action and target and blocks requester self-approval. IOC-to-detection creates only a disabled
draft and cannot bypass detection validation, simulation, approval, or publication.

## Environment and local setup

Copy backend, frontend, and collector `.env.example` files to local untracked environment files. Configure database URL, strong JWT and collector secrets, explicit HTTPS CORS origins, trusted hosts, Redis, SMTP, the HTTPS frontend public URL, and AI provider credentials. Never commit real values. Production startup rejects SQLite, Redis mock, debug mode, enabled API docs, wildcard hosts, non-HTTPS CORS origins, development email capture, insecure cookie policy, placeholder database/OpenAI credentials, and weak secrets. Browser authentication remains bearer-token compatible; see `AUTHENTICATION.md` for the remaining storage trade-off.

## Docker and production

Development and production Compose files are under `docker/`; backend and frontend images have production variants. In production use PostgreSQL, TLS at the proxy, a secrets manager, restricted origins, non-default credentials, database backups, health monitoring, and multiple API/worker replicas where required. Run migrations as a controlled pre-deployment job before application rollout.

## API documentation

FastAPI publishes OpenAPI documentation from route schemas and descriptions. Preserve existing `/api/v1` compatibility; the legacy internal `incident-copilot` route remains supported while user-facing descriptions use **Triage AI**.

## Testing

Run focused Pytest suites for authentication/RBAC, organizations/PIN, audit/export, tenant isolation, incidents, and other changed services. Run frontend TypeScript build/lint and relevant Playwright flows. Tests must use isolated temporary databases and must not rely on real credentials.

## Security and maintenance

Never query tenant data without tenant scope; never trust frontend authorization; use Pydantic validation; sanitize audit metadata; keep logs append-only through APIs; encrypt connector credentials; prevent owner escalation; review dependency advisories; rotate signing keys through a planned session-revocation process. Extend permissions by adding the catalog value, least-privilege built-in mappings, backend enforcement, frontend visibility, migration if needed, and tests.

## Troubleshooting

For migration failures, check the current Alembic head and database dialect before retrying. For 403 responses, inspect active membership and effective permissions. For missing audits, verify the transaction did not roll back before the audit call. For worker failures, check Redis/Celery health and correlation IDs. For frontend API failures, confirm the API base URL, CORS policy, current tenant token, and proxy configuration.
