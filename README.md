# TriageOps

TriageOps is an AI-assisted SOC operations platform for security event ingestion, detection rules, alerts, incidents, IOC enrichment, collectors, playbooks, SOAR response actions, investigation copilot workflows, authentication, and real-time analyst updates.

The current product is a modular monolith intended to evolve into a commercial enterprise SOC platform. The released scope in this repository is the backend API, analyst frontend, collector agent, PostgreSQL/SQLite persistence, Redis-backed operational services, Celery workers, versioned playbooks, SOAR connectors, AI investigation assistance, structured logging, health checks, and Prometheus metrics.

## Repository Layout

- `backend`: FastAPI API, SQLAlchemy models, Alembic migrations, authentication, detection, incident correlation, health checks, metrics, and Celery worker tasks.
- `frontend`: React, TypeScript, Vite, and Material UI analyst console.
- `collector-agent`: Lightweight Python collector that authenticates to the backend and submits heartbeat and event data.
- `docker`: Development and production-style Compose files plus Nginx reverse proxy configuration.

## Local Development

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
alembic upgrade head
uvicorn src.main:app --reload --host 0.0.0.0 --port 8001
```

Local development defaults to SQLite and development-only generated secrets. Production mode requires explicit strong secrets, PostgreSQL, Redis, and non-wildcard trusted hosts.

Useful backend URLs:

- API root: `http://localhost:8001`
- Swagger UI: `http://localhost:8001/docs`
- Readiness: `http://localhost:8001/health/ready`
- Liveness: `http://localhost:8001/health/live`
- Full health: `http://localhost:8001/health`
- Metrics: `http://localhost:8001/metrics`

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

The frontend runs on `http://localhost:3000`. Copy `frontend/.env.example` to `frontend/.env` when a local API URL is needed.

### Collector

1. Register a collector through the API or collector UI.
2. Copy the collector ID and token.
3. Copy `collector-agent/.env.example` to `collector-agent/.env` or set the variables in your shell.
4. Run the collector.

```powershell
cd collector-agent
pip install -r requirements.txt
$env:COLLECTOR_ID="<collector-id>"
$env:COLLECTOR_TOKEN="<collector-token>"
$env:BACKEND_URL="http://localhost:8001"
python main.py
```

Collector requests use bearer authentication and include `X-Request-ID` for log correlation.

## Authentication and Authorization

TriageOps uses JWT access tokens and database-backed refresh tokens. Refresh tokens are hashed at rest, rotated on use, grouped by token family, and revocable through logout or logout-all.

Implemented authentication controls:

- Login with account lockout after repeated failures.
- Access token and refresh token issuance.
- Refresh token rotation.
- Logout and logout-all session revocation.
- Password change with previous-session invalidation.
- Password-change timestamp checks for old access tokens.
- RBAC roles: `admin`, `analyst`, `responder`, and `viewer`.

Event ingestion requires authentication. Browser and API users use JWTs. Collectors use collector bearer tokens. Collector authentication is intentionally separate from user authentication.

## Multi-Tenancy and Organizations

TriageOps supports multiple isolated organizations in one deployment. The existing tenant boundary is exposed as organization management so current APIs remain backward compatible while organization administration is available through dedicated endpoints and frontend pages.

Implemented organization capabilities:

- Organization profile, status, subscription plan, and quota fields.
- Organization membership roles: `owner`, `administrator`, `soc_manager`, `analyst`, and `viewer`.
- One user can belong to multiple organizations.
- Authenticated tenant switching with fresh access and refresh tokens.
- Email invitation lifecycle with hashed invitation tokens, expiration, accept, and reject.
- Quota enforcement for users and collectors.
- Usage views for users, collectors, events, alerts, playbooks, SOAR executions, storage, and API request counters.
- Audit events for organization creation, updates, deletion, tenant switching, invitations, invitation decisions, and membership changes.

Every existing operational resource continues to use `tenant_id` as the enforced organization boundary. Backend dependencies resolve the active organization from the authenticated session or collector token; clients cannot gain access by sending arbitrary tenant IDs.

## Playbooks and SOAR

Playbooks support versioning, publishing, activation, manual execution, approvals, execution logs, variables, and persisted execution steps. Playbook `action` steps can invoke the SOAR connector framework by referencing a connector ID and optional credential ID in step configuration.

SOAR connectors are tenant-scoped and pluggable. Implemented connector types:

- Webhook.
- Slack incoming webhook.
- Microsoft Teams incoming webhook.
- SMTP email.
- Generic REST API.

Connector credentials are encrypted at rest and returned only as metadata/fingerprints. Action execution is persisted with request/response metadata, retry state, duration, worker ID, correlation ID, and request ID. Actions run through Celery workers in Redis-backed environments. Local development with `USE_REDIS_MOCK=true` runs SOAR tasks eagerly through the same service path so developers can work without Docker.

## AI Investigation Copilot

The AI Investigation Copilot helps analysts reason over tenant-scoped investigation evidence. It is not a general-purpose chatbot: every response is grounded in an authorized incident and its linked alerts, source events, detection rules, entities, IOCs, timeline entries, analyst notes, risk factors, and audit history.

Each incident exposes a deterministic explanation at `GET /api/v1/incidents/{incident_id}/explanation`. The response identifies the primary alert, subsequent correlated alerts, source events, matching rules, correlation reasons, observed time window, affected entities, MITRE mappings, risk breakdown, evidence references, limitations, and recommended investigation questions. This explanation works without OpenAI and is the source of truth for the incident detail panel.

After database migrations, synchronize the pinned offline MITRE ATT&CK Enterprise v18.1 reference catalog with `cd backend && python scripts/bootstrap_mitre_catalog.py`. The command is idempotent and makes no network request. See `INCIDENT_INTELLIGENCE.md` for catalog provenance, the correlation lifecycle, full-chain simulation, matrix modes, isolated browser acceptance, and troubleshooting.

Provenance is labelled as recorded, manual, or legacy-derived. Historical incidents are never presented as having correlation facts that were not stored at creation time. Official risk scores remain deterministic and their components, including any 0-100 bounding adjustment, reconcile to the displayed total.

Implemented AI capabilities:

- Incident summaries with executive summary, technical summary, root cause, impact, recommended next steps, containment suggestions, MITRE ATT&CK suggestions, and confidence score.
- Alert explanations that describe why a detection triggered, which fields matched, why the activity is suspicious, false-positive considerations, and recommended analyst actions.
- IOC analysis using existing enrichment data before LLM prompting.
- Chronological investigation timelines from events, alerts, incidents, comments, playbooks, and SOAR actions.
- Incident-scoped Copilot conversations with persisted conversation history.
- Evidence citations, confidence, limitations, provider/model metadata, and suggested follow-up questions on Copilot answers.
- Markdown incident reports suitable for PDF rendering/export.
- Detection-rule suggestions based on recent tenant incidents.
- Playbook suggestions based on incident or recent tenant activity.

AI API endpoints:

- `POST /api/v1/ai/incident/{incident_id}/summary`
- `POST /api/v1/ai/incident/{incident_id}/chat`
- `GET /api/v1/ai/incident/{incident_id}/conversations`
- `GET /api/v1/ai/incident/{incident_id}/conversations/{conversation_id}`
- `POST /api/v1/ai/incident/{incident_id}/timeline`
- `POST /api/v1/ai/incident/{incident_id}/report`
- `POST /api/v1/ai/alert/{alert_id}/explain`
- `POST /api/v1/ai/ioc/{ioc_id}/analyze`
- `POST /api/v1/ai/detections/suggest`
- `POST /api/v1/ai/playbooks/suggest`

All AI endpoints require authentication, enforce RBAC, resolve tenant scope from the authenticated session, and create audit events. Conversation history is scoped to the tenant, incident, and current user. Prompt construction redacts sensitive fields and inline credential assignments such as passwords, API keys, tokens, refresh tokens, JWTs, connector credentials, and private keys. Prompt size is bounded, known prompt-injection phrases in evidence are filtered, and Copilot chat has a per-conversation rate limit. Context selection deterministically prioritizes incident origin, the primary alert, correlation and risk factors, high-value evidence, entities, IOCs, timeline boundaries, notes, MITRE mappings, and recent conversation turns. Safe response metadata reports inclusion, omission, and context-size totals without exposing prompts.

Generated artifacts and conversation messages are stored in the database for auditability and later review. If `OPENAI_API_KEY` is unavailable, the service returns deterministic evidence-based fallback analysis so workflows remain usable in local development and tests. Copilot calls use the OpenAI Responses API with Structured Outputs, `store=false`, and no tools.

Copilot chat requests accept a client request ID for retry safety. Idempotency is scoped to the authenticated tenant, user, incident, conversation, and normalized question. A request already in progress returns a conflict response; an authorized retry after completion replays the stored result without another provider call or duplicate conversation messages. Redis provides the distributed in-flight lock when available, with a bounded process-local lock for degraded local operation. A request ID cannot be reused for a different question, user, tenant, or incident.

See `INCIDENT_INTELLIGENCE.md` for the provenance model, API response structure, Copilot boundaries, and a verification workflow.

Analysts participating in a controlled evaluation should also follow `PILOT_CHECKLIST.md` for evidence verification, AI claim reporting, and sensitive-data handling.

## Observability

Backend logs are structured JSON and include request correlation fields when available:

- `request_id`
- `tenant_id`
- `user_id`
- `collector_id`
- `endpoint`
- `execution_time_ms`
- `severity`
- `service`

The API accepts inbound `X-Request-ID` and returns it on responses. The collector also sends request IDs with heartbeat and event submissions.

Prometheus metrics are exposed at `/metrics` when `METRICS_ENABLED=true`. Current metrics include API latency and status codes, authentication outcomes, collector heartbeats, collector event ingestion, detection execution, alert creation, incident creation, WebSocket connections/events, Redis status, database health latency, queue health latency, worker execution time, connector execution totals, connector failures, retries, timeouts, execution duration, and approval latency.

WebSocket connections support lightweight heartbeat messages so clients and proxies can detect stale connections without polling the REST API. Configure the heartbeat interval with `WEBSOCKET_HEARTBEAT_SECONDS`.

## Health Checks

Health endpoints return structured JSON and keep backward-compatible top-level fields for existing frontend consumers.

- `/health/live`: process liveness.
- `/health/ready`: readiness checks for required dependencies.
- `/health`: full health report including degraded optional providers.

Checks include database, Redis, worker broker reachability, AI provider configuration, threat intelligence provider configuration, storage, and migration status.

## Environment Variables

Common backend variables:

- `ENVIRONMENT`: `development` or `production`.
- `USE_SQLITE`: `true` for local SQLite, `false` for PostgreSQL.
- `DATABASE_URL_OVERRIDE`: optional full database URL.
- `POSTGRES_SERVER`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`.
- `REDIS_HOST`, `REDIS_PORT`, `USE_REDIS_MOCK`.
- `SECRET_KEY`, `JWT_SECRET_KEY`, `REFRESH_TOKEN_SECRET`, `COLLECTOR_TOKEN_SECRET`.
- `ALLOWED_HOSTS`: JSON list of accepted hosts.
- `BACKEND_CORS_ORIGINS`: JSON list of allowed frontend origins.
- `RATE_LIMIT_DEFAULT`, `RATE_LIMIT_LOGIN`, `RATE_LIMIT_INGEST`, `RATE_LIMIT_STORAGE_URL`.
- `METRICS_ENABLED`, `METRICS_PATH`.
- `WEBSOCKET_HEARTBEAT_SECONDS`.
- `SOAR_TASK_ALWAYS_EAGER`: execute SOAR Celery tasks inline for local/test workflows.
- `OPENAI_API_KEY`, `OPENAI_MODEL`, `OPENAI_TIMEOUT_SECONDS`, `OPENAI_MAX_OUTPUT_TOKENS`, `OPENAI_REASONING_EFFORT`.
- `AI_CONTEXT_MAX_BYTES`: maximum serialized Copilot evidence context (default `65536`).
- `AI_CONTEXT_ALERT_LIMIT`, `AI_CONTEXT_EVENT_LIMIT`, `AI_CONTEXT_ENTITY_LIMIT`, `AI_CONTEXT_IOC_LIMIT`, `AI_CONTEXT_EVIDENCE_LIMIT`.
- `AI_CONTEXT_NOTE_LIMIT`, `AI_CONTEXT_AUDIT_LIMIT`, `AI_CONVERSATION_HISTORY_LIMIT`.
- `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`.
- `ADMIN_EMAIL`, `ADMIN_PASSWORD` for optional bootstrap admin creation.

Use `backend/.env.example`, `frontend/.env.example`, and `collector-agent/.env.example` as starting points.

## Docker Development Stack

```powershell
docker compose -f docker/docker-compose.yml up --build
```

Default development services:

- Frontend: `http://localhost:3000`
- Backend: `http://localhost:8001`
- Metrics through Nginx: `http://localhost/metrics`
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`
- pgAdmin: `http://localhost:5050`

The development stack uses bind mounts for fast iteration.

If port 3000 serves stale frontend source after dependency or mount changes, recreate only the frontend container and its anonymous dependency volume. This preserves PostgreSQL and Redis data volumes:

```powershell
docker compose -f docker/docker-compose.yml up -d --no-deps --build --force-recreate --renew-anon-volumes frontend
```

## Production-Style Docker Stack

The production Compose file uses multi-stage backend/frontend builds, static frontend serving through Nginx, non-root runtime users, PostgreSQL, Redis, backend, frontend, worker, health checks, and required production secrets.

```powershell
$env:POSTGRES_USER="triageops"
$env:POSTGRES_PASSWORD="<strong-password>"
$env:POSTGRES_DB="triageops"
$env:SECRET_KEY="<strong-secret>"
$env:JWT_SECRET_KEY="<strong-secret>"
$env:REFRESH_TOKEN_SECRET="<strong-secret>"
$env:COLLECTOR_TOKEN_SECRET="<strong-secret>"
$env:ALLOWED_HOSTS='["localhost","127.0.0.1","triageops.example.com"]'
$env:BACKEND_CORS_ORIGINS='["https://triageops.example.com"]'
$env:PUBLIC_PORT="8080"
docker compose -f docker/docker-compose.prod.yml up --build
```

## API Error Format

API errors use a standard envelope:

```json
{
  "timestamp": "2026-07-03T00:00:00Z",
  "request_id": "request-id",
  "status": 401,
  "error_code": "unauthorized",
  "message": "Not authenticated",
  "detail": "Not authenticated",
  "details": {},
  "documentation_url": "https://docs.triageops.local/api/errors"
}
```

The `detail` field is retained for backward compatibility with existing FastAPI clients.

## Testing

Backend regression tests:

```powershell
python -m pip install -r backend/requirements-test.txt
python -m pytest -q
cd backend
python -m pytest -q tests
```

The repository-level pytest configuration intentionally discovers `backend/tests/test_*.py`. Manual HTTP utilities are not test modules. Collector tests run separately from `collector-agent`.

```powershell
cd collector-agent
python -m pytest -q
```

Incident browser regression tests require a running backend/frontend and test credentials:

```powershell
cd frontend
$env:E2E_BASE_URL="http://localhost:3000"
$env:E2E_EMAIL="<test-user-email>"
$env:E2E_PASSWORD="<test-user-password>"
npm run test:e2e
```

Run the isolated 100-incident performance and concurrent-load validation with SQLite:

```powershell
cd backend
python scripts/incident_performance_validation.py --concurrency 8 --requests 80 --output validation.json
```

For PostgreSQL, pass an isolated validation database URL. The database name must clearly identify it as a test/validation database; the harness creates and drops a unique schema and does not print credentials:

```powershell
cd backend
$env:TEST_POSTGRES_DATABASE_URL="postgresql+psycopg://<user>:<password>@localhost:5432/triageops_batch63_validation"
python scripts/incident_performance_validation.py --database-url $env:TEST_POSTGRES_DATABASE_URL --concurrency 8 --requests 80 --output validation-postgres-c8.json
```

Frontend production build:

```powershell
cd frontend
npm run build
```

SQLite migration verification:

```powershell
cd backend
$env:USE_SQLITE="true"
$env:DATABASE_URL_OVERRIDE="sqlite:///./migration-test.db"
alembic upgrade head
```

PostgreSQL migrations can be verified with `TEST_POSTGRES_DATABASE_URL` or through the Docker stacks.

## Enterprise Foundation Notes

The current schema includes tenant-aware indexes for the primary SOC workloads: security events, alerts, incidents, collectors, IOCs, audit logs, notifications, detection matches, refresh tokens, and response-action records. List and dashboard queries use bounded pagination or aggregate database queries where implemented.
