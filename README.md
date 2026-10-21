# Socluma — AI-Assisted Security Operations

Current release: **v1.1.0**.

Socluma brings telemetry collection, threat detection, incident investigation, and response workflows into one security operations workspace. Analysts can follow an alert back to its source events, investigate related activity, and use AI assistance grounded in the incident evidence.

The repository contains a FastAPI backend, a React analyst console, a Python collector agent, database migrations, background workers, and Docker configurations for development and production-style deployments.

Use synthetic or approved lab data for evaluation. An operational deployment requires environment-specific security configuration, backups, monitoring, and validation of the integrations you enable.

## Core capabilities

- Security-event ingestion from authenticated collectors and API clients
- Sigma-style detection rules, testing, simulation, versioning, and approval workflows
- Alert triage, incident correlation, evidence timelines, and MITRE ATT&CK mapping
- IOC enrichment, sightings, watchlists, hunting, imports, exports, and provider integrations
- Tenant-isolated organizations, memberships, granular permissions, quotas, and audit trails
- Investigation workspaces, saved searches, relationship graphs, reports, and evidence snapshots
- Playbooks and SOAR actions through webhook, Slack, Microsoft Teams, SMTP, and REST connectors
- AI-assisted incident summaries, alert explanations, timelines, reports, and analyst conversations
- PostgreSQL or SQLite persistence, Redis-backed services, Celery workers, health checks, and Prometheus metrics
- Windows and Linux collector support with local spooling, signed batches, and checkpoint recovery

AI features are evidence-scoped and audited. When `OPENAI_API_KEY` is not configured, local development and tests can use deterministic fallback behavior.

## Architecture

| Component | Technology | Purpose |
| --- | --- | --- |
| `backend` | Python, FastAPI, SQLAlchemy, Alembic | API, authentication, detection, investigations, IOC workflows, SOAR, and persistence |
| `frontend` | React, TypeScript, Vite, Material UI | Browser-based SOC analyst console |
| `collector-agent` | Python | Windows/Linux event collection, batching, retry, and heartbeat delivery |
| `docker` | Docker Compose, Nginx | Development and production-style service orchestration |
| `docs` | Markdown | Operational, security, architecture, and feature documentation |

The complete Docker stack consists of the frontend, backend API, Celery worker, scheduler, PostgreSQL, Redis, and optional pgAdmin. The production-style stack adds Nginx as the public reverse proxy.

## Requirements

Choose either Docker or a local development setup.

### Docker setup

- Docker Desktop or Docker Engine
- Docker Compose v2
- Git

### Local setup

- Python 3.12 (Python 3.11 is also used by the production backend image)
- Node.js 22 or newer
- npm 11 or newer
- Git
- PostgreSQL and Redis only when not using the default SQLite and in-process Redis substitutes

## Quick start with Docker

Docker is the easiest way to run the complete application.

1. Clone the repository and enter its directory:

   ```powershell
   git clone https://github.com/ShkS44D/Socluma.git
   Set-Location Socluma
   ```

2. Create local environment files:

   ```powershell
   Copy-Item backend\.env.example backend\.env
   Copy-Item frontend\.env.example frontend\.env
   ```

3. Review `backend/.env`. Local placeholder values are suitable only for development. Never commit `.env` files.

4. Build and start the stack:

   ```powershell
   docker compose -f docker\docker-compose.yml up --build -d
   ```

5. Check service status:

   ```powershell
   docker compose -f docker\docker-compose.yml ps
   Invoke-RestMethod http://localhost:8001/health/ready
   ```

6. Open the application:

   - Analyst console: `http://localhost:3000`
   - Backend API: `http://localhost:8001`
   - API documentation: `http://localhost:8001/docs`
   - Prometheus metrics: `http://localhost:8001/metrics`
   - pgAdmin: `http://localhost:5050`

The backend container applies Alembic migrations when it starts. To create an initial administrator automatically, set `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `backend/.env` before the first startup. You can also register a user through the application.

Stop the stack without deleting database volumes:

```powershell
docker compose -f docker\docker-compose.yml down
```

To remove the Docker-managed PostgreSQL and Redis data as well, use `down -v` only when permanent deletion is intended.

## Run locally without Docker

Use separate terminals for the backend and frontend.

### 1. Backend

From the repository root:

```powershell
Set-Location backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env -ErrorAction SilentlyContinue
$env:USE_SQLITE="true"
$env:USE_REDIS_MOCK="true"
python -m alembic upgrade head
python -m uvicorn src.main:app --reload --host 127.0.0.1 --port 8001
```

If PowerShell blocks virtual-environment activation, run the following once for the current terminal and activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

The default local database is `backend/socluma.db`. It is runtime data and is excluded from Git.

### 2. Frontend

In another terminal, from the repository root:

```powershell
Set-Location frontend
npm ci
Copy-Item .env.example .env -ErrorAction SilentlyContinue
$env:VITE_API_BASE_URL="http://localhost:8001"
npm run dev
```

Open `http://localhost:3000`.

### 3. Optional background worker

Local development defaults to eager or in-process behavior where supported. To exercise the real asynchronous queue, run Redis and start a worker from the activated backend environment:

```powershell
celery -A src.workers.celery_app.celery_app worker --loglevel=INFO
```

Set `USE_REDIS_MOCK=false` and configure `REDIS_HOST` and `REDIS_PORT` first.

For periodic searches, threat-intelligence synchronization, and artifact retention, also run exactly one scheduler using the same environment:

```powershell
celery -A src.workers.celery_app.celery_app beat --loglevel=INFO
```

## Collector agent

Create a collector in Socluma and securely retain the returned collector ID and one-time token. Then run:

```powershell
Set-Location collector-agent
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env -ErrorAction SilentlyContinue
$env:COLLECTOR_ID="<collector-id>"
$env:COLLECTOR_TOKEN="<collector-token>"
$env:BACKEND_URL="http://localhost:8001"
python main.py
```

Use an HTTPS backend URL outside local development. The account running the Windows collector must have permission to read the configured event-log channels. Installation helpers are available under `collector-agent/install`.

## Configuration

Copy the supplied examples and keep real credentials only in untracked `.env` files or an approved secrets manager:

- `backend/.env.example`: application, database, Redis, security, AI, email, telemetry, detection, search, audit, and IOC settings
- `frontend/.env.example`: browser API base URL
- `collector-agent/.env.example`: collector identity, backend URL, batching, spooling, channels, and logging

Important backend settings include:

| Setting | Purpose |
| --- | --- |
| `ENVIRONMENT` | Selects development or production validation rules |
| `USE_SQLITE` | Uses SQLite locally when `true`; use PostgreSQL for production |
| `DATABASE_URL_OVERRIDE` | Optional complete database connection URL |
| `USE_REDIS_MOCK` | Allows local operation without Redis when `true` |
| `SECRET_KEY`, `JWT_SECRET_KEY`, `REFRESH_TOKEN_SECRET` | Application and session signing secrets |
| `COLLECTOR_TOKEN_SECRET` | Collector credential signing secret |
| `BACKEND_CORS_ORIGINS`, `ALLOWED_HOSTS` | Trusted browser origins and HTTP hosts |
| `OPENAI_API_KEY`, `OPENAI_MODEL` | Optional hosted AI provider configuration for local use |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY` | Optional threat-intelligence providers |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | Optional initial administrator bootstrap |

Production mode rejects weak or missing security configuration. Do not reuse the development defaults.

## Database migrations

Run migrations from `backend`:

```powershell
python -m alembic heads
python -m alembic upgrade head
python -m alembic current
```

There should be exactly one Alembic head. Back up and verify production data before every migration.

After migrations, load the pinned offline MITRE ATT&CK Enterprise catalog when required:

```powershell
python scripts/bootstrap_mitre_catalog.py
```

The catalog bootstrap is idempotent and does not require network access.

## Testing and validation

### Backend test suite

From the repository root:

```powershell
python -m pip install -r backend\requirements-test.txt
$env:PYTHONPATH="$PWD\backend"
python -m pytest backend\tests -q
```

### Collector tests

```powershell
Set-Location collector-agent
$env:PYTHONPATH="..\backend;."
python -m pytest -q
```

### Frontend checks

```powershell
Set-Location frontend
npm ci
npm run test:unit
npm run lint
npm run build
```

Browser tests require a running frontend and backend plus a dedicated test account:

```powershell
Set-Location frontend
$env:E2E_BASE_URL="http://localhost:3000"
$env:E2E_EMAIL="<test-user-email>"
$env:E2E_PASSWORD="<test-user-password>"
npm run test:e2e
```

Do not use production accounts or production data for automated tests.

## Production-style Docker deployment

The production Compose configuration uses PostgreSQL, Redis, a background worker, a single scheduler, non-root application containers, health checks, a statically built frontend, and Nginx. API and worker artifacts are persisted in the shared `application_data` volume, mounted at `/var/lib/socluma`. Include this volume in backups alongside PostgreSQL and retain the encryption/signing secrets needed to read its contents. Do not scale the scheduler beyond one instance.

When moving an existing installation to shared storage, stop the API, worker, and scheduler first. Back up artifact directories from every API/worker container and any local `backend/data` directory before replacing containers. Restore `ioc-artifacts`, `audit-exports`, and `audit-archives` into the corresponding shared-volume directories with ownership `10001:10001`, retaining the original encryption/signing secrets. Keep the backups until existing downloads have been verified.

Set strong, unique values in the deployment environment:

```powershell
$env:POSTGRES_USER="socluma"
$env:POSTGRES_PASSWORD="<strong-database-password>"
$env:POSTGRES_DB="socluma"
$env:SECRET_KEY="<strong-random-secret>"
$env:JWT_SECRET_KEY="<strong-random-secret>"
$env:REFRESH_TOKEN_SECRET="<strong-random-secret>"
$env:COLLECTOR_TOKEN_SECRET="<strong-random-secret>"
$env:ALLOWED_HOSTS='["soc.example.com"]'
$env:BACKEND_CORS_ORIGINS='["https://soc.example.com"]'
$env:FRONTEND_PUBLIC_URL="https://soc.example.com"
$env:ADMIN_EMAIL="<administrator-email>"
$env:ADMIN_PASSWORD="<strong-administrator-passphrase>"
$env:OPENAI_API_KEY="<provider-key>"
$env:PUBLIC_PORT="8080"
docker compose -f docker\docker-compose.prod.yml up --build -d
```

Terminate HTTPS at a trusted reverse proxy or load balancer in front of port 8080 and open the configured `FRONTEND_PUBLIC_URL`. Production uses secure authentication cookies and explicit HTTPS origins; plain HTTP is not a supported production login setup. Restrict network exposure, use a managed secrets solution, configure SMTP for account emails, configure backups, and monitor `/health/ready` and `/metrics`. API documentation and development email/token capture are disabled in production.

Real response execution requires a configured SOAR connector. The deprecated incident-action creation endpoint returns `501` instead of claiming that an unsupported action completed. Collector agents forward real host events only; missing permissions or empty polls do not produce simulated telemetry.

## Health and observability

- `/health/live`: process liveness
- `/health/ready`: required dependency and migration readiness
- `/health`: detailed health report, including optional providers
- `/metrics`: Prometheus metrics when `METRICS_ENABLED=true`

Backend logs use structured JSON and include correlation fields such as request, tenant, user, collector, endpoint, duration, and severity identifiers.

## Documentation

- [Architecture](ARCHITECTURE.md)
- [Windows and Docker run guide](docs/RUN_GUIDE.md)
- [Authentication](docs/AUTHENTICATION.md)
- [Authorization model](docs/AUTHORIZATION.md)
- [Audit and data protection](docs/AUDIT_DATA_PROTECTION.md)
- [Telemetry ingestion](docs/TELEMETRY_INGESTION.md)
- [Search and investigations](docs/SEARCH_INVESTIGATIONS.md)
- [Detection engineering](docs/DETECTION_ENGINEERING.md)
- [IOC intelligence](docs/IOC_INTELLIGENCE.md)
- [Incident intelligence](INCIDENT_INTELLIGENCE.md)
- [Detection troubleshooting](DETECTION_RULE_TROUBLESHOOTING.md)
- [Collector guide](collector-agent/README.md)
- [Pilot guide](PILOT_GUIDE.md)

## Security notes

- Never commit `.env` files, API keys, passwords, database files, collected events, logs, exports, or certificates.
- Rotate any credential immediately if it is accidentally exposed.
- Use HTTPS for browser, API, webhook, and collector traffic outside localhost.
- Keep development defaults and synthetic demonstration data out of production.
- Restrict connector destinations and credentials according to least privilege.
- Treat AI output as analyst assistance, not verified evidence or an autonomous response decision.

## License

No license file is currently included.
