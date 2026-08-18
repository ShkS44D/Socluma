# TriageOps Windows Run Guide

## Requirements

- Windows 10/11 with PowerShell 7 recommended.
- Docker Desktop with Docker Compose v2 for the complete stack.
- For local execution without Docker: Python 3.12 and Node.js 22 or newer.
- Administrator or delegated Event Log Reader access for live Windows Security log collection.

Run all Docker commands from the repository root:

```powershell
Set-Location "D:\AI SOC Assistent (NL)"
if (!(Test-Path backend\.env)) { Copy-Item backend\.env.example backend\.env }
if (!(Test-Path frontend\.env)) { Copy-Item frontend\.env.example frontend\.env }
```

Review `backend\.env` before startup. Replace placeholder secrets for any shared or production-like environment. Do not commit `.env` files.

## Complete Docker workflow

Build and start PostgreSQL, Redis, backend, worker, frontend, and the optional pgAdmin service:

```powershell
docker compose -f docker\docker-compose.yml build
docker compose -f docker\docker-compose.yml up -d
docker compose -f docker\docker-compose.yml ps
```

The backend container also migrates on startup. Run the explicit migration check:

```powershell
docker compose -f docker\docker-compose.yml exec -T backend alembic upgrade head
docker compose -f docker\docker-compose.yml exec -T backend alembic heads
docker compose -f docker\docker-compose.yml exec -T backend alembic current
```

Generate temporary synthetic-demo passwords in the current PowerShell session, then seed. These commands work in Windows PowerShell 5.1 and PowerShell 7:

```powershell
$env:TEST_DEMO_OWNER_PASSWORD = "$([guid]::NewGuid().ToString('N'))Aa1!"
$env:TEST_DEMO_ANALYST_PASSWORD = "$([guid]::NewGuid().ToString('N'))Aa1!"
docker compose -f docker\docker-compose.yml exec -T `
  -e TEST_DEMO_OWNER_PASSWORD=$env:TEST_DEMO_OWNER_PASSWORD `
  -e TEST_DEMO_ANALYST_PASSWORD=$env:TEST_DEMO_ANALYST_PASSWORD `
  backend python scripts/seed_test_demo.py --confirm-test-demo-seed
```

The default synthetic login identities are `demo.owner@example.com` and `demo.analyst@example.com`. Their passwords remain in the current PowerShell process as `$env:TEST_DEMO_OWNER_PASSWORD` and `$env:TEST_DEMO_ANALYST_PASSWORD`; no password is embedded in the repository. Re-seeding updates the password for an account owned exclusively by the reserved demo tenant. If either identity belongs to another organization, the seed preserves that account's existing password and only grants the explicit demo membership; use fresh values through `TEST_DEMO_OWNER_EMAIL` and `TEST_DEMO_ANALYST_EMAIL` for an isolated smoke test.

Open:

- Frontend: `http://localhost:3000`
- Backend API: `http://localhost:8001`
- API documentation: `http://localhost:8001/docs`
- Readiness: `http://localhost:8001/health/ready`

Run the end-to-end API smoke test:

```powershell
docker compose -f docker\docker-compose.yml exec -T `
  -e TEST_DEMO_OWNER_PASSWORD=$env:TEST_DEMO_OWNER_PASSWORD `
  -e TEST_DEMO_ANALYST_PASSWORD=$env:TEST_DEMO_ANALYST_PASSWORD `
  backend python scripts/test_demo_smoke_test.py --base-url http://127.0.0.1:8000
```

Reset only the reserved `TriageOps Demo` tenant and recreate its deterministic data:

```powershell
docker compose -f docker\docker-compose.yml exec -T `
  -e TEST_DEMO_OWNER_PASSWORD=$env:TEST_DEMO_OWNER_PASSWORD `
  -e TEST_DEMO_ANALYST_PASSWORD=$env:TEST_DEMO_ANALYST_PASSWORD `
  backend python scripts/reset_test_demo.py --confirm-test-demo-reset
```

Inspect logs and health:

```powershell
docker compose -f docker\docker-compose.yml logs --tail 200 backend worker frontend db redis
Invoke-RestMethod http://localhost:8001/health/ready | ConvertTo-Json -Depth 5
```

Stop the stack without deleting PostgreSQL or Redis volumes:

```powershell
docker compose -f docker\docker-compose.yml down
Remove-Item Env:TEST_DEMO_OWNER_PASSWORD -ErrorAction SilentlyContinue
Remove-Item Env:TEST_DEMO_ANALYST_PASSWORD -ErrorAction SilentlyContinue
```

## Windows collector

Create a collector in TriageOps and store the returned one-time token in an approved local secret store. In a new PowerShell window:

```powershell
Set-Location "D:\AI SOC Assistent (NL)\collector-agent"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:COLLECTOR_ID="<collector-id>"
$env:COLLECTOR_TOKEN="<one-time-collector-token>"
$env:BACKEND_URL="http://localhost:8001"
python main.py
```

Use an HTTPS backend URL outside local development. The account running the collector must be allowed to read the configured Windows event channels.

## Release checks

```powershell
Set-Location "D:\AI SOC Assistent (NL)"
python -m pip install -r backend\requirements-test.txt
$env:PYTHONPATH="D:\AI SOC Assistent (NL)\backend"
$env:PYTHONPYCACHEPREFIX="D:\AI SOC Assistent (NL)\tmp\release-pycache"
New-Item -ItemType Directory -Force "D:\AI SOC Assistent (NL)\tmp\release-test-cwd" | Out-Null
Push-Location "D:\AI SOC Assistent (NL)\tmp\release-test-cwd"
python -m pytest "D:\AI SOC Assistent (NL)\backend\tests" -q --rootdir="D:\AI SOC Assistent (NL)"
Pop-Location

Set-Location "D:\AI SOC Assistent (NL)\collector-agent"
$env:PYTHONPATH="D:\AI SOC Assistent (NL)\backend;D:\AI SOC Assistent (NL)\collector-agent"
python -m pytest -q test_batch_signing.py test_event_identity.py test_spool_state.py test_windows_collector.py

Set-Location "D:\AI SOC Assistent (NL)\frontend"
npm ci
npm run lint
npm run build
```

## Run without Docker

Backend and frontend local development are supported. Use separate PowerShell windows.

Backend with SQLite:

```powershell
Set-Location "D:\AI SOC Assistent (NL)\backend"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
if (!(Test-Path .env)) { Copy-Item .env.example .env }
$env:USE_SQLITE="true"
$env:USE_REDIS_MOCK="true"
python -m alembic upgrade head
python -m uvicorn src.main:app --reload --host 127.0.0.1 --port 8001
```

Frontend:

```powershell
Set-Location "D:\AI SOC Assistent (NL)\frontend"
npm ci
$env:VITE_API_BASE_URL="http://localhost:8001"
npm run dev
```

## Troubleshooting

- If a service is unhealthy, run `docker compose -f docker\docker-compose.yml ps` and inspect its last 200 log lines.
- If readiness reports a migration mismatch, rerun `alembic upgrade head` in the backend container and confirm one head/current revision.
- If port 3000 shows stale source after a dependency update, run `docker compose -f docker\docker-compose.yml up -d --no-deps --build --force-recreate --renew-anon-volumes frontend`.
- If login fails after reseeding an identity that also belongs to another organization, use that account's existing password or choose fresh synthetic demo email addresses.
- If the collector cannot read the Security log, run its PowerShell session with the required Event Log Reader permissions and confirm the relevant Windows audit subcategories are enabled.
- External TAXII, MISP, threat-source, SOAR, and hosted AI calls require customer credentials. Without them, use the built-in deterministic offline demo/fallback and the mocked automated tests; the UI must show configuration-required rather than success.
