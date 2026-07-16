# Batch 6.3 Release-Candidate Validation

Validation date: 2026-07-16 (Asia/Karachi)

## Scope

This record covers Incident Intelligence release-candidate validation only. It does not represent enterprise-scale load testing and does not add product functionality.

## Environment

- Host: AMD Ryzen 7 5700U, 8 cores / 16 logical processors, 15.33 GiB RAM.
- Docker Desktop: 29.6.1, allocated 16 CPUs and approximately 7.42 GiB RAM.
- PostgreSQL: 16.14 in Docker.
- Validation database: dedicated `triageops_batch63_validation` database, with a unique temporary schema per run. Every schema was dropped after its run.
- Dataset per run: 100 incidents across 2 tenants and 4 users; 120 alerts; 120 events; one incident with 100 related events and 100 related alerts; another with 20 related alerts/events; 50 entities/evidence records; 10 Copilot conversations with 100 seeded messages; and 10 IOCs.
- Provenance represented: manual, legacy-derived, Playbook-created, detection-created, and correlated incidents.

## PostgreSQL Concurrency Results

Each level executed 80 logical operations and 96 measured HTTP requests.

| Clients | Success | Failure | Error rate | Duration | Median | P95 | P99 | Max | Requests/s | Pool max active |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 96 | 0 | 0% | 20.39 s | 156.87 ms | 493.40 ms | 522.97 ms | 543.10 ms | 4.71 | 1 |
| 4 | 96 | 0 | 0% | 12.86 s | 457.93 ms | 1012.25 ms | 1248.39 ms | 1568.59 ms | 7.46 | 4 |
| 8 | 96 | 0 | 0% | 13.29 s | 911.65 ms | 2027.06 ms | 2241.93 ms | 2449.75 ms | 7.22 | 8 |
| 16 | 96 | 0 | 0% | 12.81 s | 1788.98 ms | 3860.62 ms | 4661.70 ms | 4718.13 ms | 7.50 | 14 |

All levels completed with zero database errors, deadlocks, transaction failures, duplicate messages, duplicate provider attempts, or tenant-isolation failures. Pool checkout/check-in counts were 230/230 at every level and active connections returned to zero. No membership races, partial conversation records, risk-score changes, or relationship corruption were observed.

Process RSS was not available because `psutil` was not installed. Python allocation measurements over 20 repeated explanation requests remained stable: 377.31-383.86 KiB net allocation and 1411.72-1418.00 KiB peak traced allocation.

The increasing tail latency at 8 and 16 clients is a local-capacity signal. These measurements validate correctness under controlled concurrency, not production sizing or enterprise throughput.

## Copilot Idempotency

Redis-backed and Redis-unavailable local fallback paths were tested at 2, 4, 8, and 16 concurrent callers. In every case:

- exactly one provider/fallback execution occurred;
- exactly one user message and one assistant message were persisted;
- in-flight duplicates returned conflict and completed retries replayed the same stored result;
- reusing the request ID with another question returned a validation error;
- another user, tenant, or incident could not retrieve the result;
- a controlled provider interruption returned a safe error, released the lock, and allowed a successful retry;
- no stale local lock or partial conversation pair remained.

## Gemini Status

One controlled live Gemini request was made. Gemini returned HTTP 429 `RESOURCE_EXHAUSTED`, categorized as `quota_exhausted`, because the configured account had no available prepaid credits. No automatic retry was attempted.

Live Gemini grounding evaluation is blocked, not passed. The deterministic Copilot path remains verified: the endpoint returns HTTP 200, marks `fallback_used=true`, identifies the deterministic provider, and includes non-empty references to real tenant-scoped evidence.

## Browser And Docker

- Cold frontend-only recreation completed without touching PostgreSQL or Redis data volumes.
- Host and container hashes matched for Incident Detail, Incident Copilot, and Vite configuration.
- Port 3000 served the current source, including conversation restoration, server-authoritative evidence navigation, and the pending-request guard.
- Full Playwright result: 16 passed, 0 failed, 0 skipped.
- Development backend, PostgreSQL, Redis, and frontend containers were healthy; the Celery worker responded to inspection ping.
- Production Compose configuration validation passed. A separate production runtime was not started.

Safe frontend recovery command:

```powershell
docker compose -f docker/docker-compose.yml up -d --no-deps --build --force-recreate --renew-anon-volumes frontend
```

## Regression Summary

- Root pytest: 73 passed, 2 skipped.
- Backend pytest: 73 passed, 2 skipped.
- Focused Playbook/SOAR: 12 passed.
- Collector: 3 passed.
- Playwright: 16 passed.
- Backend and collector compilation: passed.
- Frontend ESLint, TypeScript, and production build: passed.
- SQLite clean and existing-database migrations: passed.
- PostgreSQL clean and existing-database migrations: passed.
- Live authenticated API verification: login, refresh rotation, collector registration, heartbeat, ingestion, detection matching, alert creation, incident creation, WebSocket ping/pong, metrics, health, readiness, OpenAPI, and local Swagger assets passed.

The two backend skips were the opt-in live localhost ingestion test and the environment-gated PostgreSQL test when `TEST_POSTGRES_DATABASE_URL` was not supplied to pytest. PostgreSQL migrations and concurrency were run separately against the dedicated validation database.

## Release-Candidate Limitations

- Live Gemini answer quality and claim-grounding remain unverified until provider quota is restored.
- Sixteen-client latency on this local Docker allocation is too high to infer production capacity; production sizing requires a representative environment and workload.
- The existing collector `.env` token belongs to a different local database state than the Docker PostgreSQL state. Docker verification used a newly registered temporary collector and removed it afterward.
- Git status and diff verification were unavailable because this workspace does not contain usable Git repository metadata. File-level hygiene was performed against the known Batch 6.3 inventory.
