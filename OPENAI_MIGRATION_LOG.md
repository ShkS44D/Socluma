# OpenAI Provider Migration Working Log

## Initial migration plan

1. Preserve Git and secret safety, then inventory every active and historical Gemini reference.
2. Replace configuration, dependencies, provider calls, error mapping, health metadata, tests, UI labels, and documentation with OpenAI Responses API equivalents while preserving the current Triage AI contract and deterministic fallback.
3. Verify schema compatibility for new `openai` records and historical `gemini` records; add a migration only if the database constrains provider values.
4. Run automated backend, collector, frontend, migration, browser, and container checks before any live request.
5. Recreate backend and worker, perform at most one controlled OpenAI availability request, and continue grounding evaluation only if that request succeeds.
6. Re-audit secrets and provider references, review the full diff, and record exact verification results without committing, merging, or pushing.

## Initial safety state

- Branch: `openai-migration`
- Working tree at start: modified `backend/.env.example` (pre-existing change)
- `backend/.env`: ignored by `.gitignore`
- Tracked secret-pattern scan: no matching tracked files
- Automatic commit/merge/push: disabled for this migration

## Final implementation state

- Active provider: OpenAI Responses API through the official `openai==2.45.0` SDK.
- Triage AI output: Pydantic Structured Output with server-side evidence validation and backend-generated navigation metadata.
- Request controls: configured model, medium reasoning, 2,000 output-token cap, 60-second timeout, `store=False`, no tools, and SDK retries disabled.
- Fallback: `triageops-deterministic-v1` preserved for missing configuration and all classified provider/structured-output/evidence failures.
- Database: no migration required; provider/model audit data is stored in unconstrained strings/JSON, so historical Gemini values remain readable.
- Remaining Gemini text: archived pre-migration validation, this migration log, and tests/UI compatibility for historical records only.
- Git: no commit, merge, or push performed.

## Validation results

- Root/backend: 78 passed, 2 skipped, 5 parameterized subtests passed.
- Focused OpenAI/provider/security: 10 passed, 5 parameterized subtests passed (included in the root total).
- Collector: 3 passed; collector compile passed.
- Backend compile: passed.
- Frontend: ESLint, TypeScript, and production build passed.
- Playwright: 17 passed.
- SQLite: clean upgrade, existing upgrade, downgrade, and re-upgrade passed.
- PostgreSQL: clean upgrade, existing upgrade, downgrade, and re-upgrade passed; existing development database is at head.
- Docker development: backend/frontend/PostgreSQL/Redis healthy; Celery worker ping passed.
- Runtime: health, readiness, metrics, OpenAPI, login, authenticated identity, refresh rotation, and old-refresh rejection passed.
- Live OpenAI availability: succeeded once with OpenAI, `gpt-5.6-luna`, completed structured output, IDs, token usage, and validated evidence.
- Grounding: seven additional minimal calls covered the remaining controlled incident variants; no unsupported identifiers, MITRE techniques, prompt-injection following, secret exposure, cross-tenant evidence, or performed-action claims were detected.

## Principal verification commands

```text
git status --short --branch
git branch --show-current
git check-ignore -v -- backend/.env
git grep -Il -E <secret-patterns> -- . ':!backend/.env'
python -m pip install -r requirements.txt
python -m pytest -q
python -m pytest -q tests/test_openai_provider.py tests/test_incident_intelligence_hardening.py ...
python -m compileall -q src
python -m pytest -q && python -m compileall -q .   (collector-agent)
npm run lint
npx tsc --noEmit
npm run build
npm run test:e2e
alembic history
alembic upgrade head
alembic downgrade 20260715_1500
docker compose -f docker-compose.yml up -d --build db redis backend worker frontend
docker compose -f docker-compose.yml exec -T backend alembic current
docker compose -f docker-compose.yml exec -T worker celery -A src.workers.celery_app.celery_app inspect ping
docker compose -f docker-compose.yml exec -T redis redis-cli ping
docker compose -f docker-compose.yml exec -T db pg_isready -U triageops -d triageops
git diff --check
git diff --stat
```

Runtime validation commands used synthetic credentials and incident data supplied only in-process; credential values and provider prompts/responses are intentionally omitted from this log.
