# VigilantAI Demo Runbook

## Purpose and audience

This company-neutral runbook presents VigilantAI to executive and technical stakeholders as an evidence-first SOC operations platform. The audience is assumed to understand security telemetry, detection engineering, incident response, threat intelligence, and approval controls. All demonstration data is synthetic; documentation IP ranges, `.invalid` domains, and synthetic hashes are used.

## Prerequisites

- Docker Desktop is running.
- Ports 3000 and 8001 are available.
- The repository is open at `D:\AI SOC Assistent (Main)`.
- Choose strong temporary passwords locally. Never commit or screen-share them.

```powershell
cd "D:\AI SOC Assistent (Main)"
$env:TEST_DEMO_OWNER_PASSWORD="<temporary-owner-passphrase>"
$env:TEST_DEMO_ANALYST_PASSWORD="<temporary-analyst-passphrase>"
$env:TEST_DEMO_OWNER_EMAIL="demo.owner@example.com"
docker compose -f docker/docker-compose.yml up -d --build
docker compose -f docker/docker-compose.yml exec backend alembic upgrade head
docker compose -f docker/docker-compose.yml exec `
  -e TEST_DEMO_OWNER_PASSWORD=$env:TEST_DEMO_OWNER_PASSWORD `
  -e TEST_DEMO_ANALYST_PASSWORD=$env:TEST_DEMO_ANALYST_PASSWORD `
  -e TEST_DEMO_OWNER_EMAIL=$env:TEST_DEMO_OWNER_EMAIL `
  backend python scripts/seed_test_demo.py --confirm-test-demo-seed
```

Expected checks:

```powershell
docker compose -f docker/docker-compose.yml ps
Invoke-RestMethod http://localhost:8001/health
docker compose -f docker/docker-compose.yml exec backend alembic heads
```

All application services should be healthy and Alembic should show one head: `20260801_2000`.

## Demo accounts

- Owner/approver and presenter: `demo.owner@example.com`
- Analyst/requester: `demo.analyst@example.com`

For an existing `demo.owner@example.com` account, `TEST_DEMO_OWNER_PASSWORD` must be its current login password; the seed preserves that password and the account's home organization. The analyst password comes from `TEST_DEMO_ANALYST_PASSWORD`. Seed output identifies accounts but never prints passwords.

## Preflight smoke test

```powershell
docker compose -f docker/docker-compose.yml exec `
  -e TEST_DEMO_OWNER_PASSWORD=$env:TEST_DEMO_OWNER_PASSWORD `
  -e TEST_DEMO_ANALYST_PASSWORD=$env:TEST_DEMO_ANALYST_PASSWORD `
  -e TEST_DEMO_OWNER_EMAIL=$env:TEST_DEMO_OWNER_EMAIL `
  backend python scripts/test_demo_smoke_test.py --base-url http://127.0.0.1:8000
```

Proceed only when every line says `PASS` and the summary reports zero failures.

## Optional: duplicate the controlled story into Default Tenant

This operation is additive and idempotent. It does not delete or reset the
`VigilantAI Demo` tenant, and it preserves the owner's existing
Default Tenant account and password.

```powershell
$env:DEFAULT_DEMO_OWNER_EMAIL="demo.owner@example.com"
$env:DEFAULT_DEMO_OWNER_PASSWORD="<current-owner-password>"
$env:DEFAULT_DEMO_ANALYST_EMAIL="default.analyst@example.com"
$env:DEFAULT_DEMO_ANALYST_PASSWORD="<temporary-default-analyst-password>"

docker compose -f docker/docker-compose.yml exec `
  -e DEFAULT_DEMO_OWNER_EMAIL=$env:DEFAULT_DEMO_OWNER_EMAIL `
  -e DEFAULT_DEMO_OWNER_PASSWORD=$env:DEFAULT_DEMO_OWNER_PASSWORD `
  -e DEFAULT_DEMO_ANALYST_EMAIL=$env:DEFAULT_DEMO_ANALYST_EMAIL `
  -e DEFAULT_DEMO_ANALYST_PASSWORD=$env:DEFAULT_DEMO_ANALYST_PASSWORD `
  backend python scripts/seed_default_tenant_demo.py --confirm-default-tenant-demo-seed
```

Validate Default Tenant independently:

```powershell
docker compose -f docker/docker-compose.yml exec `
  -e TEST_DEMO_OWNER_EMAIL=$env:DEFAULT_DEMO_OWNER_EMAIL `
  -e TEST_DEMO_OWNER_PASSWORD=$env:DEFAULT_DEMO_OWNER_PASSWORD `
  -e TEST_DEMO_ANALYST_EMAIL=$env:DEFAULT_DEMO_ANALYST_EMAIL `
  -e TEST_DEMO_ANALYST_PASSWORD=$env:DEFAULT_DEMO_ANALYST_PASSWORD `
  backend python scripts/test_demo_smoke_test.py `
    --organization-slug default `
    --base-url http://127.0.0.1:8000
```

## Presentation sequence

1. **Login as the owner.** Open `http://localhost:3000`, sign in as `demo.owner@example.com`, then select **VigilantAI Demo** from the organization selector. Expected: the demo dashboard loads. Talking point: one authenticated account can access explicitly authorized, tenant-isolated workspaces without mixing their data.
2. **Dashboard.** Expected: an online controlled collector, events, three demo detections, related alerts, and one high-risk incident. Talking point: telemetry-to-incident operational posture in one view.
3. **Log Sources → Events.** Open the demo collector and recent events. Expected: login failures, encoded PowerShell, and DNS beacon telemetry with UTC timestamps. Talking point: normalized evidence retains raw provenance.
4. **Detection Rules.** Filter for `[SYNTHETIC DEMO]`. Expected: rules map to T1110, T1059.001, and T1071 and show matched evidence. Talking point: detections explain why they triggered.
5. **Alerts → Incidents.** Open the VigilantAI demo incident. Expected: multiple alerts correlated by host, user, source IP, and bounded time window. Talking point: incidents are correlation results, not invented summaries.
6. **Incident Detail → explanation/timeline/evidence.** Expected: origin, reasons, risk factors, source event IDs, alert IDs, entities, and citations. Talking point: every conclusion links back to authorized evidence.
7. **MITRE Matrix.** Expected: Credential Access → Execution/PowerShell → Command and Control progression. Talking point: mapping confidence and supporting alerts are visible.
8. **VigilantAI Copilot.** Generate the incident summary. Expected: grounded summaries, investigation steps, containment considerations, confidence, and evidence. If external AI is unavailable, use the deterministic offline result described below.
9. **Threat Intelligence.** Expected: synthetic IP, domain, and SHA-256 indicators with normalized values, confidence, risk, lifecycle, TLP, enrichment state, and internal sightings.
10. **IOC Review.** Select the under-review hash, assign the analyst, add a comment, adjust confidence, and choose an appropriate decision. Expected: same-organization assignment and revision history.
11. **IOC Watchlists.** Load `Priority Indicators`. Expected: member, TLP, status, sighting counts; demonstrate add/remove with a synthetic IOC only.
12. **Historical Hunts.** Expected: completed bounded hunt with events scanned, matches, progress, and no truncation. Explain cancellation/retry controls and safety caps.
13. **IOC Detection Drafts.** Expected: `[SYNTHETIC DEMO] IOC containment signal draft` is disabled and remains in draft. Talking point: intelligence never silently becomes production detection content.
14. **Response Recommendations.** Log in as the analyst to show the pending block-IP recommendation and failed self-approval. Log back in as owner to approve or reject. Expected: exact request fingerprint binding and no unsupported connector execution.
15. **Audit Logs.** Expected: seed, recommendation, review, approval, and report-download activity. Talking point: append-only, tenant-scoped accountability.
16. **IOC Reports.** Download the completed Test JSON report. Expected: authenticated download with safe filename, checksum, expiry, and TLP:RED exclusion.

## Stakeholder questions

- Which telemetry sources should be prioritized for a pilot?
- Which approval actions require two-person control in the stakeholder's operating model?
- What retention, TLP, and data-residency policies apply?
- Which MITRE techniques and business-critical assets matter most?
- What success measures should a 30-day pilot report?

## Recovery paths

- **VigilantAI Copilot unavailable:** call the authorized incident summary with `offline=true` or use the seeded incident explanation. It is clearly labelled deterministic offline analysis and makes no provider call.
- **Worker delayed:** show the already completed seeded hunt/report, then inspect `docker compose ... logs worker --tail 100`. Do not repeatedly enqueue jobs.
- **Threat provider unavailable:** show configured status, credential fingerprint, sanitized test history, and the controlled offline IOC dataset. Never claim a real connection succeeded.
- **UI becomes stale:** hard-refresh once, confirm backend health, and use the smoke test. Do not reseed until the database is explicitly confirmed.

## Honest limitations

TAXII and MISP support is bounded rather than a complete server implementation. Historical hunts, graph expansion, and exports have safety caps. Response items are recommendations requiring human approval; unsupported vendor actions are not executed. The relationship graph uses the relational database. The deterministic VigilantAI Copilot fallback is evidence-grounded but does not add external knowledge.

## Reset, shutdown, and cleanup

Reset only the reserved VigilantAI demo tenant:

```powershell
docker compose -f docker/docker-compose.yml exec `
  -e TEST_DEMO_OWNER_PASSWORD=$env:TEST_DEMO_OWNER_PASSWORD `
  -e TEST_DEMO_ANALYST_PASSWORD=$env:TEST_DEMO_ANALYST_PASSWORD `
  -e TEST_DEMO_OWNER_EMAIL=$env:TEST_DEMO_OWNER_EMAIL `
  backend python scripts/reset_test_demo.py --confirm-test-demo-reset
```

Shutdown after the meeting:

```powershell
docker compose -f docker/docker-compose.yml down
Remove-Item Env:TEST_DEMO_OWNER_PASSWORD
Remove-Item Env:TEST_DEMO_ANALYST_PASSWORD
Remove-Item Env:TEST_DEMO_OWNER_EMAIL
```

Do not use `down -v` unless deletion of all local Docker data is separately intended and approved.
