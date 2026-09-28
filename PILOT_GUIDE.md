# VigilantAI Controlled Analyst Pilot Guide

Use this pilot only with synthetic data. **Do not enter confidential customer data, credentials, tokens, or production indicators.**

## Start the environment

From the repository root:

```powershell
docker compose -f docker/docker-compose.yml up -d --build
docker compose -f docker/docker-compose.yml exec -T backend python scripts/seed_analyst_pilot.py --dry-run
docker compose -f docker/docker-compose.yml exec -T backend python scripts/seed_analyst_pilot.py
```

Start the collector in a second terminal:

```powershell
Set-Location collector-agent
python main.py
```

Open `http://localhost:3000`. Sign in with the pilot credentials supplied privately by the pilot coordinator (`<PILOT_EMAIL>` and `<PILOT_PASSWORD>`). Never place real credentials in this guide.

## Recommended investigation order

Filter incidents to **All statuses**, then investigate: Simple detection -> Multi-alert correlated -> High-risk -> Incomplete evidence -> Prompt-injection resilience -> Manual -> Legacy-style. Review the origin explanation, primary alert, linked events/rules, risk breakdown, evidence, entities, and timeline before using VigilantAI Copilot.

## VigilantAI Copilot and fallback

Open VigilantAI Copilot and ask "Why was this incident created?" followed by "Which facts are confirmed and what evidence is missing?" Verify every evidence link opens an object belonging to the incident. A normal answer shows `provider: openai`; fallback mode shows `fallback_used: true` and provider/model metadata for `vigilantai-deterministic-v1`. Fallback is expected to remain grounded and useful.

## Report a bug

Record the pilot scenario, page, steps, expected result, actual result, time, and a screenshot with secrets removed. Do not include tokens, passwords, confidential payloads, or customer data. Attach the completed `PILOT_FEEDBACK_FORM.md` to the pilot coordinator’s approved reporting channel.
