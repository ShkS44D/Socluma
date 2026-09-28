# Incident Intelligence and VigilantAI Copilot

This document describes the implemented incident provenance and incident-scoped AI behavior in VigilantAI.

## Correlation-driven lifecycle

Detection creates and retains alerts first. A single unmatched alert remains open with no `incident_id`; it stays eligible for future correlation and is never discarded. A normal detection-engine incident is created only when at least two distinct alerts reach the deterministic threshold (`CORRELATION_MIN_ALERTS=2`, `CORRELATION_MIN_SCORE=45`) within `CORRELATION_WINDOW_MINUTES=15`, share at least one strong entity identifier, and demonstrate a supported attack-stage or behavior sequence. Manual, Playbook, and historical incidents remain supported and are explicitly labelled by provenance.

Correlation compares MITRE tactic/technique/sub-technique, hostname, agent ID, rule ID, source/destination IP, host, user and port, plus source-event time. Host and agent identity carry the strongest weights; source/destination identity, MITRE, rules, and bounded temporal proximity contribute additional score. Time alone cannot qualify a pair. A strong identifier is a matching host, agent, source/destination IP or host, or source/destination user. Normal attack-chain creation also requires distinct MITRE tactics; event time determines the displayed progression and contributes to sequence confidence. Alerts emitted by different rules for the same source event cannot form a chain by themselves. Deterministic failed-login/successful-login, same-family malware with distinct artifact hashes, and suspicious-network/follow-up-connection patterns are allowed as explicitly labelled behavior sequences. Identical or same-rule/same-technique repetition is pending by default; `CORRELATION_ALLOW_REPEATED_ALERTS=true` permits it as explicitly labelled `repeated_activity`, never as multi-stage progression. Structured logs record tenant, incoming alert, candidate alert IDs, incident, score, matched identifiers, reasons, window, decision, rejection, and lock/race metadata.

Correlated alerts are linked once, ordered by source-event time, and safely reordered for late arrivals. Candidate SQL applies tenant scope, pending/unassociated ownership, dismissal state, and the source-event time window before deterministic newest-first keyset pagination in 500-row pages. This bounded-window pagination cannot lose an eligible match merely because more than 500 newer candidates exist, and it never scans older tenant history outside the window. Structured decisions record the evaluated candidate count and measured candidate-query duration; these measurements describe the tested bounded window and are not claims of enterprise-scale throughput. Event time comes from the linked security event with alert creation time as the fallback. PostgreSQL tenant advisory locking, alert row locks, direct/link consistency checks, and a database-unique `incident_alerts.alert_id` make worker retries idempotent and prevent ownership changes. Closed or resolved incidents are immutable correlation history and never seed later incidents. Every accepted alert added to an active incident recalculates provenance, risk, first/last seen, attack-stage order and MITRE mappings, and invalidates stored AI analysis so stale alert counts and risk scores are not displayed.

## MITRE mappings and confidence

Incidents support multiple persisted mappings. Each mapping stores tactic, full mapped technique ID, separately resolved parent technique ID/name, optional sub-technique ID/name, stage order, first/last seen, source alert IDs, real alert/rule/event evidence, confidence, confidence reasons, and mapping source. Parent names come only from the existing `mitre_techniques` catalog; when unavailable, the parent ID is shown without inventing a name. Confidence combines correlation strength (30%), matching entities (20%), temporal proximity (15%), MITRE sequence consistency (15%), alert evidence quality (10%), and supporting-alert count (10%). AI neither decides correlation nor invents mapping evidence.

`GET /api/v1/incidents/mitre-matrix` aggregates persisted mappings from incidents with at least two linked alerts—not raw alerts—and enforces tenant scope. Filters include date range, severity, status, and incident. Correlated evidence and `legacy-derived` historical metadata are labelled separately. The ownership-integrity migration preserves all records, aligns unambiguous historical direct-only or link-only ownership, aborts with identifying record IDs when an alert has conflicting owners or a cross-tenant link, and adds the global one-alert/one-incident constraint only after preflight. No source evidence is fabricated.

Focused browser acceptance uses the existing Playwright configuration in `frontend/tests/e2e`. Run it against a disposable Docker Compose project with `OPENAI_API_KEY` and external threat-intelligence keys explicitly blank, isolated PostgreSQL/Redis volumes, and synthetic tenant credentials supplied only through process environment variables. Playwright retains failure-only diagnostics; remove its report, trace, screenshot, and video output before staging. For operational troubleshooting, inspect safe correlation logs for the tenant, incoming alert, candidate IDs, score, matched identifiers, decision/rejection reason, window, and lock/retry metadata; never log raw payloads or credentials.

Troubleshooting: pending alerts are expected until a qualifying peer arrives. If expected alerts do not correlate, inspect strong normalized identifiers, event timestamps, MITRE stage order, and structured decision logs. `repeated_activity` should be enabled only for a documented deployment policy. If migration preflight reports ownership conflicts, stop and reconcile those named records through an explicit audited operation before retrying; do not delete or move links ad hoc. If a matrix technique is absent, verify detection-rule or OCSF MITRE data. Restart backend and workers after changing correlation configuration.

## Authoritative ATT&CK catalog and simulation acceptance

VigilantAI carries an offline, reproducible subset generated from the official MITRE ATT&CK Enterprise STIX 2.1 release `v18.1` (`mitre-attack/attack-stix-data`, source SHA-256 `f857d8f78f2f0c0b7db321a711a39fba98546c1e3076a657684850c83d0962fb`). The checked-in JSON contains every technique referenced by enabled built-in rules, pilot fixtures, and the full-chain scenario, plus required parents. It records all applicable tactics and their Enterprise matrix order, parent/sub-technique separation, descriptions, revoked/deprecated state, source version, and authoritative ATT&CK URL. Unknown IDs remain visibly unresolved and generate a safe metadata warning; they are never assigned a guessed tactic.

Synchronize the shared reference catalog after migrations:

```bash
cd backend
python scripts/bootstrap_mitre_catalog.py
```

The command is offline and idempotent. `scripts/build_mitre_catalog.py` regenerates the snapshot only from a separately obtained official STIX bundle; normal startup and tests do not download ATT&CK data. Parent `T1059 Command and Scripting Interpreter` and sub-technique `T1059.001 PowerShell` remain distinct. Multi-tactic techniques retain every official tactic while the earliest Enterprise matrix tactic is the deterministic primary display stage.

`POST /api/v1/events/simulate/full_attack_chain` creates three chronological, synthetic process events with run-unique host, agent, source, and user identities. They traverse normal event storage, Sigma detection, alert creation, deterministic correlation, incident risk/evidence, MITRE persistence, and matrix aggregation. The first alert remains pending; the second creates the incident; the third updates it. Every run is isolated from prior simulations. AI and external threat-intelligence enrichment are disabled for this simulation, and no evidence is inserted outside the processed synthetic events.

The matrix defaults to mapped tactics when mappings exist, supports show-all and tactic-jump modes, exposes a discoverable horizontal desktop matrix, and uses tactic accordions on tablet/mobile. An empty result explains that filters or missing correlated data produced no mappings. Filters remain date/severity/status/incident scoped, and every drill-down uses persisted incident mappings with verified source alerts only. If the matrix is empty, run the catalog bootstrap, confirm the incident has at least two linked alerts and `correlated` mappings, then check the current filters.

The real browser lifecycle is opt-in and must run only against the isolated acceptance Compose file:

```bash
E2E_REAL_LIFECYCLE=1 npx playwright test tests/e2e/real-correlation-lifecycle.spec.ts
```

Supply the isolated frontend/API URLs and synthetic analyst credentials through `E2E_BASE_URL`, `E2E_API_BASE_URL`, `E2E_EMAIL`, and `E2E_PASSWORD`. Keep OpenAI, OTX, AbuseIPDB, and VirusTotal credentials blank. Failure-only screenshots, traces, and videos are temporary diagnostics and must not be committed.

## Incident Creation

An incident can be created by detection and correlation workflows or by a Playbook step. ORM-created incidents default to a manual origin. Detection-created incidents retain the alert that first caused incident creation as their deterministic primary alert. Alerts added later retain their recorded correlation reason, score, sequence, risk contribution, matching entities and indicators, and time difference from the primary alert.

The incident record persists creation and correlation facts that would otherwise be lost. Source-alert counts, source-event counts, affected-entity counts, detection references, timeline entries, IOC references, and evidence links are calculated from current tenant-scoped relationships.

Provenance is explicitly labelled:

- `recorded`: provenance was captured when the incident was created or updated.
- `manual`: no automatic detection origin is claimed.
- `legacy_derived`: the incident predates detailed tracking. Derived display fields are identified, and the API states that the exact historical correlation reason is unavailable.

Legacy records are not rewritten with invented correlation facts.

```mermaid
flowchart LR
    Event["Security event"] --> Rule["Detection rule match"]
    Rule --> Alert["Alert"]
    Alert --> Correlation["Tenant-scoped correlation"]
    Correlation --> Incident["Incident"]
    Incident --> Explanation["Deterministic explanation"]
    Explanation --> VigilantAI Copilot["Grounded VigilantAI Copilot context"]
```

## Explanation API

`GET /api/v1/incidents/{incident_id}/explanation`

The endpoint requires an authenticated `admin`, `analyst`, or `responder`. Tenant scope comes from the authenticated session; a client-supplied tenant ID is not accepted.

The response contains:

- Incident origin and creation reason.
- Primary and correlated alert contributions.
- Source events and detection-rule matches.
- Correlation key, score, window, and reasons.
- Chronological timeline summary.
- Evidence-backed users, hosts, IPs, processes, files, hashes, domains, URLs, email addresses, cloud resources, collectors, and log sources when present.
- IOC and MITRE ATT&CK references.
- Risk score breakdown and severity rationale.
- Evidence references, limitations, and recommended investigation questions.

Large alert and event collections are bounded by validated query limits. Existing incident and alert APIs remain unchanged.

The official risk score is deterministic. It combines base severity (low 10, medium 20, high 30, critical 40), bounded multiple-alert, suspicious-behavior, threat-intelligence, asset-criticality, MITRE-impact, and analyst-feedback factors. The breakdown includes the uncapped total and any bounding adjustment, so its numeric components always reconcile to the final 0-100 score. AI output cannot change the official score.

## VigilantAI Copilot Data Access

The VigilantAI Copilot may read only controlled views of the current incident:

- Summary and origin.
- Related alerts and source events.
- Detection matches.
- Timeline and entities.
- IOCs, risk factors, and MITRE mapping.
- Analyst notes and incident audit history.

It cannot perform arbitrary database queries, run code or shell commands, execute Playbooks or SOAR actions, close incidents, or take containment action. Recommendations always require analyst review.

## Grounding and Safety

Every answer returns an answer, evidence references, confidence, limitations, suggested follow-up questions, provider, model, generation time, request ID, and fallback status. References identify the incident, alert, event, IOC, entity, or stored evidence used to support the answer.

Conversation records belong to one tenant, incident, and user. Other users cannot retrieve that history through the conversation APIs. Prompts are size-bounded. Event payloads, alert text, IOC values, analyst questions, conversation history, and notes are structurally separated as untrusted content from provider system instructions. Sensitive dictionary fields and inline credential assignments are redacted, and common instruction-override phrases are neutralized before provider submission.

If OpenAI is unavailable, invalid, timed out, rate limited, or over quota, VigilantAI returns deterministic analysis from the same authorized evidence. The response identifies the local fallback provider and retains citations and limitations.

## Environment

- `OPENAI_API_KEY`: optional in development and required by production runtime validation.
- `OPENAI_MODEL`: OpenAI model name; configured as `gpt-5.6-luna`.
- `OPENAI_TIMEOUT_SECONDS`, `OPENAI_MAX_OUTPUT_TOKENS`, and `OPENAI_REASONING_EFFORT`: bounded request controls.

No additional environment variables are required for incident provenance or deterministic fallback analysis.

## Demo Workflow

1. Ingest an event that matches an enabled detection rule.
2. Open the generated incident and review **How This Incident Was Created**.
3. Follow the displayed event, rule, alert, correlation, and incident chain.
4. Review the primary alert, correlated alerts, entities, IOCs, risk factors, MITRE mapping, evidence, and limitations.
5. Select **Open VigilantAI Copilot** and ask: `Why was this incident created?`
6. Open the cited alert or event below the answer.
7. Ask: `Which evidence supports the severity?` and `What should I investigate next?`
8. Temporarily omit `OPENAI_API_KEY` in a development environment to demonstrate that deterministic fallback analysis remains available.

The VigilantAI Copilot enhances the deterministic explanation; it does not replace or alter the underlying incident evidence.
