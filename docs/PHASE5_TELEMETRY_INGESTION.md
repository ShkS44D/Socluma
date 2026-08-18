# Phase 5 — Telemetry Ingestion and Collector Management

## Architecture

Collectors persist events in an encrypted, bounded SQLite FIFO before transmission. They send batches to
`POST /api/v1/events/ingest/batch`. The API validates the tenant and source assignment, normalizes each event,
persists accepted events and a receipt in one transaction, and only then queues downstream detection work.
Permanent parsing failures enter the dead-letter queue; transient downstream failures use bounded Celery retries.

The original `POST /api/v1/events/ingest` route remains as a compatibility wrapper and still returns the legacy
detection response.

## Ingestion contract

- Maximum batch, event, and request sizes are configuration-controlled.
- A batch ID is idempotent for one authenticated actor. Reusing it with different content is a conflict.
- Source event IDs and idempotency keys are authoritative identities. Otherwise, a canonical SHA-256 content
  fingerprint is used. This is exact deterministic deduplication, not fuzzy similarity matching.
- Receipts report accepted, duplicate, and rejected items independently, allowing partial acceptance.
- JSON, RFC-style syslog envelopes, CEF, LEEF, Windows, and Linux inputs use a versioned parser registry.
- Normalized records use a stable OCSF-oriented internal envelope. Full OCSF certification is not claimed.
- Timestamps are stored in UTC while a supplied offset is retained. Invalid or missing timestamps reduce the
  quality score and default to receive time.
- Extension field count, key length, string length, and request size are bounded.

## Collector lifecycle

Administrators create short-lived enrollment tokens at `POST /api/v1/collectors/enrollment-tokens`. The raw token
is shown once; only its password hash is stored. A collector exchanges it once at `/collectors/enroll` and receives
a scoped credential. Credential rotation supports a short overlap window, while revocation immediately invalidates
all credentials.

Heartbeats carry version, operating system, queue/spool depth, counters, resource pressure, policy version,
checkpoint health, uptime, and service state. The server derives healthy, degraded, upgrade-required, and
blocked-version states. `/collectors/me/configuration` returns safe policy/version and batching information.

Installer guidance is under `collector-agent/install/` for Windows and systemd Linux deployments. Production
packages should be signed in the release pipeline; these repository scripts do not claim code signing.

## Durable local behavior

`collector-agent/spool.py` encrypts event payloads with a locally generated Fernet key stored with restricted
permissions and uses SQLite WAL plus full synchronization. FIFO eviction enforces the configured disk cap.
`state.py` atomically replaces checkpoint files and retains a last-known-good backup. A checkpoint advances only
after the corresponding events have reached durable local storage.

## Data sources, imports, and operations

`/api/v1/telemetry/sources` manages parser, transport, assignment, enablement, quality threshold, throughput,
lag, accepted/rejected/duplicate counts, and health. File import accepts bounded UTF-8 JSON, JSONL, and CSV.
`/telemetry/metrics` summarizes volume, quality, receive time, and failure states. `/telemetry/dead-letter` lists
permanent failures and supports controlled replay of downstream failures.

Native UDP/TCP/TLS syslog listeners remain disabled by default. They require a separately hardened network
receiver deployment; the current release accepts syslog payloads over authenticated HTTPS ingestion.

## Permissions and audit

Phase 5 adds telemetry, data-source, collector enrollment/credential/policy/group/update, metrics, import, replay,
and dead-letter permissions. Administrative lifecycle actions and batch summaries are audited without raw events,
tokens, passwords, or authorization headers.

## Upgrade

Run `alembic upgrade head`; expected head is `20260729_1600`. Existing collector registration and single-event
ingestion remain supported. Existing collector tokens continue to authenticate and are migrated to indexed lookup
hashes by the compatibility path.

## Operational limits

- Downstream detection is at-least-once; event processing status prevents intentional duplicate processing.
- This phase provides one active policy version per newly created policy. Rich staged rollout controls are API
  foundations, not a complete release orchestration engine.
- Source health is request-driven. Scheduled stale-source notifications should be connected to the deployment's
  notification channel in a later operations phase.
- File imports are processed inline after upload in this release; large enterprise imports should move to object
  storage plus asynchronous workers.
