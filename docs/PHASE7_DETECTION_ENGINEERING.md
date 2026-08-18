# Phase 7 Detection Engineering

## Architecture and lifecycle

A detection rule is the stable, tenant-owned identity. `detection_rule_versions`
contains immutable content revisions with deterministic version numbers and SHA-256
content hashes. Production evaluation reads `production_version_id`; draft edits
cannot affect live evaluation. Existing enabled rules are migrated to version 1,
and historical detection matches retain the exact version and hash.

The centrally enforced lifecycle is:

`draft → validating → ready_for_review → under_review → approved → production`

Validation or tests can return a version to `draft`/`test_failed`; review may request
changes. Production versions can be disabled or retired, and retired versions can
be archived. A new publication disables the previous production revision without
deleting it. Rollback creates a new, reviewable draft from an older exact version.
Two-person approval is enabled by default, is bound to the version/hash, and expires.

## Rule types and validation

Structured rules support event match, threshold, frequency, aggregation (`count`,
`distinct_count`, `min`, `max`, `sum`, `avg`), ordered sequence, and correlation.
Fields come from the Phase 6 normalized-field catalog. Windows, groups, sequence
steps, cardinality, clauses, input size, and complexity are bounded. No `eval`,
arbitrary Python, SQL, shell, or template execution is supported.

Regular expressions use the `regex` package with input truncation, a configurable
timeout, length/capture limits, and nested-quantifier rejection. A timeout is a
controlled non-match. Sigma YAML uses safe loading, preserves original content,
and records validation warnings. Sigma support is intentionally a safe subset;
unsupported features are reported and must not be treated as silently supported.

## Testing and simulation

Version-specific test cases store masked normalized events, expectations, and a
content hash. Test results record status, bounded evidence summaries, and runtime.
Historical simulation is a Celery job over tenant-scoped events. It enforces date
and event limits, never creates real matches/alerts/incidents, supports status and
cancellation, and expires its stored projection. Returned examples contain IDs and
safe projections rather than unrestricted raw telemetry.

## Execution controls and provenance

Production matching stores rule/version/hash, rule type, contributing event IDs,
conditions, aggregate values, group/window information, MITRE mappings, confidence,
risk contribution, parser/data-source provenance, and a deterministic explanation.
Rule/version/tenant grouping bounds state. Event idempotency and match uniqueness
prevent retry duplication.

Exceptions are tenant-scoped, time-bound typed predicates. Suppression policies
bound alert volume, while maintenance windows suppress scoped alert creation.
Suppressed matches remain stored and report why they were suppressed. Permanent
or broad exemptions should continue through an approval workflow; Phase 7 does not
auto-approve them.

## Health, quality, MITRE, and content packs

Analytics expose rule lifecycle, match volume, a deterministic quality indication,
and actionable recommendations. ATT&CK coverage distinguishes draft and production
mapping and explicitly warns that mapping is not proof of telemetry health or
detection efficacy. Health snapshot and recommendation tables preserve historical
operational results.

Content-pack import supports validation-only dry runs, checksum/manifest storage,
duplicate pack detection, bounded rule counts, attribution, and draft-only
installation. Packages never execute scripts and never activate imported rules.

## Detection as code

Run from `backend`:

```powershell
python scripts/detection_cli.py validate rules/example.yml
python scripts/detection_cli.py test rules/example.yml tests/events.json
python scripts/detection_cli.py manifest rules/example.yml tests/events.json
```

Output is deterministic JSON. Validation failures return a non-zero exit code, so
the same commands can be used in CI later. The CLI does not connect to the database,
publish content, embed credentials, or push to Git.

## Permissions and audit

Authoring, validation, test, simulation, review, approval, publication, disablement,
retirement, rollback, cloning, import/export, metrics, exceptions, maintenance,
content packs, Sigma, and ATT&CK coverage have separate permissions. Administrators
do not inherit approval/publication rights merely from the administrator role.
Authors cannot approve their own version when two-person approval is enabled.

Version creation, lifecycle transitions, exceptions, maintenance, and controlled
imports write safe audit events. Permission denials use the established denial
audit path. Raw event payloads and secrets are excluded.

## API errors and compatibility

Cross-tenant lookups return 404. Permissions return 403. Lifecycle conflicts return
409, validation errors 422, and oversized datasets 413. Responses use stable Phase
7 error codes without SQL, stack traces, or internal paths.

Migration `20260729_1800` upgrades from Phase 6 head `20260729_1700` on SQLite and
PostgreSQL. Downgrade removes Phase 7 structures but is destructive to Phase 7
history; back up first. Existing rule IDs, alerts, incident correlation, Sigma
behavior, and event ingestion are preserved.

## Practical limits

The built-in database evaluator is designed for bounded SOC workloads, not
search-engine scale. Sigma is not complete-spec support. Quality recommendations
are deterministic and require analyst action; they do not modify rules. External
Git hosting, vendor marketplace coverage, machine-learning detections, HA, and
automatic destructive response remain deferred.
