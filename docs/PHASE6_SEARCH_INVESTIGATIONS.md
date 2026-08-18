# Phase 6 search and investigation workspace

## Architecture and safety

The search path is: authenticated request → effective organization permissions → parser → typed AST → tenant predicate → time predicates → parameterized SQLAlchemy expressions → safe projection → bounded page. User text is never concatenated into SQL. Saved searches retain a sanitized display query and normalized AST.

Interactive searches default to 24 hours, are limited to 30 days without `search.extended_range`, allow at most 200 rows per page, and use deterministic secondary sorting. This is database-backed search for moderate operational datasets. Portable JSON text matching is not search-engine-scale.

## Query language and field catalog

Supported forms are `field:value`, `field="value"`, comparisons, `IN (...)`, `EXISTS`, `NOT EXISTS`, Boolean operators, parentheses, quoted phrases, ISO UTC times, and values such as `now-24h`. Portable CIDR matching supports `/8`, `/16`, and `/24`. Leading wildcards and unknown fields are rejected. Query length, clauses, nesting, wildcard count, list size, ranges, sorts, and pages are bounded.

```text
event.category:authentication AND user.name:"alice"
source.ip:10.0.0.5 AND severity>=high
host.name:web-01 AND process.name:powershell.exe
timestamp>=now-24h AND result:failure
entity.type:ip
```

`GET /api/v1/search/fields` returns permission-aware public field names, types, operators, sort/facet flags, masking metadata, examples, and index status without database expressions.

## Search library, sharing, and schedules

History belongs to the current user and organization and redacts credential-like values. Saved searches support visibility, tags, pinning, cloning, revisions, protected templates, and expiring internal share references. Hourly/daily/weekly schedules run through Celery-compatible work and recheck the owner, membership, organization status, permissions, and limits each time. They record run history and never create alerts or detection rules.

## Entities and graph

Ingestion extracts bounded user, host, IP, process, file, hash, domain, URL, and email entities. Values are validated, tenant-deduplicated, linked to events, and maintain first/last seen and sighting counts. Reprocessing is idempotent. Observed edges include user-to-host, user-to-process, host-to-IP, process-to-file, and domain-to-IP. Graph responses are evidence-backed, tenant-scoped, relational, depth/node/edge limited, and include accessible list data.

## Investigation evidence and collaboration

Investigations use only `open`, `active`, `completed`, and `archived`, and may link to an incident. They support collaborators, linked resources, ordered bookmarks, sanitized plain-text notes with revisions, and immutable allowlisted snapshots. Snapshots retain selected normalized fields, parser/schema provenance, raw-event hash, and projection integrity hash. These prove stored-content integrity, not external legal authenticity.

Binary attachment storage is deferred. The metadata endpoint validates configured size and MIME allowlists, creates a safe generated filename and hash/classification/scanning extension fields, returns no local path, and marks the record `metadata_only`.

## Exports and reports

Expiring jobs produce search CSV, JSONL, or evidence ZIP, and investigation JSON/Markdown reports. Jobs recheck access, enforce row limits, use safe projections, create manifests/checksums, store through Phase 4 encrypted artifact storage, and audit requests/downloads.

## Permissions, retention, and troubleshooting

Phase 3 permissions separately cover resources, saved searches, schedules, exports, investigations, graphs, bookmarks, snapshots, and attachments. Viewer access is read-only; analysts have normal investigation tools without export/snapshot authority; managers have schedule/export/evidence authority. Credential fields and audit records are excluded from general search. Phase 4 classification, expiry, audit integrity, retention, and legal-hold rules remain authoritative.

- `SEARCH_FIELD_UNKNOWN`: use a field from `/search/fields`.
- `SEARCH_TIME_RANGE_TOO_LARGE`: narrow the range or obtain extended permission.
- `SEARCH_SORT_INVALID`: select a sortable catalog field.
- Empty result: check active organization and the default 24-hour window.
- Disabled schedule: check owner, membership, organization status, and permissions.
- `EXPORT_NOT_READY`: poll status; `EXPORT_EXPIRED`: create another export.

No dedicated search/graph database, public links, full case management, binary attachment storage, ML relationship inference, or automatic alerts from schedules are added. Entity types share one common detail/timeline/graph page rather than separate bespoke screens.
