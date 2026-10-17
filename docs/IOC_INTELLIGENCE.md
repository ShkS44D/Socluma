# IOC Intelligence (Phases 7.5 and 7.6)

Socluma keeps IOC intelligence tenant-scoped. An IOC is identified by organization, type, and
canonical normalized value. Original input is retained for provenance; matching uses only the
canonical value and content hash.

## Supported indicators

IPv4, IPv6, CIDR, domain, URL, email, MD5, SHA-1, SHA-256, SHA-512, file name,
file path, registry key, mutex, user agent, certificate fingerprint, JA3, JA4, and
cryptocurrency address are represented. Validation is type-specific. Defanged `hxxp`, `hxxps`,
`[.]`, `(.)`, and `[:]` inputs are refanged without fetching the supplied URL. Unicode domains
are converted to IDNA/punycode and flagged by normalization.

## Lifecycle and scoring

Lifecycle transitions are centralized for `new`, `under_review`, `active`, `monitoring`,
`false_positive`, `allowlisted`, `expired`, `revoked`, and `archived`. False-positive,
allowlist, revoke, and archive transitions require a reason. Only active and monitoring IOCs
match telemetry. Explainable operational risk keeps confidence, source reliability, provider
consensus/conflict, sightings, recency, lifecycle, and allowlist effects separate. Every
recalculation records a score version and weighted reasons.

## Enrichment and sightings

VirusTotal, AbuseIPDB, OTX, and the internal heuristic use type compatibility and the existing
cache. UI responses expose bounded normalized provider results, never provider credentials or
unrestricted raw responses. Provider failures are logged without indicator values or keys.
Post-ingestion worker processing matches tenant-local active IOCs and creates idempotent sightings
linked to exact events and matched fields. Redis is not required for correctness.

## Lists, review, exchange, and integrations

Tenant watchlists and allow/warning entries are available through IOC APIs. Review queues cover
new, under-review, high-risk, sighted, expiring, and failed-enrichment indicators. STIX 2.1
supports bounded Bundle import previews and deterministic export for supported indicator patterns;
unsupported objects and patterns are reported. TLP markings are stored and TLP:RED exports require
explicit override permission.

TAXII 2.1 collection pulls and MISP pull/push synchronization run as tenant-scoped background
jobs. Source credentials are encrypted at rest, returned only as redacted metadata, and can be
tested or rotated without plaintext disclosure. Requests use HTTPS certificate validation,
bounded redirects, DNS/private-address protection, timeouts, response-size limits, pagination
limits, and sanitized failures. Synchronization remains disabled until explicitly configured.

Bulk imports accept bounded CSV, JSON, JSONL, STIX, and MISP artifacts. Uploaded artifacts are
encrypted, filenames are sanitized, validation can run as a dry run, and row-level results
separate valid, invalid, duplicate, and created records. Destructive bulk actions require a
preview and explicit confirmation. Review assignments and decisions retain revisioned history.

Watchlists support policies and bounded historical hunts. The relationship graph combines
explicit relationships and sighting evidence while enforcing depth, node, and edge limits and
providing a tabular fallback. IOC-to-detection creates a disabled draft with typed fields and
provenance; normal validation, simulation, approval, and publication are still required.
Response recommendations create exact, fingerprint-bound human approval requests and never
execute automatically.

Reports are asynchronous, encrypted, expiring artifacts in CSV, JSON, JSONL, Markdown, HTML,
STIX, or ZIP form. Manifests include checksums and applied limits. `TLP:RED` content is excluded
from commercial reports and automatic notification delivery unless an explicitly authorized
recipient scope is supplied.

## Operational limits and deferred scope

Configuration bounds provider concurrency/retries, TTLs, bulk size, hunt range, STIX/TAXII/MISP
payloads, watchlist size, and artifact lifetime. This phase does not provide a TAXII server,
unrestricted public sharing, automatic destructive response, a graph database, full MISP/STIX
object coverage, or unlimited telemetry scale. Real provider tests require tenant-supplied
credentials and network access; automated tests use mocks and never contact providers.

## Demo workflow

1. Create a defanged IOC in Threat Intelligence and review its canonical value.
2. Move it to active or monitoring.
3. Enrich it and compare safe normalized provider verdicts and risk reasons.
4. Ingest a matching event and open its internal sighting evidence.
5. Add it to a watchlist or allow/warning list.
6. Assign and decide an item in **IOC Review**.
7. Create a watchlist and run a bounded historical hunt.
8. Generate a disabled IOC detection draft and inspect its provenance.
9. Request a response recommendation and have a different authorized user approve it.
10. Generate an IOC report and verify its checksum before it expires.

Troubleshooting: a valid IOC with no sightings is normally inactive, expired, allowlisted, or not
present in normalized event fields. Provider failures do not block internal matching.
