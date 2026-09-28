# Phase 7.6 Demo and Operations Guide

## Vendor-neutral controlled demonstration

1. Sign in as an organization owner and confirm the active organization.
2. Open **Threat Sources** and show configured status, safe test history, and credential fingerprints.
   Do not enter or test live provider credentials during the executive demonstration.
3. Open **TAXII** or **MISP** and explain bounded synchronization using the stored controlled-demo
   history. Show progress, safe counts, cursor metadata, and sanitized failures without claiming a
   live external connection.
4. Open **Bulk IOC Operations**, upload the sample CSV as a dry run, review valid/invalid/duplicate
   row counts, then confirm an import.
5. Open **IOC Review**, assign a different analyst, record a decision, and show revision history.
6. Create a watchlist, run a historical hunt, and inspect matched event provenance.
7. Open **Relationship Graph** and show both the bounded graph data and accessible tables.
8. Generate an IOC detection. Confirm it is a disabled draft, then continue through Detection
   Engineering validation and approval.
9. Create a response recommendation. Demonstrate that the requester cannot approve it and that no
   connector action occurs without approval.
10. Generate a ZIP report, download it before expiry, and verify its manifest and checksum.

## Sample bulk CSV

```csv
type,value,source,confidence_score,source_reliability,tlp
ipv4,192.0.2.10,controlled-demo,80,70,TLP:AMBER
domain,example.invalid,controlled-demo,60,60,TLP:GREEN
sha256,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,controlled-demo,90,80,TLP:AMBER
```

## Production checklist

- Use PostgreSQL and Redis/Celery; run `alembic upgrade head` as a controlled deployment step.
- Supply strong versioned encryption keys and place provider credentials only in the source UI.
- Configure explicit HTTPS origins, trusted hosts, threat-source destinations, TLS certificates,
  notification delivery, artifact retention, backups, monitoring, and worker concurrency.
- Keep private-address threat sources blocked. Permit a destination only after infrastructure and
  security review; never broadly allow metadata, loopback, link-local, or management ranges.
- Review least-privilege permissions for source management, sync, import, bulk action, review,
  hunts, graph, detection generation, recommendations, approvals, and report export.
- Verify cancellation, retry/backoff, stale jobs, artifact expiry, TLP handling, audit integrity,
  tenant switching, and disaster recovery before production.

## Honest limitations

VigilantAI implements a bounded TAXII client and a practical MISP attribute subset, not a TAXII
server or complete MISP/STIX platform. The relationship graph uses the relational database rather
than a graph database. Historical hunts and reports are intentionally capped. Response items are
recommendations with human approval, not automatic vendor-agnostic containment. Real provider
tests require customer-supplied credentials and network access.

## Troubleshooting

- **Source test fails:** validate the public HTTPS URL, certificate, provider key, and destination
  allowlist. The displayed message is intentionally sanitized; use request IDs and protected logs.
- **Sync imports nothing:** inspect collection/filter settings, safe cursor, unsupported count, and
  the tenant selected in the header.
- **Import remains uploaded:** verify Celery and Redis, then inspect the import job error code.
- **IOC has no sightings:** activate or monitor it, confirm it is not allowlisted/expired, and check
  normalized event fields.
- **Report is unavailable:** wait for completion, verify export permission, and regenerate expired
  artifacts.
