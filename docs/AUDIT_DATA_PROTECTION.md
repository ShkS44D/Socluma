# Audit Logging, Retention, and Data Protection

Back up the database and both audit artifact directories before applying migration
`20260729_1500`. Socluma does not claim compliance certification, external SIEM
archival, cloud object storage, an external secrets manager, or full DLP.

## Event taxonomy and integrity

Audit actions use validated stable lowercase identifiers; established underscore or
single-token names remain compatible while new events use dotted names.
Events belong to fixed security and operations categories. Each tenant has an ordered chain state. New records contain a
sequence, previous hash, and HMAC-SHA256 over canonical security fields. The HMAC key
version is stored; the key is not. Legacy records are deterministically chained with
compatibility hash version 0 during migration, so migration never needs plaintext
secrets. Verification reports the first missing or modified sequence and never
repairs data. Normal ORM update/delete operations on audit rows are blocked.
During HMAC-key rotation, configure current and previous versions in
`AUDIT_INTEGRITY_KEYS_JSON` until all retained records using the prior version expire.

## Sanitization and classification

Audit before/after/details values are recursively bounded and converted to JSON-safe
data. Passwords, tokens, cookies, authorization headers, MFA/TOTP material, recovery
codes, deletion PINs, keys, and credentials are replaced with `[REDACTED]`. Circular,
binary, unserializable, deep, and oversized values are safely represented or
truncated. The same sanitized representation is used for exports.

Classifications are `public`, `internal`, `confidential`, `restricted`, and `secret`.
Audit data defaults to confidential. Restricted and secret values may not be written
to ordinary logs; use encrypted storage and expose only fingerprints or metadata.
Operational IP addresses remain available to authorized audit viewers and follow the
tenant audit retention policy. No geolocation is collected.

## Retention, legal holds, and archives

Tenant policies define default, security, administrative, authentication, export,
and archive retention. Critical classes cannot be configured below the platform
minimum (90 days by default). Active legal holds filter by date, category, and
resource and stop purge. Holds are immutable except for a one-way active-to-released
transition; release does not trigger immediate purge.

Retention processing is tenant-scoped and bounded to 500 records. It only purges a
contiguous chain prefix and stops at the first held or ineligible record. When
enabled, the prefix is archived first as compressed JSONL containing a manifest,
checksums, tenant/date/sequence metadata, and sanitized records. Local filesystem
storage is the current implementation; the interface can later support object
storage. Celery tasks exist, but scheduling remains an operator decision.
Set `AUDIT_ARTIFACT_ENCRYPTION_ENABLED=true` to encrypt local archive and export
artifacts with the current versioned encryption key; downloads are decrypted only
after tenant, permission, token, state, and expiration checks.

## Exports

CSV, JSONL, and evidence-package ZIP jobs preserve the exact authorized filters.
Evidence packages contain JSONL, integrity results, a manifest, and checksums.
Artifacts use opaque tenant/job identifiers, never personal data. Download requires
both `audit.export.download` and an expiring random authorization token. Paths are
never returned. Expiration removes artifacts. The legacy `/audit-logs/export`
endpoint remains for compatible moderate exports; new clients should use jobs.

## Encryption and rotation

Encrypted JSON uses authenticated Fernet encryption with an embedded `vN:` version.
`ENCRYPTION_KEYS_JSON` is a JSON object such as `{"1":"...","2":"..."}` and the
current version is selected by `ENCRYPTION_CURRENT_KEY_VERSION`. Keep the previous
key while old rows exist. MFA and connector credential rows persist key versions.
Rotation is explicit through the owner-protected operation; it is never run at
startup and audit records contain counts/version only, never plaintext or keys.
Decryption failures return `DECRYPTION_FAILED`.
Version 1 remains backward-compatible with the existing derived-key abstraction when
no key ring is configured. A version greater than 1 requires an explicit key ring.

## Detection and permissions

Five serious denied/failed administrative actions by one actor in 15 minutes create
a high-severity `REPEATED_ADMIN_DENIALS` security event with cooldown deduplication.
Integrity failure creates a critical `AUDIT_INTEGRITY_FAILED` event.

Permissions: `audit.view`, `audit.export`, `audit.integrity.verify`,
`audit.retention.manage`, `audit.legal_hold.view`, `audit.legal_hold.manage`,
`audit.archive.manage`, `audit.export.download`, `data_protection.view`,
`data_protection.manage`, and `encryption.rotation.execute`. Administrators do not
automatically receive retention, legal-hold management, archive management, or data
protection management. Encryption rotation is owner-only.

## Stable errors

The APIs use `AUDIT_EVENT_INVALID`, `AUDIT_INTEGRITY_FAILED`,
`RETENTION_MINIMUM_REQUIRED`, `LEGAL_HOLD_NOT_FOUND`,
`LEGAL_HOLD_ALREADY_RELEASED`, `ARCHIVE_JOB_FAILED`, `EXPORT_JOB_NOT_FOUND`,
`EXPORT_NOT_READY`, `EXPORT_EXPIRED`, `EXPORT_DOWNLOAD_DENIED`, and
`DECRYPTION_FAILED`. Cross-tenant job/hold lookups return 404.
