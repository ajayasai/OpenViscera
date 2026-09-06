# Architecture and verification

## Components

`models.py` defines strict command contracts. `domain.py` is the version-2 deterministic, I/O-free reducer and opinion gate; `domain_v1.py` is frozen for historical verification. `governance.py` supplies atomic dispatch batches, password changes and HTTP access auditing; `migrations.py` supplies the explicit additive upgrade. `store.py` owns authorization, signed identities, SQLite transactions and replayable case events. `app.py` supplies the same-origin FastAPI API, queues and security middleware. `evidence.py` verifies and exports evidence and performs encrypted backup/restore. `documents.py` creates administrative PDFs. `static/` is a dependency-free, responsive browser workbench. `cli.py` provides local administration; `demo.py` creates synthetic fixtures only.

There is one SQLite database plus an Ed25519 signing key and separately retainable public key. Attachment bytes reside in the database, scoped by department and content hash, so evidence metadata, bytes, event and current projection commit atomically. Database foreign keys, WAL and full synchronous mode are enabled. Use a local filesystem, not a shared network filesystem, and one application process for the evaluated configuration.

## Write path

Authenticate → verify signed session and current identity → check CSRF/origin → authorize department, role and assignment → begin immediate transaction → resolve idempotency key → verify expected version and current signed projection → validate strict command → apply pure reducer → enforce normalized container uniqueness → store attachment if present → sign event → append event and update projection → commit.

Each event includes schema, case ID, sequence, event ID, actor identity, recording time, action, validated data, previous hash and resulting-state digest. The signature covers canonical sorted compact UTF-8 JSON. All case mutations are append-only at the API; triggers reject SQL update/delete of ledger rows. Issued opinion content, approval identity, issue timestamp and report references remain unchanged after subsequent evidence arrives.

Read operations verify event hashes/signatures and the projection against the latest signed digest. Full export and database audit additionally replay all events with the reducer and hash all attachments. These checks detect database-only alteration; they do not defend against an attacker possessing the signing key or prove the physical truth of entries.

## Opinion readiness

All specimens must have requested examinations; every request needs a laboratory receipt and its latest report reviewed. Pending transfers and unresolved discrepancies block approval and issue. The draft must reference exactly the current report set, its evidence fingerprint must still match, the approver must differ from the author, and only the assigned examiner may issue. The first issue is final; later issues are supplementary.

The fingerprint covers case metadata, specimen and seal state, requests, transfers, reports, attachments and substantive notes. It also covers correction, report-withdrawal and opinion-withdrawal control histories. It excludes access-policy changes, ordinary opinion actions and administrative follow-ups. A new attachment or note conservatively makes a previous draft/approval stale, even before a new report has been registered. Review and approval are not the same act. A later report never inherits the review or approval of the version it supersedes.

## Portable bundle

ZIP members are `case.json`, `events.json`, `files/<sha256>`, `manifest.json` and `manifest.sig`. The signed manifest specifies format, public key, exact member names, sizes, hashes, event count and head. Verification rejects unexpected, duplicate, missing, excessive and unsafe members and never extracts ZIP paths. It replays the signed history and compares the final case projection.

The verifier requires an externally trusted public key. Optional `--expected-head` pins a separately retained case checkpoint. Without that checkpoint, a genuinely signed older bundle still verifies. The administrative checkpoint command emits all case heads and administrative head with a deployment signature for separate retention; it does not upload them to an external service.

## Boundaries and compatibility

Seven staff roles are enforced server-side. Lab users see only requests for their laboratory and associated permitted reports/attachments, not departmental opinions or complete case exports. Cases default to department-wide access, but v0.2 supports restricted named membership without an administrator clinical-read bypass. Lists, counts, queues, attachments, exports and scanner lookup share the same checks. Audit administrators/auditors have a separate explicit permission to inspect department-wide request metadata, not restricted case contents.

The API uses random HTTP-only cookie sessions plus CSRF tokens, not tokens in browser local storage. Exports and attachment downloads require authentication and are returned as downloads. JSON OpenAPI and command schemas are available to authenticated users at `/api/schema`; interactive public API documentation is disabled.

New stores use database schema 2. The explicit migration adds access-audit storage while preserving original case rows, signatures and keys. Schema-1 events use the frozen original reducer; schema-2 events use the extended rules. Version downgrade inside an event stream is rejected. A successful migration verifies unchanged case heads. Further format changes still require explicit versioned migrations and historical-bundle tests; do not modify the frozen reducer or reinterpret signed old events.
