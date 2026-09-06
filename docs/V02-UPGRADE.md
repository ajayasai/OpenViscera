# v0.2 upgrade and operating boundaries

## Existing v0.1 stores

Stop the service and retain a verified backup and external checkpoint before upgrading. v0.2 refuses to serve a schema-1 store until migration is explicitly requested.

```bash
# After installing the v0.2 checkout; use a new backup filename.
openviscera backup --data ./var --output /secure-location/pre-v02.ovb
openviscera migrate --data ./var
openviscera audit --data ./var --output /separate-location/post-v02-checkpoint.json
```

The migration adds the HTTP access-audit table and triggers, advances the database schema, and records a signed administrative migration event. It does not rewrite case projections, existing event signatures, issued opinions or private keys. Old events replay through the frozen `domain_v1.py`; new events are schema 2. A case can contain a schema-1 prefix followed by schema-2 events; downgrade back to schema 1 is rejected during verification. The original v1 reducer has an explicit regression digest.

Migration checks the existing database first and compares case ledger heads afterwards. Migration DDL and the administrative event are in one transaction. Repeating a completed migration is a no-op. A restored v1 backup must also be migrated before serving. Restores preserve the existing session-invalidation behavior.

This is not a general migration framework, automatic rolling upgrade, bidirectional downgrade or key-rotation scheme. Do not reopen a schema-2 store with an old server. Store owners must stop every old writer before migration.

## Restricted cases

An assigned examiner or an administrator who already has access may switch a case to restricted named members. The assigned examiner and the policy author must remain members; explicitly include a suitable independent reviewer and required coordinators/couriers/laboratory staff. Cross-department and disabled accounts cannot be granted membership. Normal role and assignment restrictions still apply after membership is granted.

There is no implicit administrator access to restricted clinical case contents, no self-service break-glass bypass and no unrestricted administrator regrant endpoint. Plan membership and recovery procedures before restricting a record. Access changes do not themselves alter the clinical evidence fingerprint. Revocation immediately affects subsequent reads, exports, lookup and idempotent command replays. Accounts and contact-directory metadata remain department scoped rather than case scoped.

Department administrators and auditors may inspect department-wide access-audit metadata, including opaque case IDs, even for cases they cannot clinically open. The audit does not store case references, narratives, filenames, query strings, passwords or cookies. Anonymous failures have a separate chain and are verified by the local audit command, not included in a department's HTTP audit view.

## Corrections and withdrawals

Corrections can change specimen description, recorded preservative, quantity or unit, or requesting-authority text. A proposed correction preserves the effective old value until another reviewer approves it; the event history retains both values and both identities. It cannot relabel containers, rewrite custody timestamps, move evidence to a different case or rewrite an issued opinion. Competing changes are checked against the proposal's exact original value.

A report-withdrawal proposal makes that report disputed immediately. Independent approval confirms withdrawal; rejection preserves the report as usable, but the intervening evidence/control history conservatively invalidates old opinion fingerprints. A withdrawn latest report never makes an older revision current automatically. A replacement must explicitly supersede the actual latest revision. An issued opinion can be marked withdrawn immediately by the assigned examiner or an authorized reviewer. Its text and original approval/issue facts remain unchanged. Generated opinion PDFs show the withdrawal warning.

There is no automatic recall of copies previously downloaded or sent outside this application. An old correctly signed export still verifies cryptographically; independently retained recent heads are needed to recognize stale exports. Withdrawal is a workflow fact, not a qualified electronic revocation service or a legal conclusion.

## Returns and additional examinations

An evidence-backed external return records the external sender's name and the authenticated receiving department user. An observed changed seal is recorded as an external seal observation, not a claim that the local receiver applied it. Mismatches and pre-existing discrepancies remain quarantined until an independent decision resolves them.

An additional examination can be explicitly accepted when the specimen is already recorded at that laboratory. Laboratory staff may authenticate acceptance for their own lab; department staff must attach matching documentary confirmation. No new physical handover is fabricated. Acceptance time must follow the additional request's creation and a pending outbound handover blocks the operation.

## Atomic batches and lookup

The browser batch form requires a successful non-mutating preview before enabling commit. The backend rechecks all items in the commit transaction; the preview is not a reservation. A version conflict or invalid item causes no partial dispatch. Each container retains its own signed event and remains pending acknowledgement. The batch limit is 100 containers and supports one case per batch, not arbitrary cross-case bulk operations.

The scanner workflow accepts a container identifier or `openviscera:specimen:<opaque-id>` from a keyboard-input scanner. Camera capture and physical scanner/printer hardware have not been validated. Server-side access and laboratory-scope filters apply to both forms of lookup.

## Access audit semantics

Handled HTTP API responses, including sensitive reads/exports and authentication/authorization failures, are appended to signed per-department chains before response release. List/dashboard requests include the accessible case IDs used for the result. If durable audit append fails, the client receives 503 instead of sensitive bytes. A write may already have committed before its response is withheld: retry workflow writes with the same idempotency key; inspect state before retrying other administrative operations. An audit record shows the response was prepared for release, not proof that a remote client received every byte.

The local CLI, direct service calls, filesystem reads, database administration, process crashes and reverse-proxy/pre-application failures are not a complete operating-system access-audit system. Full read/export traffic now writes the access ledger, increasing SQLite write volume. Local audit verifies every chain; independent checkpoints remain necessary to detect whole-ledger rollback. An attacker with the deployment private key can still forge signatures.

## Remaining production gaps

SSO/MFA, forgotten-password recovery, administrator password reset, full case-assignment transfer, general restricted-case recovery, approved malware scanning/content disarm, high availability, measured large-department capacity, institutional retention/disposal policy, thermal-printer templates, key rotation and integrations with actual laboratories/instruments remain unimplemented or unvalidated. Password change requires the current password, revokes all sessions, and throttles incorrect current-password attempts. The SQLite database still needs host-level encryption and access control. Public source availability and passing tests do not establish clinical validation, regulatory compliance or superiority to every commercial alternative.
