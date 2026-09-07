# v0.3 upgrade and operating boundaries

## Upgrade existing installations

Stop every old writer. With the existing release, back up the deployment and retain a separately trusted public key and recent external checkpoint. Install v0.3 into a separate environment, test a restored copy, then run:

```bash
openviscera migrate --data ./var
openviscera audit --data ./var --output /separate-location/post-v03-checkpoint.json
openviscera serve --data ./var
```

This supports schema 1 or 2 directly to schema 3. The schema-1 route adds the existing access-audit tables; both routes change the schema marker and append a signed administrative migration event. Case projections, event bytes, signatures, case heads, original issued opinions and keys are not rewritten. Migration verifies the database before and after and checks unchanged case heads. Repeating migration is a no-op.

`domain_v1.py` and `domain_v2.py` remain byte-for-byte historical reducers. New events use schema 3; verification accepts an old prefix followed by new events but rejects backwards schema transitions. Pre-upgrade bundles remain verifiable by v0.3. An older verifier will not understand new schema-3 events. Do not downgrade a store or run old/new writers together. This is not rolling migration, key rotation or high availability.

## Who can act

Existing case membership, department, laboratory and signed-session controls apply before any new command. A restricted case has no implicit administrator clinical-access bypass.

| Action | Role and additional gates |
| --- | --- |
| Propose examiner reassignment | Administrator/coordinator with case access, or the assigned examiner; target is an active department examiner with explicit restricted-case membership. |
| Propose retention/change | Coordinator or assigned examiner. |
| Place preservation hold / request release | Examiner, coordinator or reviewer with case access. |
| Decide reassignment, retention, hold release or disposal | Reviewer with case access; never the proposal/request author. |
| Propose/record disposal | Examiner or coordinator who is the active, recorded local custodian. |
| Cancel pending/approved disposal | Examiner, coordinator or reviewer with case access; cancellation does not erase history. |

Disposal approval requires an active local examiner/coordinator custodian, not a courier or a remote laboratory holder. Completion rechecks that the original approver still has active reviewer access. A deactivated or excluded approver requires cancellation and a fresh proposal/approval.

## Retention and preservation

There are no built-in legal retention periods. A human supplies a date, policy/authority reference and rationale. Every instruction, including a proposed extension or shortening, needs independent approval. The previous approved instruction stays effective while a proposal is pending, and any pending change blocks disposal. A rejected proposal remains visible. A retention date before collection is invalid.

A preservation hold takes effect immediately and does not block ordinary testing or opinion work. A specimen hold applies only to that container; a case hold also applies to specimens added later. Holds need not have an automatic end date. To release a hold, record a release request with authority/reference and rationale; a different reviewer must approve. Rejection or a pending request leaves the hold active. A new physical specimen hold cannot be placed on a specimen already recorded as disposed. A case hold cannot recover material previously disposed.

Retentions, holds and hold releases are signed administrative history. They do not alter an already issued medical opinion's evidence fingerprint by themselves. All remain in the portable bundle and chronology.

## Disposal: gates, not automatic destruction

The application never determines lawful disposal authority or scientific suitability and never operates physical equipment. Verify applicable institutional and external authority separately.

1. The approved retention deadline must have elapsed; no retention change may be pending.
2. No applicable case or specimen hold may remain active.
3. The specimen must be sealed, in an active local department custodian's possession, and all case custody/report/review blockers must be clear.
4. A current issued opinion must cover the current case evidence. This conservative release rule requires the entire case to be ready, not just the selected container.
5. The custodian records a disposal proposal with human-entered authority, method and rationale. A different reviewer approves it. Both stages recheck the current gates.
6. Upload a matching original administrative certificate. Only after actual, separately authorized disposal, the recorded custodian records the true completion time and note. The service rechecks gates, approval freshness, approver access and matching certificate in the same transaction.

The completion time cannot precede the approval, retention deadline or last recorded custody, or be in the future. It is a documentary completion record, not an assurance that the physical event actually occurred. This release does not provide a separate on-site witness countersignature. Approval identity is an application account identity under the deployment signing key, not a qualified individual electronic signature.

Evidence, custody, retention history, applicable hold/release history or reassignment changes make a disposal proposal stale. Releasing a subsequently placed hold does not revive the earlier approval. Even a rejected intervening policy proposal remains part of that history. Cancel and create a fresh proposal when stale. This deliberately favors a new human review over convenience.

All transitions use optimistic case versions, idempotency keys and a single database transaction. A concurrent hold and completion cannot both commit against the same version; refresh and re-evaluate the losing request. A hold attempted after a completion is already committed cannot undo the physical completion.

Completed disposal permanently closes physical actions for that specimen: new examination requests, resealing, handovers, acknowledgements and return/receipt records cannot restart it. There is no undo button and no in-place rewriting of physical history. Erroneous completion records require institutional incident handling; an exception/correction workflow for that status is not supplied. Original specimens, transfers, reports, opinions, attachments and event histories are retained. A later report may still arrive, be reviewed and reopen supplementary opinion work; it does not resurrect the specimen.

## Administrative certificates versus evidence

Attachment purpose defaults to `evidence`, maintaining conservative behavior. The dedicated certificate form creates `administrative` attachments. They are hashed, signed, included in backups/exports and visible to authorized department users, but excluded from the clinical opinion fingerprint. This avoids an endless cycle in which attaching the disposal certificate makes the required clinical opinion stale.

Administrative attachments cannot be registered as laboratory reports, and laboratory accounts cannot upload or read them through department-only certificate paths. Classification is human-entered: the software does not recognize document meaning. Misclassifying clinical evidence as administrative could omit it from automatic opinion-staleness detection. Use normal evidence uploads for clinical or interpretive material and review certificate contents as part of the audit. Attachment purpose is immutable; no silent reclassification endpoint is supplied.

## Examiner reassignment

The old assignment stays effective until an independent reviewer approves. Pending reassignment blocks opinion approval and issue. Active status, department, examiner role and restricted-case access are checked again at approval. Grant required named membership separately; reassignment never secretly modifies ACLs. Reassignment does not transfer physical custody.

An approved assignment change preserves original issued opinions and their original author/approver. The assignment participates in the clinical fingerprint, so supplementary opinion work reopens; the newly assigned examiner must explicitly review the history and issue a new human-authored opinion through the usual independent review. Rejection leaves the assignment and existing evidence fingerprint unchanged.

## Queues, visibility and deployment limits

The eighth queue shows missing retention instructions, due review, pending decisions and stale disposal proposals. It is a list of work requiring attention, not disposal authorization. Different users may see different custodian-specific blockers. Restricted cases remain excluded from unauthorized lists, counts, lookups and exports. Laboratory views omit departmental lifecycle control records and administrative certificates; their specimen view only indicates recorded disposal status where that specimen is otherwise visible.

This remains single-process SQLite with no SSO/MFA, forgotten-password reset, HA, live instrument/laboratory integration, malware pipeline, automated notification delivery, external signature service, automatic data erasure, emergency restricted-case bypass or application-level database encryption. Institutional policy review, clinical acceptance, security assessment, actual hardware printing/scanning and realistic deployment/load/recovery tests remain necessary.
