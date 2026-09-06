# Changelog

## 0.2.0 — 2026-09-06

Added restricted-case membership, signed HTTP access auditing with fail-closed sensitive responses, independently reviewed corrections and report withdrawals, issued-opinion withdrawals, documented external returns, additional examination acceptance, previewed atomic dispatch batches, permission-checked specimen lookup, password changes with session revocation and throttling, and an explicit additive migration preserving frozen v1 event semantics.

Added browser controls and expanded the real Chromium workflow. The local suite passed 169 tests with 97.03% statement coverage. A synthetic 25-container microbenchmark showed a 7.13× median service-operation improvement for atomic batches over individual handovers; no commercial comparison or production-capacity claim is implied.

Existing v0.1 stores require a stopped-service backup and explicit `openviscera migrate`. Original case projections, issued texts and signatures are preserved. See `docs/V02-UPGRADE.md` for scope, access policy, failure/retry behavior and remaining limitations.

Historical dispatch PDFs now replay the original dispatch snapshot, so later approved metadata corrections cannot silently rewrite a previous covering letter.

## 0.1.0 — 2026-09-05

Initial specimen dispatch and pending-opinion pilot: collection/sealing, recipient or documentary external receipts, report revisions, independent opinion approval, signed evidence exports, encrypted backup/restore, seven work queues and browser/API tests.

