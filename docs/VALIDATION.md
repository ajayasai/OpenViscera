# Initial validation and competitive acceptance plan

Evaluation date: **5 September 2026**. Release: **0.1.0**. Dataset: generated synthetic cases only. This is developer-run validation, not independent clinical acceptance, penetration testing, accreditation or a head-to-head comparison with proprietary systems.

## Executed results

**105 passed in 26.20 seconds; 96% Python statement coverage (rounded), 1,195 of 1,244 statements covered.** Environment: Linux, Python 3.13.5, FastAPI 0.128.2, Pydantic 2.13.4, cryptography 46.0.4, ReportLab 4.4.9, pytest 9.0.2. Timings are observations from this environment, not performance guarantees.

| Validation area | What was exercised |
| --- | --- |
| Complete lifecycle | Collection, request, sealing, account/external dispatch, receipt, report upload, review, draft, independent approval, issue, supplementary handling. |
| Evidence freshness | Unreviewed/latest report checks, explicit supersession, duplicate-byte rejection, stale approvals, exact report coverage and revision-triggered reopening without changing the issued record. |
| Custody | Wrong sender/recipient rejection, no unsealed dispatch, no duplicate acknowledgement, timestamp ordering, automatic seal discrepancy and independent resolution. |
| Linking and uniqueness | Wrong-case and wrong-specimen attachments, laboratory scope, normalized container duplicates across cases, examination duplicates. |
| Authorization | Seven roles, all auditor mutation denials, assigned examiner restrictions, department isolation, laboratory-filtered data/downloads, self-approval rejection. |
| Concurrency | Version conflicts, idempotent retries and 16 simultaneous competing writes with exactly one winner. |
| Tampering | Event/projection changes, invalid signatures, administrative/identity changes, session injection, missing/modified blobs, damaged uniqueness registry, truncated ledger. |
| Portable verification | Pinned keys and heads, changed archive members, path traversal, exact member/hash checks, deterministic case replay. |
| Recovery | Authenticated encrypted backup and verified restore, incorrect passphrase/tamper rejection, overwrite refusal, restored-session invalidation. |
| Web security | Authentication, CSRF, Origin/Host checks, secure-cookie mode, session revocation, persistent throttling, oversized and chunked request bodies, upload format/path restrictions, sanitized validation errors. |
| Browser | Actual Chromium forms connected to the actual API through the in-process test harness; multi-account complete workflow, report revision, no observed JS errors, desktop and 390-pixel mobile rendering without horizontal overflow. |
| Documents/package | Five administrative PDF types generated, rendered and visually inspected; wheel and source distribution built locally; three static UI assets verified inside the wheel; JavaScript syntax check passed. |

Commands used for the full test run:

```bash
OV_BROWSER_TEST=1 OV_BROWSER_INPROCESS=1 OV_CHROMIUM=/usr/bin/chromium \
  OV_SCREENSHOT_DIR=/tmp/openviscera-screenshots \
  pytest tests --cov=openviscera --cov-report=term \
  --cov-report=json:/tmp/coverage.json --junitxml=/tmp/junit.xml
node --check src/openviscera/static/app.js
```

The local browser policy blocks all HTTP navigation. It was not changed. The alternative harness renders the real HTML/CSS/JavaScript in memory and binds browser fetch to a FastAPI TestClient against the real store. This validates UI behavior and application responses, **not** browser enforcement of network cookies, TLS, Origin, CSP or a deployed reverse proxy. Those server controls have separate API tests. The normal HTTP Chromium workflow remains in the test suite and CI definition for a network-enabled environment.

An early browser run found an HTML boolean-attribute bug that made the discrepancy checkbox required; that bug was fixed and the full browser workflow rerun successfully. PDF rendering uses deployment-supplied fonts when configured; non-Latin scripts and physical printers were not validated.

## Not established by these results

No licensed commercial comparison, external penetration test, clinical pilot, regulatory/legal compliance assessment, high-availability test, production volume benchmark, Windows/macOS execution, non-Latin shaping validation, physical barcode-scanner test, malware-scanning integration, or live laboratory integration was performed. Docker and reverse-proxy execution were not verified in the initial environment. CI configuration alone is not evidence that a hosted run has passed.

Coverage is statement coverage, not branch or mutation coverage. A passing safety test proves only the scenarios tested. Service-key signatures are not individual qualified signatures or externally trusted timestamps. Full host/key compromise and whole-deployment rollback without external checkpoints remain outside the protection claim.

## Compare fairly with existing systems

Public product descriptions establish that [LabVantage supports pathologists and medical examiners](https://www.labvantage.com/blog/pathologists-and-medical-examiners/) and [Forensic Advantage offers medical-examiner case management](https://www.forensicadvantage.com/medical-examiner-edition). [SENAITE](https://www.senaite.com/) already supplies open-source laboratory management. These are product descriptions, not independent evidence that any competing product lacks OpenViscera's controls. Their licensed configurations were not inspected.

OpenViscera's implementation can be inspected and tested without commercial licensing. The proposed differentiators are department-side external-lab reconciliation, explicit report-to-opinion freshness, independently verifiable full evidence exports, and a small self-hosted stack. **Superiority is a hypothesis requiring comparative evaluation, not a release claim.**

For a meaningful evaluation, pre-register the same synthetic case set and scripts for every evaluated system/configuration. Include missing acknowledgements, seal mismatches, two specimens with similar identifiers, wrong-case uploads, late reports, superseding reports after issue, concurrent receipt entry, absent examiner, independent approval, disabled users, complete export and verified recovery. Do not give one product a simplified scenario or assume configuration gaps are product impossibilities.

Measure task completion and correction rates, unsafe transitions actually blocked, operator time/clicks, training time, audit/reconstruction completeness, vendor-independent export verification, restore success and recovery time, median/p95 latency under specified concurrency and database size, operational burden, accessibility and deployment cost. Have forensic practitioners and security reviewers score outcomes blind where feasible. Publish scripts, synthetic data, exact versions/settings, failures and uncertainty. Only then make a bounded claim such as "lower median reconciliation time on this benchmark," not "better than all alternatives."

## Highest-priority work before institutional production

Complete structured corrections/retractions, external specimen returns and late additional-examination receipt transitions; agree interim-opinion/exclusion policy; add restricted-case ACLs, SSO/MFA and password lifecycle; build an appropriate malware quarantine/release pipeline; implement complete access auditing, key rotation and database migrations; validate non-Latin PDFs and label printers; establish approved retention/hold/disposal behavior; conduct external security and forensic-practitioner review; measure realistic capacity and consider PostgreSQL/object storage only with preserved atomicity and verification guarantees.
