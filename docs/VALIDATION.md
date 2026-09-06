# v0.2 validation results

Date: 6 September 2026. Release: 0.2.0. Data: synthetic cases only. This is developer-run validation, not independent clinical acceptance, penetration testing, accreditation or a licensed commercial-product comparison.

## Executed local results

**169 passed in 47.21 seconds. Python statement coverage: 97.03% (1,636 of 1,686 statements).** This includes the expanded Chromium workflow and 55 dedicated v0.2 tests, plus additional denial cases automatically added to the role matrix. The original event reducer remains byte-for-byte frozen and has a regression digest.

```bash
PYTHONPATH=src OV_BROWSER_TEST=1 OV_BROWSER_INPROCESS=1 \
  OV_CHROMIUM=/usr/bin/chromium OV_SCREENSHOT_DIR=/tmp/ov-screenshots \
  python -m pytest tests --cov=openviscera --cov-report=term-missing \
  --cov-report=json:/tmp/coverage.json --junitxml=/tmp/junit.xml
node --check src/openviscera/static/app.js
node --check src/openviscera/static/controls.js
```

The local environment uses Linux and Python 3.13.5. Library versions are captured in the release evidence bundle. Timing is an observation, not a performance guarantee. Statement coverage does not imply branch coverage, mutation coverage, or absence of security defects.

## What the new tests establish

| Area | Executed checks |
| --- | --- |
| Restricted cases | Direct reads, list totals, dashboard counts, attachments, PDFs, full exports and QR/container lookups cannot disclose restricted case contents to excluded staff. Administrators have no automatic clinical-read bypass. Revoked users cannot obtain the case through idempotent command replay. |
| Authorization | Duplicate, cross-department, disabled and missing-owner memberships rejected. Handover recipients must have explicit access to restricted cases. Independent decisions reject the proposer, including under a hypothetical role change. |
| Controlled corrections | Original field is unchanged until approval; before/after provenance retained; rejection, stale expected values, duplicate proposals, wrong fields and invalid numeric corrections tested. |
| Withdrawals | A disputed or withdrawn latest report cannot be reviewed or satisfy readiness; no automatic fallback to an older revision; replacements supersede the actual latest revision. Issued opinion withdrawal preserves the original text/approval and reopens work. |
| External laboratories | Documentary return restores recorded department custody; changed seals remain discrepancies; additional examination acceptance records no fictional physical transfer and requires matching proof for staff transcription. |
| Batches | Preview changes no case state, commit retains one signed event per specimen, retries are idempotent, invalid later items reject the entire batch, and two concurrent batches have exactly one winner. |
| Access audit | Reads, exports and handled denials recorded with route templates and opaque IDs; sensitive bodies, passwords and query strings absent; invalid signatures detected; a failed audit append withholds clinical responses; committed writes remain safely retryable by idempotency key. |
| Password changes | Current password required, incorrect attempts throttled, every old session revoked, old password rejected afterwards. |
| Migration/recovery | Original schema-1 signatures, issued projection and exported bundle preserved; schema-2 events append after migration; repeat migration is a no-op; failed migration rolls back; v1 backups can be restored and migrated. |
| Browser | Original lifecycle plus restriction, independent correction and withdrawal, external return, preview/commit batch, specimen lookup, password change and audit page. No observed JavaScript errors; 390-pixel layout has no document-level horizontal overflow. |

A browser run found horizontal overflow after extra account/lookup actions were added. The mobile header was fixed and the browser suite rerun successfully. Audit tables deliberately scroll within their own container on narrow screens.

## Browser transport limitation

This environment blocks browser HTTP navigation to local services. The real HTML/CSS/JavaScript ran in Chromium and called the real FastAPI app/store through the test suite's in-process transport. This validates UI and application behavior, not browser enforcement of TLS, production cookies, CSP or reverse-proxy configuration. The server controls have separate API tests. GitHub Actions is configured to exercise the normal HTTP browser path on hosted runners; only an actually completed successful run should be cited as hosted validation.

## Dispatch microbenchmark

Command: `PYTHONPATH=src python tools/benchmark_dispatch.py --specimens 25 --repeats 5`.

| Variant | Transactions | Signed events | Median timed service operations |
| --- | ---: | ---: | ---: |
| Individual handover commands | 25 | 25 | 264.4 ms |
| One atomic batch | 1 | 25 | 37.1 ms |

The median ratio was **7.13×**. Both variants retained pending recipient acknowledgements and passed full signed replay after every run. The same quiescent synthetic store was copied for each trial; trial order alternated. Setup, login, HTTP/TLS, operator time and post-run audit were outside the timer. The raw five-run arrays, environment and implementation are supplied. This result compares two OpenViscera execution paths, not OpenViscera with a commercial product, and is not a large-department capacity benchmark.

## Deliberately unproven

No licensed head-to-head product test, external penetration test, clinical pilot, regulatory certification, high-availability test, production-load benchmark, physical scanner/printer test, Unicode shaping study, malware-scanning integration or live laboratory/instrument integration was completed. Container/TLS-proxy execution was not validated locally. Old correctly signed bundles can be stale; whole-deployment rollback and key compromise still need controls outside the application.

Read the [primary-source competitive review](V02-COMPETITIVE-REVIEW.md) and [upgrade/security boundaries](V02-UPGRADE.md). Future comparisons should use pre-registered scenarios and report unsafe transitions, operator effort, audit reconstruction, recovery, failure modes and uncertainty—not an unsupported claim to be better than every alternative.
