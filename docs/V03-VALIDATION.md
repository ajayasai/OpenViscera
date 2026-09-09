# v0.3 validation results

Date: 7 September 2026. Release: 0.3.0. Original repository baseline: `78608c4dfe442a799e47bb809be09e7ccd424941`. All case data, certificates, staff identities and credentials used in these tests are synthetic. This is developer-run validation, not independent clinical acceptance, penetration testing, accreditation or a licensed commercial-product comparison.

## Executed local results

**221 tests passed in 64.76 seconds. Python statement coverage: 97.60% (1,911 of 1,958 statements).** Both real Chromium journeys were included. The current schema-3 reducer executed all 185 statements, but this is statement coverage, not exhaustive branch/state-space coverage.

The baseline was rerun before changes: 168 passed and one opt-in browser test skipped, with 96% rounded statement coverage. The earlier release separately recorded 169 passing tests with its browser enabled; [that historical record](V02-VALIDATION.md) is preserved. This upgrade adds 40 dedicated lifecycle/authorization/migration/recovery tests, 11 automatically expanded command-denial cases and one additional Chromium journey: 52 additional tests relative to the earlier 169-test full suite.

Executed commands:

```bash
PYTHONPATH=src OV_BROWSER_TEST=1 OV_BROWSER_INPROCESS=1 \
  OV_CHROMIUM=/usr/bin/chromium OV_SCREENSHOT_DIR=/tmp/v03-browser \
  pytest --cov=openviscera --cov-report=term-missing \
  --cov-report=json:/tmp/v03-coverage.json --junitxml=/tmp/v03-junit.xml
node --check src/openviscera/static/app.js
node --check src/openviscera/static/controls.js
node --check src/openviscera/static/lifecycle.js
PYTHONPATH=src python -m compileall -q src
```

Environment: Linux, Python 3.13.5; pytest 9.0.2, FastAPI 0.128.2, Starlette 0.50.0, Pydantic 2.13.4, cryptography 46.0.4, httpx 0.28.1, Playwright 1.57.0, ReportLab 4.4.9. Runtime is an observation under this environment, not a capacity/performance guarantee. Dependencies are bounded in pyproject.toml but not a deployment lock file.

## What was exercised

| Control | Executed evidence |
| --- | --- |
| Retention | Missing instruction, unelapsed deadline, proposed shortening, independent approval, pending changes, date before collection and naive timestamps. Existing issued opinion is unchanged by administrative retention history. |
| Preservation | Specimen and case-wide holds, future specimens under a case hold, independent release, release rejection and the rule that a request is not a release. |
| Disposal | Full proposal/approval/certificate/completion; matching proof and actual-time bounds; missing approval; no auto-execution on expiry; approved/current-evidence requirements. |
| Approval freshness | Intervening evidence, policy, hold/release history and inactive reviewer checks; stale proposal cancellation and fresh reapproval. Reverting a hold does not revive old approval. |
| Concurrency | Competing hold and completion against one expected version have exactly one committed winner. Idempotent retry returns the original event without double disposal. |
| Physical closure | New request, handover, reseal and return actions reject after disposal. Original specimens/transfers/reports/opinions remain unchanged. Later reports reopen opinion work without physical resurrection. |
| Reassignment | Active examiner/department/explicit membership constraints; target deactivation rechecked at approval; pending assignment blocks opinion approval; old issued text remains intact while supplementary work reopens. |
| Access boundaries | Forbidden roles, laboratory views, certificate upload/download restrictions, restricted-case queue and scanner behavior, plus all original v0.2 access-audit and restricted-case tests. |
| Replay/migration | Byte-for-byte frozen v2 reducer digest; actual signed schema-2 records and issued opinions survive migration; old exported bundle verifies; new events append as schema 3; all original v1 migration tests remain enabled. |
| Recovery | Encrypted backup/restore preserves completed disposition, administrative certificate and original case history; full database/signature/replay verification succeeds. |
| Browser | Original v0.2 journey plus actual retention/hold/release/disposal/certificate/reassignment forms, multi-account decisions, unavailable physical actions and pending supplementary opinion. No observed JavaScript errors. Mobile page has no document-level horizontal overflow at 390 pixels; history tables scroll internally. |

The browser run exposed native datetime-input step validation rejecting fractional seconds. The shared input now accepts valid fractional-second timestamps; the completed workflow was rerun successfully. A separate authorization review found a pending-disposal completion path could look up a nonexistent approver before the domain rejection. It now rejects with the normal workflow conflict response, with a regression test.

## Browser transport and hosted validation

This local environment blocks browser navigation to a local HTTP service. The real HTML/CSS/JavaScript ran in Chromium with an in-process binding to the actual FastAPI app and store. This tests UI/application behavior, not real TLS, reverse-proxy settings, cookie enforcement or the browser's network/CSP path. Separate HTTP API tests exercise server controls.

**Hosted execution succeeded on 7 September 2026.** GitHub Actions pull-request run [34085674973](https://github.com/ajayasai/OpenViscera/actions/runs/34085674973), for implementation commit `8af8ea80c41d154a334f13048c59b77a09e3cf73`, completed successfully at 05:10:19 UTC. All four jobs passed: Python 3.11, 3.12 and 3.13 unit/API/replay/coverage/package jobs, and the Chromium job running both browser journeys over ordinary HTTP. Each Python job also passed compilation, all three JavaScript syntax checks and `python -m build`. The matching push run [34085653414](https://github.com/ajayasai/OpenViscera/actions/runs/34085653414) also succeeded.

This verifies the hosted browser network path in addition to the local bridge. It does not verify a production TLS/reverse-proxy deployment or constitute an independent security audit. The exact 221-test/97.60% figures above are from the retained local full-suite output, not inferred from GitHub's job-status summaries. Documentation-only commits may follow the implementation commit; their own CI status is visible in the pull request.

## Remaining validation work

No commercial head-to-head benchmark, external security audit, clinical pilot, jurisdiction-specific legal validation, HA test, realistic production-load benchmark, live laboratory/instrument integration, malware pipeline, hardware scanner/printer study or production TLS deployment was performed. This change does not establish better performance than commercial systems or even a measured large-department capacity for OpenViscera.

Physical disposal is a human-documented external action. There is no equipment integration or independent on-site witness countersignature; administrative certificate classification is human-entered and must not conceal clinical evidence. Whole-deployment rollback, old valid exports and private-key compromise remain outside the protection of an internally signed ledger alone.

See [the operating/upgrade guide](V03-UPGRADE.md) and [the primary-source comparison and pre-registered acceptance protocol](V03-COMPETITIVE-REVIEW.md). Retain raw logs, JUnit, coverage and screenshots with each evaluated build.
