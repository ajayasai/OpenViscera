# OpenViscera

**Every specimen. Every next step.** A self-hosted forensic-medicine department workbench for specimen dispatch, custody reconciliation, external laboratory reports, and pending final or supplementary opinions.

**Status: v0.3.0 — tested retention, preservation and reassignment upgrade; not a clinically validated production system.** Human experts enter preservative details, review results, and write opinions. OpenViscera does not interpret laboratory findings, recommend preservatives, infer causes of death, or generate medical conclusions.

## New in v0.3

OpenViscera now follows the physical specimen beyond the laboratory return, with explicit retention instructions, preservation holds and independently reviewed disposal records. Expiry is a review task, never an automatic destruction trigger.

| Improvement | Implemented behavior |
| --- | --- |
| Retention instructions | Human-entered deadline and authority reference; every instruction or change requires independent review. Pending changes block disposal. No hardcoded legal retention period. |
| Preservation holds | Immediate specimen-specific or whole-case hold, including later-collected specimens. Release requires a documented request and another reviewer; a request alone does not release a hold. |
| Disposal control | Local custodian proposes; independent reviewer approves; custodian records actual completion with a matching original administrative certificate. Gates are rechecked at proposal, approval and completion. |
| Stale-approval protection | Evidence, custody, retention, hold/release or reassignment changes invalidate the proposal. Releasing a later hold does not revive an earlier approval: cancel and propose again. |
| Physical-workflow closure | Completed disposal blocks new requests, resealing, handover and receipt actions for that specimen. Reports, issued opinions, attachments and signed history are never deleted. Later laboratory evidence can still reopen opinion work. |
| Examiner reassignment | Active replacement examiner must already have restricted-case access. Independent approval changes the assignment; previous opinions remain intact and supplementary opinion work reopens. Pending reassignment blocks opinion approval and issue. |
| Eighth work queue | Missing retention instructions, elapsed deadlines, pending decisions and stale disposal approvals are visible alongside the seven existing clinical/dispatch queues. |
| Browser workflows | A dedicated Lifecycle tab exposes every new command, original decisions, blockers and completion history. Department/laboratory access boundaries apply to API, queues and scanner lookup. |
| Historical compatibility | Explicit schema-1/schema-2 to schema-3 migration; both older reducers remain byte-for-byte frozen. Existing case heads, issued records and signatures are unchanged. |

**Validation:** see [the current executed results](docs/VALIDATION.md), [operating semantics and upgrade procedure](docs/V03-UPGRADE.md), and [the primary-source competitive review and acceptance plan](docs/V03-COMPETITIVE-REVIEW.md). The source, tests and workflow are implemented; superiority over commercial products has not been established by a licensed head-to-head test.

The v0.2 release remains documented in [its upgrade guide](docs/V02-UPGRADE.md) and [historical validation record](docs/V02-VALIDATION.md). Its restricted-case permissions, signed access audit, independently reviewed corrections/withdrawals, external returns, atomic dispatch batches and password lifecycle remain in this release.

## What works

| Area | Implemented behavior |
| --- | --- |
| Case and specimen records | Case reference, authority, assigned examiner, priority; container, quantity, unit, description, examiner-entered preservative, collection time and location. Department-wide normalized container uniqueness. |
| Custody | Seal history, current-custodian handover, named-user acknowledgement, evidence-backed external-lab receipt, automatic seal-mismatch discrepancy, independent resolution. Sending is not receiving. |
| Eight work queues | Dispatch, receipt reconciliation, outstanding reports, examiner review, pending opinions, custody discrepancies, manual follow-ups, and storage/retention review. Search and case pagination. |
| Report lifecycle | Received, reviewed and incorporated are separate. Exact specimen/request links, original attachment hashes, explicit supersession, duplicate-byte rejection, preserved old versions. |
| Opinion control | Human-authored drafts, independent reviewer approval, assigned-examiner issue, complete current-report coverage, current-evidence checks at approval AND issue. Later evidence reopens pending work without rewriting an issued opinion. |
| Documents | QR specimen label, dispatch covering letter, handover receipt, chronology and opinion PDF; original evidence downloads; portable signed case bundle. |
| Integrity | Ed25519-signed hash-linked event history; transactionally updated projections; replay verification; signed identity/session records; separately pinnable public key and case head. |
| Access | Seven roles, department boundaries, laboratory-scoped views, server-side permission checks, session revocation, CSRF protection and persistent login throttling. |
| Operations | Generated demo credentials, CLI administration, encrypted backups, verified restore, externally retainable checkpoints, Docker packaging, automated tests. |

The complete source, browser interface, API, tests and deployment documentation are included. There are no commercial feature switches, external analytics, cloud dependencies at runtime, or AI-generated medical opinions.

## Try the synthetic demonstration

Requires Python 3.11 or newer. Run from a terminal:

```bash
git clone https://github.com/ajayasai/OpenViscera.git
cd OpenViscera
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell instead: .venv\Scripts\Activate.ps1
python -m pip install -e .
openviscera demo --data ./demo-data
openviscera serve --data ./demo-data --insecure-local
```

Open `http://127.0.0.1:8000`. The demo command prints a different random password for each synthetic account. Start with `examiner`; use `coordinator`, `lab` and `reviewer` to exercise their distinct steps. `admin` manages users and laboratories, not clinical approvals. `courier` acknowledges its own transfers; `auditor` is read-only. Save the generated passwords privately. No demo or operational credentials are committed to this repository; test fixtures use explicitly synthetic passwords.

The demonstration creates seven synthetic cases, including missing acknowledgements, an unresolved seal discrepancy and a revised report reopening an issued opinion. It refuses to overwrite an existing data directory.

For an empty department, replace `demo` with `openviscera init --data ./var`, then create laboratory and staff accounts through Administration. **Use HTTPS and complete the deployment review before entering real case information.** The loopback-only `--insecure-local` mode is for local evaluation, not network deployment.

## Validate a complete workflow

Create case → collect → request examination → seal → hand over → acknowledge or record documented external receipt → upload/register PDF → examiner review → prepare draft → another account independently approves → assigned examiner issues. Upload a revised report and verify that pending opinion work reopens while the original issued record remains unchanged.

A report may be received before the physical receipt has been reconciled. That does not silently close the missing-receipt queue, and it cannot bypass the opinion gate. Original records are not editable in place: add a clarifying note, a new report revision or a new draft.

## Run tests

```bash
python -m pip install -e '.[dev]'
pytest --cov=openviscera --cov-report=term-missing
python -m playwright install chromium
OV_BROWSER_TEST=1 pytest tests/test_browser.py tests/test_v3_browser.py
```

For PowerShell, set `$env:OV_BROWSER_TEST="1"` before invoking pytest. The browser suite exercises actual forms and the actual API, including different accounts, issuing an opinion, and revision-triggered reopening.

The browser suites cover the original workflow and the new hold/release/retention/disposal and reassignment forms, including a narrow mobile layout. See [validation details](docs/VALIDATION.md) for exact counts, coverage, transport limitations and hosted results. Test success is not clinical acceptance, legal certification or proof of safety against every possible input.

## Verify exported evidence independently

```bash
openviscera verify case-evidence.zip --public-key /trusted/public-key.txt
# A separately retained expected head also detects a stale/rolled-back export:
openviscera verify case-evidence.zip --public-key /trusted/public-key.txt --expected-head EXPECTED_SHA256
openviscera audit --data ./var --output /separate-location/checkpoint.json
```

Trust the deployment public key through a separate channel; accepting a key from the same untrusted ZIP does not establish identity. Signatures authenticate the deployment key, not a legally certified individual signature. A valid old history cannot be distinguished from a rollback without an independently retained checkpoint. A compromised server holding the private key is outside this protection boundary.

## Back up and restore

```bash
openviscera backup --data ./var --output /secure-location/department.ovb
openviscera restore /secure-location/department.ovb --data ./restored-data
```

Backup passphrases are prompted, not accepted as command-line arguments. Backups include the consistent database and signing key, use authenticated encryption, and must be protected. Restore refuses an existing destination, verifies the restored evidence, and invalidates sessions. Test recovery; do not merely test backup creation. This pilot bounds evidence bundles and backups to 100 MiB.

## Honest competitive scope

This is **not** advertised as the first open-source specimen manager or as proven better than every proprietary product. [LabVantage](https://www.labvantage.com/blog/pathologists-and-medical-examiners/) and [Forensic Advantage](https://www.forensicadvantage.com/medical-examiner-edition) address broader established forensic workflows; [SENAITE](https://www.senaite.com/) already provides open-source laboratory management. No licensed head-to-head product evaluation has been performed.

OpenViscera's implemented focus is the department-side gap around external laboratories: explainable queues, acknowledgement reconciliation, evidence-linked review, stale-opinion protection and independently verifiable exports. [The comparison and acceptance plan](docs/V03-COMPETITIVE-REVIEW.md) defines how to evaluate these advantages without inventing competitor limitations.

## Documentation and limits

[Workflow and permissions](docs/WORKFLOW.md) · [Architecture](docs/ARCHITECTURE.md) · [Deployment and recovery](docs/OPERATIONS.md) · [Validation](docs/VALIDATION.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

Known limits include SQLite/single-process deployment, no HA or measured large-department capacity, no SSO/MFA or forgotten-password recovery, no antivirus/content-disarm pipeline, no laboratory/instrument connectors, no automatic email delivery, and no jurisdiction-certified retention/disposal policy. The database is not encrypted at rest by the application. Restricted-case membership needs careful administration because no emergency bypass is provided. Examiner reassignment is independently reviewed and does not silently grant restricted-case membership. Already exported copies are not automatically recalled when an opinion is withdrawn.

The new disposal workflow records physical disposition; it does not erase electronic records, operate equipment, prescribe methods, determine lawful authority, or automatically recall old exports. Administrative certificates must not be used to hide clinical evidence from opinion review.

The default PDF font covers the application's basic Latin output; configure a deployment-supplied font through `OV_PDF_FONT` for other scripts and validate rendering. Unsupported default-font characters fail explicitly rather than silently producing corrupted text. Fonts are not bundled. Labels currently print on A4 rather than thermal-printer templates.

## License

MIT. See [LICENSE](LICENSE). Use only synthetic information in public issues, screenshots, fixtures and pull requests.
