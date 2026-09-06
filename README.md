# OpenViscera

**Every specimen. Every next step.** A self-hosted forensic-medicine department workbench for specimen dispatch, custody reconciliation, external laboratory reports, and pending final or supplementary opinions.

**Status: v0.2.0 — tested workflow/security upgrade, not a clinically validated production system.** Human experts enter preservative details, review results, and write opinions. OpenViscera does not interpret laboratory findings, recommend preservatives, infer causes of death, or generate medical conclusions.

## New in v0.2

This release closes concrete limitations in the original pilot rather than making an untested claim to beat every commercial system.

| Improvement | Implemented behavior |
| --- | --- |
| Restricted case access | Explicit named members; no implicit administrator bypass for clinical contents. Enforced on direct reads, lists/counts, queues, downloads, exports and scanner lookup. |
| Signed access audit | Department-specific HTTP access chains record handled reads, exports and denied requests without case narratives, passwords or query strings. Sensitive responses are withheld if audit append fails. |
| Controlled corrections | Before/after specimen or requesting-authority corrections need an independent reviewer. Original values and both decisions remain in signed history. |
| Report/opinion withdrawal | Report disputes and independent withdrawal decisions; no silent revival of an older revision. Issued opinions can be withdrawn without erasing their original text or approvals. |
| Complete return path | Documentary external-laboratory returns record the external sender and authenticated local receiver; seal discrepancies remain explicit. |
| Additional examinations | A new request for a specimen already at the lab can receive its own documented/authenticated acceptance without inventing a physical handover. |
| Atomic dispatch batches | Preview and commit up to 100 handovers in one case/transaction. Any invalid item rejects the whole batch; every container retains its own signed event and outstanding acknowledgement. |
| Scanner lookup | Find a container using its identifier or an opaque OpenViscera QR payload. The same case and laboratory permissions apply. |
| Password lifecycle | Current-password-verified change, persistent failed-change throttling and revocation of every existing session. |
| Explicit upgrade | Additive v1-to-v2 database migration, a frozen v1 reducer and schema-aware replay preserve existing signatures and issued records. |

**Measured validation:** 169 tests passed, 97% Python statement coverage (1,636 of 1,686 statements), and an expanded real Chromium UI test using an in-process API transport. An internal 25-container benchmark measured a median **264.4 ms for individual handovers versus 37.1 ms for an atomic batch (7.13×)** over five repetitions. Both modes produced 25 signed events and passed full replay. This measures store operations, not transport, operator time, production capacity or performance against a commercial product. Raw results and methodology accompany the release validation artifacts; the benchmark is reproducible with `python tools/benchmark_dispatch.py`.

**Existing installations:** stop the old service, back up, install v0.2, then run `openviscera migrate --data ./var`. The server refuses unmigrated stores. Read [upgrade and control semantics](docs/V02-UPGRADE.md), [validation](docs/VALIDATION.md), and the [primary-source competitive review](docs/V02-COMPETITIVE-REVIEW.md).

## What works

| Area | Implemented behavior |
| --- | --- |
| Case and specimen records | Case reference, authority, assigned examiner, priority; container, quantity, unit, description, examiner-entered preservative, collection time and location. Department-wide normalized container uniqueness. |
| Custody | Seal history, current-custodian handover, named-user acknowledgement, evidence-backed external-lab receipt, automatic seal-mismatch discrepancy, independent resolution. Sending is not receiving. |
| Seven work queues | Dispatch, receipt reconciliation, outstanding reports, examiner review, pending opinions, custody discrepancies, and scheduled manual follow-ups. Search and case pagination. |
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
OV_BROWSER_TEST=1 pytest tests/test_browser.py
```

For PowerShell, set `$env:OV_BROWSER_TEST="1"` before invoking pytest. The browser suite exercises actual forms and the actual API, including different accounts, issuing an opinion, and revision-triggered reopening.

Current local evaluation: **169 tests passed, 97% Python statement coverage**. Chromium exercised case restriction, independent correction/withdrawal decisions, external return, previewed batch dispatch, scanner lookup, password change and audit viewing as well as the original lifecycle. Browser transport used the documented in-process harness because this environment blocks local HTTP navigation; server controls have separate HTTP API tests. The GitHub Actions browser job is configured to use the normal network path. See [validation details](docs/VALIDATION.md) for precise scope.

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

OpenViscera's implemented focus is the department-side gap around external laboratories: explainable queues, acknowledgement reconciliation, evidence-linked review, stale-opinion protection and independently verifiable exports. [The comparison and acceptance plan](docs/VALIDATION.md) defines how to evaluate these advantages without inventing competitor limitations.

## Documentation and limits

[Workflow and permissions](docs/WORKFLOW.md) · [Architecture](docs/ARCHITECTURE.md) · [Deployment and recovery](docs/OPERATIONS.md) · [Validation](docs/VALIDATION.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

Known limits include SQLite/single-process deployment, no HA or measured large-department capacity, no SSO/MFA or forgotten-password recovery, no antivirus/content-disarm pipeline, no laboratory/instrument connectors, no automatic email delivery, and no retention/disposal workflow. The database is not encrypted at rest by the application. Restricted-case membership needs careful administration because no emergency bypass or general examiner-reassignment workflow is provided. Already exported copies are not automatically recalled when an opinion is withdrawn.

The default PDF font covers the application's basic Latin output; configure a deployment-supplied font through `OV_PDF_FONT` for other scripts and validate rendering. Unsupported default-font characters fail explicitly rather than silently producing corrupted text. Fonts are not bundled. Labels currently print on A4 rather than thermal-printer templates.

## License

MIT. See [LICENSE](LICENSE). Use only synthetic information in public issues, screenshots, fixtures and pull requests.
