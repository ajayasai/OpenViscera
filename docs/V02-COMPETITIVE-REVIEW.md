# v0.2: compete on verifiable behavior, not untested superlatives

Review date: 6 September 2026. This is a primary-source capability review, not a licensed product test.

## What commercial descriptions actually establish

[Forensic Advantage's Medical Examiner CMS](https://www.forensicadvantage.com/medical-examiner-edition) describes internal/external laboratory requests, autopsy and investigation reports with review/approval, role-related workflows, document generation and EDRS integration. [Its LIMS offering](https://www.forensicadvantage.com/lims-software) describes batch processing and instrument integration. These are existing capabilities, not gaps to claim as OpenViscera inventions.

[LabVantage MAP](https://www.labvantage.com/blog/forensic-case-management-optimized-using-labvantage-morgue-autopsy-pathology-component/) describes an integrated morgue/autopsy/pathology workflow, role-aware collaboration and transfer of specimen metadata into laboratory workflows. [Forensic Filer](https://www.forensicfiler.com/forensic-filer-online.aspx) describes hosted case management and reporting. Public product descriptions do not establish the absence of more specific controls in a configured installation.

OpenViscera therefore does not claim a broader product suite, proven faster operator performance, a stronger independent security assessment, or superiority to every closed-source configuration. Existing open-source LIMS also remain relevant; this project is not the first open-source sample manager.

## Gaps closed in OpenViscera itself

| v0.1 limitation | v0.2 implementation | Executable evidence |
| --- | --- | --- |
| Every department staff account could read every department case | Restricted named-member case policies; no implicit administrator override for clinical content; filters cover list totals, queues, direct reads, attachments, PDFs, exports and specimen lookup | `test_restricted_case_removes_existence_from_all_store_views`, `test_restricted_case_not_disclosed_through_http` |
| No complete request-level read audit | Signed per-department HTTP access chains, including handled authentication/authorization failures, reads and exports; sensitive responses withheld when audit append fails | `test_access_audit_captures_reads_exports_denials_and_no_sensitive_payloads`, `test_audit_append_failure_withholds_clinical_response` |
| Corrections required unstructured notes | Proposed before/after corrections, independent approval/rejection, optimistic original-value checks and permanent decision history | `test_controlled_correction_preserves_original_and_requires_independence` |
| Invalid report/opinion lacked a withdrawal workflow | Report disputes and independent withdrawal decisions; no silent fallback to an earlier report; explicit issued-opinion withdrawal without deleting original text | `test_report_withdrawal_no_fallback_and_requires_replacement`, `test_withdraw_opinion_preserves_original_and_reopens_case` |
| Externally held specimens could not return through the application | Evidence-backed return receipts naming the external sender and authenticating the local receiving account, with automatic seal discrepancy handling | `test_external_return_retains_evidence_and_can_resume_custody` |
| Additional examinations after laboratory receipt could get stuck | Explicit additional-request acceptance, authenticated by the laboratory or transcribed by staff with matched documentary evidence; no fabricated physical transfer | `test_late_request_acceptance_works_without_fabricated_custody` |
| Repetitive one-container handovers | Up to 100 handovers in one transaction; non-mutating preflight and explicit browser confirmation; invalid late items roll back the entire batch | `test_batch_preview_commit_and_idempotent_retry`, `test_batch_late_failure_rolls_back_entire_batch` |
| QR label had no direct lookup workflow | Keyboard-scanner/container lookup through the same case and laboratory permissions | `test_specimen_qr_lookup_and_case_acl` |
| No password-change interface | Current-password-verified change, throttling and revocation of every session | `test_password_change_revokes_all_sessions`, `test_password_change_failures_are_persistently_throttled` |
| No versioned upgrade path | Explicit additive schema migration; frozen v1 reducer and schema-aware replay; legacy signatures, keys and issued case projections preserved | `test_migration_preserves_v1_signatures_bundle_and_issued_record` |

These tests establish implemented behaviors on synthetic scenarios. They do not establish that a competing product lacks the same behaviors.

## Measurable comparison inside OpenViscera

`tools/benchmark_dispatch.py` compares N individual validated handovers with a single atomic N-container batch, using copies of the same quiescent synthetic database. Setup, authentication, transport and full post-run audit are outside the timer. Every variant retains N signed handover events, leaves acknowledgement pending and passes a complete signed replay. The output includes raw times, medians, environment and transaction counts. This is a controlled in-project microbenchmark, not evidence of a cross-product speed advantage or a production-capacity claim.

## Independent acceptance still needed

Use the same pre-registered synthetic cases, trained operators, hardware and product configurations to compare task correctness, operator time, wrong-link prevention, missing-receipt reconciliation, correction provenance, post-issue revisions, access isolation, export reconstruction and recovery. Report failures and uncertainty, not just favorable averages. Include independent forensic practitioners, security reviewers and administrators.

The security design follows the principles of [OWASP authorization guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)—check each request and protect guessed object IDs—and [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)—record security-relevant activity without logging credentials or sensitive contents. This is design rationale, not OWASP certification or proof of compliance.
