# Department workflow and role guide

## Setup

Initialize a fresh store. The administrator adds a laboratory, an examiner, a coordinator and an independent reviewer. A laboratory user must be assigned to a laboratory. Accounts have unique usernames and at least 14-character passwords. Disabled accounts cannot authenticate; existing sessions are revoked. There is no public registration.

## Collection to receipt

The examiner or coordinator creates the case and enters the specimen information. The examiner is explicitly assigned. Quantity is a positive bounded decimal; unit and preservative are entered, not recommended. Container identifiers are Unicode-normalized and case-insensitively unique within the department, including across cases.

Request an examination and destination laboratory before dispatch. The current recorded holder seals the specimen. Resealing records another seal-history entry and reason; it cannot occur during an unacknowledged handover. A sealed, non-quarantined specimen can be handed to another named user or dispatched to a named external laboratory recipient.

For account-based transfers, the named recipient signs in and acknowledges the observed seal and condition. The sender cannot acknowledge on their behalf. For laboratories without an account, upload receipt evidence and have the examiner/coordinator record the named external recipient, receipt time, observed seal and evidence reference. This is explicitly a documented staff transcription, not an authenticated laboratory signature.

A mismatch automatically records a discrepancy, regardless of the checkbox. Only an independent reviewer can record a resolution; the original discrepancy remains in history. Physical-event timestamps must have a timezone, cannot be future-dated and cannot precede the preceding custody event. Recording time is separately retained. Handover does not change the holder until acknowledged.

## Report to opinion

Upload a PDF and register it against the exact examination request. Its attachment must belong to the request's specimen within the same case. File bytes and hashes are retained; identical bytes cannot masquerade as a new revision of that request. A revised report explicitly supersedes the latest version. All earlier versions and their review records remain present.

The assigned examiner or reviewer records review with a note. A superseded report cannot receive a new review. A human writes the opinion and selects the current report versions. Approval is by an independent reviewer; issue is by the assigned examiner. Readiness and evidence freshness are checked at both approval and issue, not merely when the form was opened.

Later evidence reopens pending work while preserving the issued document. Create a new supplementary draft, obtain independent approval, and issue it after the new reports are reviewed and all other blockers are cleared. Substantive notes or newly uploaded evidence also conservatively invalidate an earlier draft's fingerprint. Administrative follow-up notes do not.

## Permission summary

| Role | Core actions |
| --- | --- |
| Administrator | Add users/labs, disable/reactivate users; department read access, no clinical mutation role. |
| Examiner | Assigned-case collection, requests, review, drafting and issue; custody, evidence and coordination. |
| Coordinator | Case intake, collection, requests, report registration, evidence-backed external receipts, follow-ups. |
| Courier | Seal/handover only when current custodian; acknowledge only transfers addressed to that account. |
| Laboratory | Laboratory-scoped view, own-lab reports/evidence; acknowledge transfers addressed to that account. |
| Reviewer | Expert review, independent discrepancy resolution, independent opinion approval, supporting notes/evidence. |
| Auditor | Read-only department review and verified exports. |

The backend is authoritative; hiding a browser button is not the control. Discrepancy resolution rejects reviewers who participated in the transfer. Author/self-approval remains prohibited even when the role model changes.

## Queues and follow-ups

Queues intentionally overlap: one case can have a missing receipt and an outstanding report. Priorities and due dates order work; overdue markers are calculated from recorded timestamps, not medical urgency inference. Each queue shows at most 200 items while retaining the total count. The case register supports search and pagination.

Record a manual contact method, note and next follow-up date against a request. These are work reminders, not automatically sent emails. The application does not contact laboratories or external services.

## Corrections and unsupported workflows

There is no silent edit/delete for evidence fields or issued opinions. Add a clearly identified corrective case note and follow department procedure; a structured correction/retraction mechanism is not yet implemented. Do not overwrite a wrong laboratory report: preserve it, document the issue and use the correct linked revision where appropriate.

External-laboratory specimen return and additional examinations requested after the original lab receipt do not yet have complete transitions. Do not fabricate a handover or acknowledgement to bypass this limit. The strict opinion gate intentionally has no administrative override or waiver for an outstanding examination in this release; departments requiring interim opinions or justified exclusions need a reviewed extension.
