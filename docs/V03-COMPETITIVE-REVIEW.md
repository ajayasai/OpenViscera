# v0.3 competitive scope and acceptance protocol

Reviewed: 7 September 2026. Sources are vendor-maintained product descriptions, not independent measurements. No licensed hands-on comparison was performed. An undocumented capability is **unknown**, not absent.

## Relevant commercial products

| Product | Vendor-documented scope | What that means for OpenViscera |
| --- | --- | --- |
| LabVantage MAP | Unified body intake, autopsy, downstream laboratory analysis and final reporting, with role-aware information sharing and autopsy-to-laboratory handoff. [1] | Much broader than OpenViscera's department-side specimen and pending-opinion workflow. Claiming replacement of the complete suite would be misleading. |
| Forensic Advantage Medical Examiner CMS | Medicolegal investigation, body/evidence custody, internal/external lab requests, autopsy reporting with review/approval, identification workflows and configured integrations. [2] | External lab tracking and report approval are not unique to OpenViscera. Detailed hold and stale-approval behavior needs hands-on testing. |
| Porter Lee MedEx | Barcode-based body/tissue tracking, daily body inventory, custody, toxicology and autopsy reporting, built on BEAST functionality. [3] | Barcode/custody functionality alone is not a competitive moat. OpenViscera does not implement a full morgue inventory or body-release application. |
| Forensic Advantage LIMS | Batch processing, staff/instrument resource management, authorized web access, audit trails and laboratory/instrument integration. [4] | OpenViscera remains weaker in laboratory execution/instrumentation breadth; a narrow specimen-department comparison must not hide that gap. |

## Implemented v0.3 differentiators to evaluate

These are transparent, executable controls in this source tree, not claims that competitors lack them: independent retention changes; case-wide holds covering future specimens; independently reviewed hold release; disposal proposals invalidated by intervening history rather than revived by reverting a flag; a matching certificate requirement with current access checks at completion; physical closure without evidence deletion; reviewed examiner reassignment; frozen historical reducers and independently verifiable bundles.

The value proposition is a focused, self-hosted workflow with inspectable rules and no paid feature gate. An institutional team can examine the exact state transitions and run the failure tests rather than relying only on a demonstration. Open source does not itself establish security, legal compliance or good usability.

## Pre-register a comparison before claiming superiority

Use licensed, supported releases with comparable configuration and expert setup. Record exact product version, optional modules, hardware, database size, staff roles, enabled policy and network conditions. A feature outside a product's intended scope is "out of scope," not a zero silently counted as a win. A vendor-declined/unavailable test is "not measured."

Use only realistic synthetic cases. Include at least these tasks:

| Scenario | Required outcome / observable measure |
| --- | --- |
| External report arrives before receipt reconciliation | Missing receipt remains visible; issue is blocked until required custody work is resolved. |
| Laboratory revises an incorporated report | Old issued record remains intact; further review/opinion work is visible. |
| Unauthorized user guesses a restricted case/container ID | No clinical details, counts, file bytes or task labels leak. |
| Reviewer approves their own proposal | Independent-decision rule rejects the operation. |
| Deadline elapses while a preservation hold exists | No automatic destruction or executable completion; reason is visible. |
| Case hold is placed before another specimen is collected | Newly collected specimen inherits the effective case hold. |
| Hold release is requested but not approved | Hold remains effective. |
| A hold is placed and released after disposal approval | Old approval cannot silently become valid again. |
| Evidence/custody changes after approval | Approval/completion fails safely; a fresh review is required. |
| Approval author loses access before completion | Completion fails and points to reapproval rather than silently relying on revoked authority. |
| Two users race hold and completion | No contradictory double commit against one version; audit reconstructs the winner and failed attempt. |
| An assigned examiner leaves the department | Explicit active replacement, independent decision, preserved old opinions and unchanged physical custody. |
| A completed specimen receives a later report | Evidence remains recordable and reviewable; specimen does not become physically available. |
| Export/restore crosses an application upgrade | Original signatures, attachments, issued text and separately pinned heads still verify. |

Separate correctness gates from convenience scores. Publish unsafe-transition counts first; record operator task success, completion time, error recovery, number of user actions, audit reconstruction success, exported-data portability, backup/restore time and operational cost. Randomize product/task order across trained operators, retain raw results and uncertainty intervals, and disclose all failed tasks and customizations. Compare support/SSO/integration/HA requirements explicitly instead of hiding them in an average.

A supportable claim would be: "In this pre-registered external-laboratory retention/reconciliation benchmark, release X outperformed releases Y/Z on measured task time while satisfying the same safety gates." The claim "better than every closed-source alternative" requires far more evidence and cannot be inferred from this repository's tests.

## Primary sources

[1] LabVantage, 11 June 2025: https://www.labvantage.com/blog/forensic-case-management-optimized-using-labvantage-morgue-autopsy-pathology-component/

[2] Forensic Advantage Medical Examiner CMS: https://www.forensicadvantage.com/medical-examiner-edition

[3] Porter Lee MedEx: https://www.porterlee.com/mes.html

[4] Forensic Advantage LIMS: https://www.forensicadvantage.com/lims-software
