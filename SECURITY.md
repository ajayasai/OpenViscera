# Security policy and trust boundary

This is a pilot release, not a penetration-tested, accredited or regulatory-certified system. Do not use it for operational forensic evidence without institutional security, information-governance and workflow review.

## Reporting

Do not put real evidence, credentials, private keys or exploitable deployment details in public issues. Use the repository's private vulnerability-reporting facility when available. If unavailable, open a non-sensitive issue requesting a private reporting channel, without disclosing the vulnerability or affected case material. No private reporting service or response-time SLA is claimed.

## Implemented controls

Server-side role and department checks; restricted laboratory projections and downloads; assigned-examiner and independent-approver rules; optimistic versions and idempotency; SQLite transactions; SHA-256 attachment verification; Ed25519 event, identity and session signatures; scrypt passwords; random server-side sessions; HTTP-only SameSite cookies; CSRF tokens; exact-origin checks; trusted hosts; request-size bounds; persistent login throttling; no-store responses; restrictive content security policy; forced-download evidence; no external scripts or telemetry. Disabling an account revokes its sessions. Encrypted backup restoration invalidates all restored sessions.

Administrative changes and successful authentication are recorded in a signed administrative chain. Clinical writes are in each case ledger. **v0.2 adds signed per-department HTTP access chains** for handled API responses, including reads, exports and authentication/authorization failures; anonymous requests have a separate chain. Sensitive response bytes are withheld when audit append fails. This is not a complete operating-system or network-delivery audit: CLI/filesystem reads, process crashes and pre-application failures are outside its scope. A committed write may need an idempotent retry after an audit-response failure. See [v0.2 operating semantics](docs/V02-UPGRADE.md).

## What signatures do and do not establish

The service signs canonical event bodies containing actor identity, event and recording timestamps, previous hash and resulting state digest. Reads verify the ledger and current projection; full export/audit also replays the reducer and validates attachments. Identity seals detect database-only forgery of roles, passwords, laboratory metadata and sessions.

These are signatures of the deployment key, not individual smart-card signatures, a qualified electronic-signature service, an external timestamp authority, or proof that a person physically handled the specimen. External receipt transcription requires evidence but is not independently authenticated laboratory acknowledgement.

Someone with the signing key can create apparently valid records. Keep the key and data directory access-controlled; retain public keys and signed checkpoints separately. A self-contained valid older bundle does not prove that no newer evidence exists. Database/key rollback detection needs an independently retained recent checkpoint. Administrative-chain tail truncation has the same external-checkpoint limitation.

## Deployment obligations and residual risks

Use TLS, encrypted host volumes, least-privilege operating-system accounts, network restrictions, protected backup storage and reviewed retention policies. The application database and signing key are not application-encrypted at rest; encrypted backups do not change that fact. File format signatures and hashes are not malware detection. Uploaded PDFs may contain active or malicious content: deploy a reviewed scanning/quarantine process and hardened viewers before real-data use.

There is no SSO, MFA, forgotten-password recovery, independent key custody, formal key-rotation migration, operating-system-wide read monitoring, antivirus/CDR service, export approval workflow, legal hold/disposal workflow or high-availability design. v0.2 provides restricted-case named membership, current-password-verified password changes and per-department HTTP access auditing. An administrator cannot automatically read restricted clinical contents; administrators/auditors can inspect department-wide audit metadata including opaque case IDs. The contact directory remains department scoped. There is no emergency restricted-case bypass or general examiner-reassignment workflow. Case exports contain confidential information; human recipients remain responsible for secure handling.

The default setup is single-process SQLite. Resource bounds apply to individual uploads/requests/exports, not total concurrent resource consumption. Add reverse-proxy connection, rate and resource limits. Do not trust arbitrary forwarded headers: the CLI disables proxy-header processing. Cookies are secure except in explicit loopback-only local evaluation mode.
