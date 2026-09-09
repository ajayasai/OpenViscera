# v0.4: multi-factor access and recoverable account security

This release adds account protection to the v0.3 specimen workflow. It does not
claim a clinical validation, accreditation, independent penetration test, legal
signature certification, or superiority over every commercial product.

## Upgrade safely

Stop all writers. Back up with the installed release, retain the deployment public
key and a separate recent checkpoint, and test a restored copy before production.
Install v0.4 in a separate environment, then run:

```sh
openviscera migrate --data ./var
openviscera audit --data ./var --output /separate-location/post-v04-checkpoint.json
```

Schema 1, 2 and 3 stores upgrade explicitly to **database schema 4**. The earlier
access-audit migration still runs for schema 1. Migration verifies existing case,
identity, administrative and access records before adding signed account-security
metadata. User identities are re-sealed to include the new additive column. All
sessions are invalidated; users must sign in again. Re-running is a no-op.

**Case event schema remains 3.** No event reducer, specimen projection, case head,
attachment, issued opinion or historical signature is rewritten. Existing case
bundles remain verifiable. Older servers refuse schema 4; do not mix writers or
manually change schema markers to downgrade. This is not a rolling HA migration.

## Enrollment and mandatory policy

Choose **Account → Set up authenticator**. Re-enter the current password, scan the
locally generated QR (or manually enter the secret), and confirm a code from the
authenticator. Enrollment is not active until confirmation succeeds. The setup
expires after ten minutes. A new setup invalidates the earlier pending setup.
There is no external QR provider, SMS dependency or cloud authentication service.

Configuration for all accounts, including administrators and laboratory users:

```sh
OV_REQUIRE_MFA=1 openviscera serve --data ./var --origin https://your-approved-host
```

Use `OV_REQUIRE_MFA=0` only when intentionally permitting password-only accounts.
The default is 0 for compatibility. Other values fail startup instead of silently
disabling the policy. Compose forwards this variable; setting it in the deployment
environment takes effect without changing users or case data.

With mandatory MFA enabled, a password-only sign-in grants **only enrollment and
account-remediation access**. Case lists, counts, direct reads, scanner lookup,
exports, administrative operations and clinical writes remain forbidden. The
policy is enforced at the server on every authenticated request, not merely by
hiding controls. MFA cannot be disabled through the web interface under this
policy. Accounts already enrolled always require their factor even when the
deployment-wide policy is optional.

Do not enable mandatory MFA until staff have an enrollment/recovery procedure and
reliable clocks. A trusted local operator is still needed for exceptional recovery.

## Sign-in protocol and replay boundaries

RFC 6238 TOTP uses a per-account random 160-bit secret, SHA-1 HMAC, six digits and
30-second steps. Validation accepts the current step and one neighboring step on
either side. The last accepted counter is persisted atomically with the operation;
a counter at or below it cannot be used again. A code used at sign-in cannot also
approve a password change. Wait for the next code, or use a different recovery code.

After password verification, enrolled accounts receive a random five-minute
challenge, **not a session cookie or case access**. Only its hash is stored. Each
account has at most one outstanding challenge: a new password sign-in replaces the
previous challenge. It has a five-failure limit. Account-level MFA failures are
also bounded to eight per 15-minute window across new challenges and process
restarts; an IP bucket limits invalid challenge submissions. Existing password
login throttling is retained. Account-security reauthentication uses its own
persistent eight-failure window. Input-length and syntax bounds apply before
processing. These limits intentionally trade availability for resistance to
online guessing; they do not make a public endpoint immune to denial of service.

Factor consumption, challenge removal, session creation, signed identity update
and administrative login audit use one SQLite write transaction. Concurrent
submissions cannot both consume the same factor/challenge. A failed downstream
operation rolls the transaction back. There is no authentication bypass through
the case command or specimen import interfaces.

**TOTP is not phishing-resistant.** This release does not implement WebAuthn,
passkeys, SSO, OIDC, hardware attestation or a qualified individual signature.

## Secret handling and sessions

MFA secrets and pending enrollment secrets are encrypted with AES-GCM and
account-bound associated data. The encryption key is HKDF-SHA-256 derived with a
purpose-specific context from the deployment's signing-key seed. Account security,
challenge records and session metadata are covered by deployment signatures.
Unsigned changes, missing required session metadata and credential-epoch
mismatches fail closed. These are application integrity controls, not independent
hardware-backed key protection.

This encrypts MFA secrets, **not the case database**. Access to the server's private
key defeats these controls. Historical rollback of the entire database requires
independently retained checkpoints to detect; signatures alone do not establish
freshness. Use filesystem encryption, backups and appropriate key custody.

Sessions use HttpOnly, SameSite=Strict cookies, Secure outside explicit loopback
mode, CSRF protection and an eight-hour absolute lifetime. There are at most 20
sessions per account. Account security lists creation, expiry and authentication
method; it does not pretend to identify a physical device or a trustworthy IP.
Users may revoke one of their sessions or all other sessions. A foreign session ID
cannot be revoked or enumerated through this interface. Enabling/disabling MFA,
regenerating recovery codes, changing credentials, local recovery and account
status changes revoke sessions and outstanding challenges as appropriate.

No passwords, TOTP secrets, provisioning URIs, plaintext recovery codes or raw
challenge values enter application audit events. Reverse proxies must not log
request/response bodies. Codes stay in the current form, not localStorage or URL
parameters. Closing the secret-bearing dialog clears its DOM contents. Screenshots
and shoulder-surfing remain operator responsibilities.

## Recovery codes and local recovery

Enrollment issues ten independent 128-bit random recovery codes, displayed once.
Only user-bound hashes persist. Each code still requires the account password and
is consumed once. It does not turn off MFA. The account screen shows the remaining
count, never the original codes. Regeneration requires password plus a fresh factor,
invalidates old codes and signs out all sessions. Lost response delivery can mean
new codes were committed but never displayed: sign in with the authenticator and
regenerate rather than replaying an old privileged operation.

There is deliberately **no web administrator endpoint to reset another person's
MFA**. A trusted local operator can perform documented exceptional recovery after
out-of-band identity checks:

```sh
openviscera recover-account examiner --data ./var
# Only when the factor really is lost and recovery is authorized:
openviscera recover-account examiner --data ./var --reset-mfa
```

The command prompts for an authorization/reason reference and a temporary password
with confirmation. Passwords are not arguments or printed output. Recovery keeps
MFA by default; removing it requires the explicit flag. It preserves case
permissions and account activation state. Sessions/challenges are revoked and a
signed administrative event records the affected account, reason and reset choice.
The recovered user **must set a personal password before case access**. Under
mandatory MFA, the user must then enroll a new factor if it was reset. This is a
trusted-local-operator procedure, not a dual-operator attestation or an automatic
identity-proofing system. No email or SMS is sent.

## Backup and restore

The existing authenticated encrypted backup contains the database and key, and
therefore the material needed to recover MFA secrets. Protect it accordingly.
Restore invalidates sessions, sign-in challenges and pending enrollments. It also
clears all recovery-code hashes so previously consumed codes cannot be resurrected
by restoring an older snapshot. The restored authenticator stays enrolled, but the
current and adjacent TOTP window are barred: wait up to 90 seconds before signing
in, then regenerate recovery codes. If the authenticator is unavailable, follow the
explicit local recovery procedure. A restore still returns passwords and factor
configuration to their snapshot values; review and rotate credentials after
recovery, especially after an incident.

## Sources and evaluation

Primary technical references: [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238),
[OWASP MFA guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html),
and [cryptography AES-GCM documentation](https://cryptography.io/en/latest/hazmat/primitives/aead/).
The implementation is tested against all 18 Appendix B combinations for SHA-1,
SHA-256 and SHA-512; the provisioned application profile is SHA-1/6 digits/30 seconds.

[LabVantage Forensic Navigator](https://www.labvantage.com/industries/forensic/)
and [Forensic Advantage Medical Examiner CMS](https://www.forensicadvantage.com/medical-examiner-edition)
describe broader forensic platforms. Their published pages do not establish an
absence of MFA, equivalent security safeguards, or weaker implementation. No
licensed head-to-head comparison was performed. The defensible improvement here is
closing specific OpenViscera account-security gaps with reproducible tests.
