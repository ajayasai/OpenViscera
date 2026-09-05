# Deployment, recovery and pilot acceptance

## Local evaluation

Use the README quickstart on loopback with synthetic data. A demo store cannot become an operational store merely by deleting demo cases: initialize a separate empty store and retain no demo credentials. Local passwords are generated for demonstrations or prompted for initialization, never published defaults.

## Network deployment

Set `OV_ORIGIN` to the exact external HTTPS origin. Put the single application process behind a TLS reverse proxy that preserves the expected Host and Origin. Do not expose its plaintext upstream port to the network. Set body size, connection and rate limits at that proxy. The application bounds JSON requests to 8 MiB and attachments to 5 MiB; account for JSON/base64 overhead.

A Dockerfile and Compose definition are supplied, but container execution was not validated in the initial restricted build environment. Review and test them before deployment:

```bash
cp .env.example .env
# Set OV_ORIGIN to the real HTTPS hostname.
docker compose build
docker compose run --rm app init --data /data
docker compose up -d
```

The named volume contains the database, signing key and public-key file. The image runs as UID 10001; the Compose service has a read-only root filesystem, writable evidence volume, bounded temporary filesystem and no capabilities. It binds the upstream port to host loopback only. **Compose does not supply a certificate or TLS proxy**: configure your institution's existing reverse proxy before login over the network. Secure cookies intentionally do not work over plain HTTP in production mode.

Use encrypted host volumes, restrict backup and key access, and protect against host compromise. Keep the key and public key paired. The deployment refuses a key that differs from database metadata. There is no supported in-place key-rotation migration in this release; do not replace the key manually.

For non-Latin PDFs, mount an institution-supplied appropriate TrueType font read-only and set `OV_PDF_FONT` to its path inside the runtime. Restart after a font change. Verify actual target scripts, shaping, document layout and printed labels before use. No fonts are distributed with OpenViscera, and configuring a Unicode font alone is not a guarantee that every script renders correctly.

## Backups and checkpoints

Run `openviscera audit --data /path --output /separate/checkpoint.json` and retain the checkpoint away from the application. Record a trusted public key out of band. Evidence ZIP verification can pin an individual expected case head from such a checkpoint.

The backup command uses SQLite's backup API for a consistent snapshot, includes the signing key, and encrypts an authenticated archive with a prompted passphrase. Save that passphrase separately. This pilot refuses snapshots or archives beyond its 100 MiB bound; it is not a large-scale backup solution.

Restore into a nonexistent directory with `openviscera restore backup.ovb --data /new/path`. Authentication, archive bounds, SQLite integrity, signed case replay, attachment hashes and identity records are checked before the staging directory is moved into place. Sessions are invalidated. Validate case counts and externally retained heads, then point a stopped application at the restored store. Retain the original until recovery is accepted.

A successful restore does not establish that the backup is the newest legitimate backup. Compare against separately retained recent checkpoints. Protection against deletion or rollback of the entire deployment depends on storage and checkpoint controls outside the application.

## Operational review before real data

Institutional acceptance must cover the complete specimen-to-opinion flow with realistic synthetic cases, allowed correction and exceptional workflows, access scope, external-receipt policy, independent approval, export handling, account lifecycle, retention/hold/disposal policy, threat modelling and penetration testing, malware handling, recovery drills, realistic concurrency and volume, PDF/label printing, clock synchronization and incident response.

Automated tests are evidence about implemented rules, not accreditation, legal compliance or clinical validation. No production uptime SLA, external integrations, read-access monitoring service, managed hosting or legal certification is included.

## Version upgrades

Schema version 1 is explicit. No migration engine is shipped. Back up, retain a checkpoint, test the new release against a copy, verify prior signed bundles and compare heads before any upgrade. Reject an upgrade that silently changes event interpretation. Keep old verification environments for historical evidence when formats evolve.
