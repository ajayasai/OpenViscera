# v0.4 validation record

## Reproducible local results — 9 September 2026

**268 tests passed; 97.91% Python statement coverage
(2249 of 2297 statements).** This is statement coverage,
not exhaustive branch coverage, state-space exploration, a penetration test or clinical validation.
The implementation and tests used only synthetic accounts, fixtures and case material.

The final suite was executed in four foreground groups, accumulating coverage over
the same final Python source revision, on Python 3.13.5:

| Group | Passed | pytest-reported duration |
| --- | ---: | ---: |
| API, authentication and CLI | 74 | 31.53 s |
| Evidence and original workflow | 95 | 12.34 s |
| v0.2/v0.3 governance and lifecycle | 96 | 22.95 s |
| Three Chromium journeys | 3 | 27.78 s |

The earlier v0.3 record is preserved in [V03-VALIDATION.md](V03-VALIDATION.md).
Its completed public main commit was `cad53c31e512285267b762de67ddc61a1c080f92`.

## What the new tests exercise

The 46 dedicated authentication tests include all 18 RFC 6238 Appendix B
algorithm/timestamp combinations; one-time TOTP counters; recovery-code consumption;
concurrent completion; challenge replacement, expiry and five-failure limits;
persistent account throttling across challenges and restarts; enrollment expiry;
account-bound encrypted secrets; tampered or missing signed identity/session metadata;
per-user session limits; foreign-session revocation denial; factor-required credential
changes; account deactivation; required-enrollment read/write denial; CSRF/origin
checks; lost-factor local recovery; restored MFA with revoked sessions/challenges/codes;
and an actual schema-3 table-shape migration without historical event changes.

MFA route code reached 100% statement coverage and the authentication module reached
99.64%. That is not proof against all attacks. The security model and remaining
assumptions are documented in [V04-SECURITY.md](V04-SECURITY.md).

## Browser transport boundary

Local Chromium explicitly rejected loopback navigation with
`ERR_BLOCKED_BY_ADMINISTRATOR`. The local tests therefore used the existing
in-process FastAPI transport bridge while exercising actual Chromium DOM, forms,
JavaScript and role changes. This is **not** a local real-network browser result.

The new browser journey exercises required enrollment, local QR/manual-secret setup,
confirmation, saved recovery codes, second-factor sign-in, stale recovery-code
rejection, revocation of another session, recovery-code replacement and
factor-protected password changes. It checks desktop/mobile layout, absence of page
JavaScript errors, and clearing the enrollment secret from the dialog DOM. Public
screenshots omit QR secrets, passwords and plaintext recovery codes.

The original full specimen workflow and v0.3 retention/reassignment browser journeys
also pass. They were updated only where the Account navigation changed and to load
the new script in the in-process bridge.

## Hosted validation and reproduction

The CI workflow runs Python 3.11/3.12/3.13 tests, a minimum 90% statement-coverage gate,
compilation, JavaScript syntax checks, package builds, and all three Chromium
journeys with ordinary HTTP. Hosted job status must be checked on the **final
published commit**, not inferred from this local report or an earlier revision.
CI artifacts include distributions, coverage/JUnit reports and browser screenshots.

```sh
python -m pip install -e '.[dev]'
pytest --cov=openviscera --cov-fail-under=90 --cov-report=term-missing
python -m playwright install chromium
OV_BROWSER_TEST=1 pytest tests/test_browser.py tests/test_v3_browser.py tests/test_auth_browser.py
```

`OV_BROWSER_INPROCESS=1` is solely a constrained-environment test option. CI does
not enable it. Authentication mocks or fake successful CI checks are not used.

## Not established

No licensed commercial head-to-head evaluation, realistic large-department load
benchmark, high-availability test, independent security assessment, instrument/LIMS
integration, phishing-resistant identity system, jurisdictional acceptance or
production clinical deployment was performed. MFA closes a concrete gap in
OpenViscera; it does not establish that competitors lack equivalent controls.
