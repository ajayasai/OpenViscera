# Contributing

Use synthetic cases only. Never submit real names, autopsy photographs, laboratory reports, credentials, private keys or operational database files.

Install `python -m pip install -e '.[dev]'`, run `pytest --cov=openviscera`, and exercise the Chromium workflow with `OV_BROWSER_TEST=1 pytest tests/test_browser.py`. Use a separate demo directory for manual evaluation.

Workflow changes belong in strict Pydantic contracts, the pure reducer, server-side authorization, the browser UI and tests together. Every mutation must be transactional, version-checked, idempotent and signed. Add negative tests demonstrating that existing safeguards cannot be bypassed. Do not add a UI-only restriction as an authorization control.

The signed event schema is a public compatibility boundary. Changing event interpretation can break verification of existing bundles: version the format and implement explicit migrations/compatibility tests rather than reinterpreting historical records. Do not delete or overwrite issued opinions.

Small reviewed changes are preferred. Document security limitations honestly. No clinical inference, default preservative recommendations, automatic diagnostic text, telemetry, third-party scripts or externally sent case data should be added without an explicit reviewed design and appropriate governance.
